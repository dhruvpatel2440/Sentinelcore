"""M11 — PCAP parsing. A capture is attacker-controlled data, often literally
captured from an attack, so every tshark invocation here:

  * uses an absolute, pre-resolved binary path and an argv list — never a
    shell string
  * passes `-n` to disable all name resolution, so parsing a capture can
    never trigger an outbound DNS/MaxMind lookup
  * runs with a hard wall-clock timeout and a CPU/address-space rlimit
    (`_limit_resources`), so a decompression or complexity bomb in a
    dissector cannot exhaust the container
  * already runs as the container's unprivileged, capability-dropped user
    (see backend/Dockerfile) — there is no separate sandbox to construct

A single field-extraction pass produces both flows and artifacts, in
preference to tshark's `-z conv,tcp/udp` text tables: those tables have no
stable machine-readable format across tshark versions, whereas `-T fields`
output is trivial to parse line by line with flat memory regardless of
capture size.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import logging
import resource
import shutil
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.core.config import settings

logger = logging.getLogger("sentinelcore.pcap.parser")

TSHARK_PATH = shutil.which("tshark")
CAPINFOS_PATH = shutil.which("capinfos")

_CPU_SECONDS_LIMIT = 120
_ADDRESS_SPACE_LIMIT_BYTES = 1024 * 1024 * 1024  # 1 GiB
_MAX_LINE_BYTES = 1024 * 1024
_MAX_PACKET_LINES = 5_000_000  # defensive ceiling against a bomb-shaped capture
_PROGRESS_EVERY_LINES = 20_000


class ParseError(Exception):
    pass


def _limit_resources() -> None:
    try:
        resource.setrlimit(resource.RLIMIT_CPU, (_CPU_SECONDS_LIMIT, _CPU_SECONDS_LIMIT))
        resource.setrlimit(resource.RLIMIT_AS, (_ADDRESS_SPACE_LIMIT_BYTES, _ADDRESS_SPACE_LIMIT_BYTES))
    except (ValueError, OSError):
        pass  # best-effort — some sandboxes (CI) disallow RLIMIT_AS


def _require_binaries() -> None:
    if TSHARK_PATH is None:
        raise ParseError("tshark is not installed in this image")
    if CAPINFOS_PATH is None:
        raise ParseError("capinfos is not installed in this image")


# ---------------------------------------------------------------------------
# Metadata
# ---------------------------------------------------------------------------


def _parse_capinfos_datetime(value: str) -> datetime | None:
    value = value.replace(" UTC", "").strip()
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(value, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


async def parse_metadata(path: Path) -> dict[str, Any]:
    _require_binaries()
    argv = [CAPINFOS_PATH, "-M", "-u", str(path)]
    proc = await asyncio.create_subprocess_exec(
        *argv, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, preexec_fn=_limit_resources
    )
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=60)
    except asyncio.TimeoutError as exc:
        proc.kill()
        await proc.wait()
        raise ParseError("capinfos timed out") from exc

    if proc.returncode != 0:
        raise ParseError(f"capinfos failed: {stderr.decode(errors='replace')[:500]}")

    info: dict[str, str] = {}
    for line in stdout.decode(errors="replace").splitlines():
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        info[key.strip()] = value.strip()

    packet_count = None
    try:
        packet_count = int(info.get("Number of packets", "").replace(",", ""))
    except ValueError:
        pass

    duration_seconds = None
    duration_raw = info.get("Capture duration", "")
    if duration_raw:
        try:
            duration_seconds = float(duration_raw.split()[0])
        except (ValueError, IndexError):
            pass

    return {
        "packet_count": packet_count,
        "link_type": info.get("File encapsulation") or None,
        "first_packet_ts": _parse_capinfos_datetime(info.get("First packet time", "")),
        "last_packet_ts": _parse_capinfos_datetime(info.get("Last packet time", "")),
        "duration_seconds": duration_seconds,
    }


# ---------------------------------------------------------------------------
# Combined field-extraction pass — feeds both flows and artifacts
# ---------------------------------------------------------------------------

FIELDS = [
    "frame.number", "frame.time_epoch", "frame.len",
    "ip.src", "ip.dst", "ipv6.src", "ipv6.dst",
    "tcp.stream", "tcp.srcport", "tcp.dstport",
    "udp.stream", "udp.srcport", "udp.dstport",
    "dns.qry.name",
    "http.host", "http.request.uri", "http.request.method", "http.user_agent",
    "tls.handshake.extensions_server_name",
    "http.authorization",
]
_F = {name: i for i, name in enumerate(FIELDS)}


@dataclass
class _FlowAgg:
    protocol: str
    stream_id: int
    src_ip: str | None = None
    dst_ip: str | None = None
    src_port: int | None = None
    dst_port: int | None = None
    packet_count: int = 0
    byte_count: int = 0
    start_ts: float | None = None
    end_ts: float | None = None
    app_protocols: set[str] = field(default_factory=set)


def _to_int(value: str) -> int | None:
    try:
        return int(value)
    except ValueError:
        return None


def _to_float(value: str) -> float | None:
    try:
        return float(value)
    except ValueError:
        return None


def _decode_basic_auth(header: str) -> str | None:
    if not header.lower().startswith("basic "):
        return None
    try:
        return base64.b64decode(header[6:].strip()).decode("utf-8", errors="replace")
    except (binascii.Error, ValueError):
        return None


class ParseResult:
    def __init__(self) -> None:
        self.flows: dict[tuple[str, int], _FlowAgg] = {}
        self.artifacts: list[dict[str, Any]] = []
        self.lines_processed = 0
        self.truncated_output = False


async def run_field_extraction(
    path: Path, *, pcap_id: str | None = None, redis=None, timeout: int | None = None
) -> ParseResult:
    """Single streaming pass. Reads tshark's stdout line by line so memory
    stays flat regardless of capture size, and never buffers the whole
    (potentially gigabytes-large) output at once."""
    _require_binaries()
    timeout = timeout or settings.pcap_parse_timeout_seconds

    argv = [TSHARK_PATH, "-r", str(path), "-n", "-T", "fields", "-E", "separator=\t", "-E", "occurrence=f"]
    for name in FIELDS:
        argv += ["-e", name]

    proc = await asyncio.create_subprocess_exec(
        *argv, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, preexec_fn=_limit_resources
    )

    result = ParseResult()
    seen_values: dict[str, set[str]] = {"dns": set(), "http": set(), "sni": set(), "ua": set(), "auth": set()}

    async def _consume() -> None:
        assert proc.stdout is not None
        while True:
            try:
                raw = await proc.stdout.readline()
            except (ValueError, asyncio.LimitOverrunError):
                result.truncated_output = True
                break
            if not raw:
                break
            if len(raw) > _MAX_LINE_BYTES:
                continue
            result.lines_processed += 1
            if result.lines_processed > _MAX_PACKET_LINES:
                result.truncated_output = True
                proc.kill()
                break

            _consume_line(raw.decode("utf-8", errors="replace").rstrip("\n"), result, seen_values)

            if pcap_id and redis and result.lines_processed % _PROGRESS_EVERY_LINES == 0:
                try:
                    await redis.set(f"pcap:progress:{pcap_id}", 50)  # metadata phase already reported 10%
                except Exception:  # noqa: BLE001
                    pass

    try:
        await asyncio.wait_for(_consume(), timeout=timeout)
    except asyncio.TimeoutError as exc:
        proc.kill()
        await proc.wait()
        raise ParseError(f"tshark field extraction timed out after {timeout}s") from exc
    finally:
        if proc.returncode is None:
            try:
                await asyncio.wait_for(proc.wait(), timeout=5)
            except asyncio.TimeoutError:
                proc.kill()

    stderr = b""
    if proc.stderr is not None:
        stderr = await proc.stderr.read()
    if proc.returncode not in (0, None) and not result.flows and not result.artifacts:
        raise ParseError(f"tshark failed: {stderr.decode(errors='replace')[:500]}")

    return result


def _consume_line(line: str, result: ParseResult, seen_values: dict[str, set[str]]) -> None:
    cols = line.split("\t")
    if len(cols) < len(FIELDS):
        cols = cols + [""] * (len(FIELDS) - len(cols))

    def col(name: str) -> str:
        return cols[_F[name]]

    ts = _to_float(col("frame.time_epoch"))
    frame_len = _to_int(col("frame.len")) or 0
    frame_number = _to_int(col("frame.number"))

    src_ip = col("ip.src") or col("ipv6.src") or None
    dst_ip = col("ip.dst") or col("ipv6.dst") or None

    stream_key: tuple[str, int] | None = None
    if col("tcp.stream"):
        stream_id = _to_int(col("tcp.stream"))
        if stream_id is not None:
            stream_key = ("tcp", stream_id)
            src_port, dst_port = _to_int(col("tcp.srcport")), _to_int(col("tcp.dstport"))
    elif col("udp.stream"):
        stream_id = _to_int(col("udp.stream"))
        if stream_id is not None:
            stream_key = ("udp", stream_id)
            src_port, dst_port = _to_int(col("udp.srcport")), _to_int(col("udp.dstport"))
    else:
        src_port = dst_port = None

    if stream_key is not None:
        flow = result.flows.get(stream_key)
        if flow is None:
            flow = _FlowAgg(protocol=stream_key[0], stream_id=stream_key[1])
            result.flows[stream_key] = flow
        if flow.src_ip is None and src_ip:
            flow.src_ip, flow.dst_ip = src_ip, dst_ip
            flow.src_port, flow.dst_port = src_port, dst_port
        flow.packet_count += 1
        flow.byte_count += frame_len
        if ts is not None:
            flow.start_ts = ts if flow.start_ts is None else min(flow.start_ts, ts)
            flow.end_ts = ts if flow.end_ts is None else max(flow.end_ts, ts)

    dns_qry = col("dns.qry.name")
    if dns_qry and dns_qry not in seen_values["dns"]:
        seen_values["dns"].add(dns_qry)
        result.artifacts.append(
            {"artifact_type": "dns_query", "value": dns_qry, "packet_number": frame_number, "ts": ts, "stream_key": stream_key}
        )
        if stream_key:
            result.flows[stream_key].app_protocols.add("dns")

    http_host, http_uri, http_method = col("http.host"), col("http.request.uri"), col("http.request.method")
    if (http_host or http_uri) and (http_host, http_uri) not in seen_values["http"]:
        seen_values["http"].add((http_host, http_uri))
        result.artifacts.append(
            {
                "artifact_type": "http_request", "value": f"{http_method or 'GET'} {http_host}{http_uri}",
                "detail": {"host": http_host, "uri": http_uri, "method": http_method},
                "packet_number": frame_number, "ts": ts, "stream_key": stream_key,
            }
        )
        if stream_key:
            result.flows[stream_key].app_protocols.add("http")

    user_agent = col("http.user_agent")
    if user_agent and user_agent not in seen_values["ua"]:
        seen_values["ua"].add(user_agent)
        result.artifacts.append(
            {"artifact_type": "user_agent", "value": user_agent, "packet_number": frame_number, "ts": ts, "stream_key": stream_key}
        )

    sni = col("tls.handshake.extensions_server_name")
    if sni and sni not in seen_values["sni"]:
        seen_values["sni"].add(sni)
        result.artifacts.append(
            {"artifact_type": "tls_sni", "value": sni, "packet_number": frame_number, "ts": ts, "stream_key": stream_key}
        )
        if stream_key:
            result.flows[stream_key].app_protocols.add("tls")

    auth_header = col("http.authorization")
    if auth_header and auth_header not in seen_values["auth"]:
        decoded = _decode_basic_auth(auth_header)
        if decoded:
            seen_values["auth"].add(auth_header)
            result.artifacts.append(
                {
                    "artifact_type": "credential", "value": decoded,
                    "detail": {"scheme": "basic"}, "packet_number": frame_number, "ts": ts, "stream_key": stream_key,
                }
            )


# ---------------------------------------------------------------------------
# Packet-level, on-demand (never stored)
# ---------------------------------------------------------------------------


async def list_packets_for_flow(path: Path, protocol: str, stream_id: int, *, limit: int, offset: int) -> list[dict]:
    _require_binaries()
    display_filter = f"{protocol}.stream eq {stream_id}"
    argv = [
        TSHARK_PATH, "-r", str(path), "-n", "-Y", display_filter, "-T", "fields",
        "-E", "separator=\t",
        "-e", "frame.number", "-e", "frame.time_epoch", "-e", "frame.len", "-e", "_ws.col.Protocol", "-e", "_ws.col.Info",
    ]
    proc = await asyncio.create_subprocess_exec(
        *argv, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, preexec_fn=_limit_resources
    )
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=settings.pcap_parse_timeout_seconds)
    except asyncio.TimeoutError as exc:
        proc.kill()
        await proc.wait()
        raise ParseError("packet listing timed out") from exc
    if proc.returncode != 0:
        raise ParseError(f"tshark failed: {stderr.decode(errors='replace')[:500]}")

    packets = []
    for i, line in enumerate(stdout.decode(errors="replace").splitlines()):
        if i < offset:
            continue
        if len(packets) >= limit:
            break
        cols = line.split("\t")
        if len(cols) < 5:
            continue
        packets.append(
            {
                "frame_number": _to_int(cols[0]), "ts": _to_float(cols[1]), "length": _to_int(cols[2]),
                "protocol": cols[3], "info": cols[4],
            }
        )
    return packets


MAX_FOLLOW_BYTES = 512 * 1024


async def follow_stream(path: Path, protocol: str, stream_id: int) -> dict:
    _require_binaries()
    if protocol not in ("tcp", "udp"):
        raise ParseError("follow is only supported for tcp/udp streams")
    argv = [TSHARK_PATH, "-r", str(path), "-n", "-q", "-z", f"follow,{protocol},ascii,{stream_id}"]
    proc = await asyncio.create_subprocess_exec(
        *argv, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, preexec_fn=_limit_resources
    )
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=settings.pcap_parse_timeout_seconds)
    except asyncio.TimeoutError as exc:
        proc.kill()
        await proc.wait()
        raise ParseError("follow-stream timed out") from exc
    if proc.returncode != 0:
        raise ParseError(f"tshark follow failed: {stderr.decode(errors='replace')[:500]}")

    content = stdout.decode("utf-8", errors="replace")
    truncated = len(content) > MAX_FOLLOW_BYTES
    if truncated:
        content = content[:MAX_FOLLOW_BYTES]
    return {"content": content, "truncated": truncated}
