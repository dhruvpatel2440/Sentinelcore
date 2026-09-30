#!/usr/bin/env bash
# U08 §6.2 — attack runner for the isolated validation lab.
#
# Refuses to run unless --target is inside LAB_CIDR and is not the gateway
# or the platform host. Runs one attack class N times with a random 30-90s
# gap between runs, appending one JSON line per run to
# validation/runs/<attack>.jsonl with UTC start/end, the exact argv used,
# and the tool's version string.
#
# Usage:
#   scripts/run_attacks.sh --attack A1 --target 192.168.10.50 \
#       --attacker-iface eth0 [--runs 10] [--lab-cidr 192.168.10.0/24] \
#       [--gateway-ip 192.168.10.1] [--platform-ip 192.168.10.10]
#
#   A6 (exploit) needs --msf-module and, for usermap_script, --msf-payload.
#   A7 (web scan) needs --web-port (default 80).
#   A8 (pcap replay) is a different mode:
#     scripts/run_attacks.sh --attack A8 --pcap capture.pcap --attacker-iface eth0
#
#   DRY_RUN=1 prefixes every attack command with `echo` instead of running
#   it — used to test this script's own guard/logging logic without a real
#   lab or attack tooling installed.
set -euo pipefail

ATTACK=""
TARGET=""
IFACE=""
RUNS=10
LAB_CIDR="${LAB_CIDR:-192.168.10.0/24}"
GATEWAY_IP="${GATEWAY_IP:-}"
PLATFORM_IP="${PLATFORM_IP:-}"
WEB_PORT=80
MSF_MODULE=""
MSF_PAYLOAD=""
PCAP_FILE=""
SSH_USER="msfadmin"
FTP_USER="msfadmin"
CRED_LIST="${CRED_LIST:-}"
OUT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/runs"

usage() {
    echo "Usage: $0 --attack A1..A8 --target IP --attacker-iface IFACE [options]" >&2
    exit 1
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --attack) ATTACK="$2"; shift 2 ;;
        --target) TARGET="$2"; shift 2 ;;
        --attacker-iface) IFACE="$2"; shift 2 ;;
        --runs) RUNS="$2"; shift 2 ;;
        --lab-cidr) LAB_CIDR="$2"; shift 2 ;;
        --gateway-ip) GATEWAY_IP="$2"; shift 2 ;;
        --platform-ip) PLATFORM_IP="$2"; shift 2 ;;
        --web-port) WEB_PORT="$2"; shift 2 ;;
        --msf-module) MSF_MODULE="$2"; shift 2 ;;
        --msf-payload) MSF_PAYLOAD="$2"; shift 2 ;;
        --pcap) PCAP_FILE="$2"; shift 2 ;;
        --ssh-user) SSH_USER="$2"; shift 2 ;;
        --ftp-user) FTP_USER="$2"; shift 2 ;;
        --cred-list) CRED_LIST="$2"; shift 2 ;;
        -h|--help) usage ;;
        *) echo "Unknown argument: $1" >&2; usage ;;
    esac
done

[ -n "$ATTACK" ] || usage
[ -n "$IFACE" ] || usage
if [ "$ATTACK" != "A8" ]; then
    [ -n "$TARGET" ] || usage
fi
if [ "$ATTACK" = "A8" ]; then
    [ -n "$PCAP_FILE" ] || { echo "A8 requires --pcap" >&2; exit 1; }
fi

mkdir -p "$OUT_DIR"

# ---------------------------------------------------------------------------
# Scope guard — never scan/attack anything outside the lab, the gateway, or
# the platform host itself.
# ---------------------------------------------------------------------------

_ip_in_cidr() {
    # Pure-bash IPv4-in-CIDR check (no external tool dependency). Prints
    # "yes"/"no". $1=ip $2=cidr
    local ip="$1" cidr="$2"
    local net="${cidr%/*}" bits="${cidr#*/}"

    IFS=. read -r a b c d <<< "$ip"
    IFS=. read -r na nb nc nd <<< "$net"
    local ip_int=$(( (a << 24) + (b << 16) + (c << 8) + d ))
    local net_int=$(( (na << 24) + (nb << 16) + (nc << 8) + nd ))
    local mask=$(( bits == 0 ? 0 : (0xFFFFFFFF << (32 - bits)) & 0xFFFFFFFF ))

    if [ $(( ip_int & mask )) -eq $(( net_int & mask )) ]; then
        echo "yes"
    else
        echo "no"
    fi
}

if [ "$ATTACK" != "A8" ]; then
    if [ "$(_ip_in_cidr "$TARGET" "$LAB_CIDR")" != "yes" ]; then
        echo "REFUSED: $TARGET is not inside LAB_CIDR ($LAB_CIDR)" >&2
        exit 2
    fi
    if [ -n "$GATEWAY_IP" ] && [ "$TARGET" = "$GATEWAY_IP" ]; then
        echo "REFUSED: $TARGET is the lab gateway" >&2
        exit 2
    fi
    if [ -n "$PLATFORM_IP" ] && [ "$TARGET" = "$PLATFORM_IP" ]; then
        echo "REFUSED: $TARGET is the SentinelCore platform host" >&2
        exit 2
    fi
fi

# ---------------------------------------------------------------------------
# Per-attack command builders. Each sets the global array ARGV.
# ---------------------------------------------------------------------------

_require_tool() {
    command -v "$1" >/dev/null 2>&1 || { echo "required tool not found: $1" >&2; exit 3; }
}

_tool_version() {
    "$1" --version 2>&1 | head -n1 || echo "unknown"
}

build_argv() {
    local run_no="$1"
    case "$ATTACK" in
        A1)
            _require_tool nmap
            if [ $(( run_no % 2 )) -eq 0 ]; then
                ARGV=(nmap -sS -e "$IFACE" -Pn "$TARGET")
            else
                ARGV=(nmap -sS -T2 -e "$IFACE" -Pn "$TARGET")
            fi
            TOOL=nmap
            ;;
        A2)
            _require_tool nmap
            ARGV=(nmap -sV -A -e "$IFACE" -Pn "$TARGET")
            TOOL=nmap
            ;;
        A3)
            _require_tool nmap
            ARGV=(nmap -sn -e "$IFACE" "$LAB_CIDR")
            TOOL=nmap
            ;;
        A4)
            _require_tool hydra
            [ -n "$CRED_LIST" ] || { echo "A4 requires --cred-list FILE" >&2; exit 1; }
            ARGV=(hydra -l "$SSH_USER" -P "$CRED_LIST" -t 4 "ssh://$TARGET")
            TOOL=hydra
            ;;
        A5)
            _require_tool hydra
            [ -n "$CRED_LIST" ] || { echo "A5 requires --cred-list FILE" >&2; exit 1; }
            ARGV=(hydra -l "$FTP_USER" -P "$CRED_LIST" -t 4 "ftp://$TARGET")
            TOOL=hydra
            ;;
        A6)
            _require_tool msfconsole
            [ -n "$MSF_MODULE" ] || { echo "A6 requires --msf-module" >&2; exit 1; }
            local rc_file
            rc_file="$(mktemp)"
            {
                printf 'use %s\n' "$MSF_MODULE"
                printf 'set RHOSTS %s\n' "$TARGET"
                [ -n "$MSF_PAYLOAD" ] && printf 'set PAYLOAD %s\n' "$MSF_PAYLOAD"
                printf 'exploit -z\n'
                printf 'exit -y\n'
            } > "$rc_file"
            ARGV=(msfconsole -q -r "$rc_file")
            TOOL=msfconsole
            ;;
        A7)
            _require_tool nikto
            ARGV=(nikto -h "$TARGET" -p "$WEB_PORT")
            TOOL=nikto
            ;;
        A8)
            _require_tool tcpreplay
            ARGV=(tcpreplay --intf1="$IFACE" "$PCAP_FILE")
            TOOL=tcpreplay
            ;;
        *)
            echo "Unknown attack: $ATTACK (expected A1-A8)" >&2
            exit 1
            ;;
    esac
}

# ---------------------------------------------------------------------------
# Run loop
# ---------------------------------------------------------------------------

OUT_FILE="$OUT_DIR/${ATTACK}.jsonl"
EFFECTIVE_RUNS="$RUNS"
if [ "$ATTACK" = "A8" ]; then
    EFFECTIVE_RUNS=1  # a single labelled capture is one deterministic "run"
fi

for run_no in $(seq 1 "$EFFECTIVE_RUNS"); do
    build_argv "$run_no"
    version="$(_tool_version "$TOOL")"

    start_ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "[$start_ts] $ATTACK run $run_no/$EFFECTIVE_RUNS: ${ARGV[*]}"

    if [ "${DRY_RUN:-0}" = "1" ]; then
        echo "  (dry run) ${ARGV[*]}"
    else
        "${ARGV[@]}" || echo "  attack command exited non-zero (recorded anyway)" >&2
    fi

    end_ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

    argv_json="$(printf '%s\n' "${ARGV[@]}" | python3 -c 'import json,sys; print(json.dumps([l.rstrip(chr(10)) for l in sys.stdin]))')"

    python3 - "$ATTACK" "$run_no" "$start_ts" "$end_ts" "$TARGET" "$version" "$argv_json" "$OUT_FILE" <<'PY'
import json
import sys

attack, run_no, start_ts, end_ts, target, version, argv_json, out_file = sys.argv[1:9]
record = {
    "attack_id": attack,
    "run_no": int(run_no),
    "start_ts": start_ts,
    "end_ts": end_ts,
    "target": target,
    "tool_version": version,
    "argv": json.loads(argv_json),
}
with open(out_file, "a") as f:
    f.write(json.dumps(record) + "\n")
PY

    if [ "$run_no" -lt "$EFFECTIVE_RUNS" ]; then
        gap=$(( (RANDOM % 61) + 30 ))  # 30-90s
        echo "  sleeping ${gap}s before next run"
        sleep "$gap"
    fi
done

echo "Done: $EFFECTIVE_RUNS run(s) logged to $OUT_FILE"
