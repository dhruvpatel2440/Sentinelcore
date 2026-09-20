"""Unix domain socket server for the privileged helper.

No TCP listener exists anywhere in this process, by design: the only way to
reach a privileged operation is a filesystem socket whose permissions the
kernel enforces (root:sentinelcore, 0660).
"""

from __future__ import annotations

import grp
import logging
import os
import signal
import socket
import socketserver
import sys
import threading
import uuid

from helper.config import config
from helper.executor import ExecutionError
from helper.ops import OPS
from helper.protocol import ProtocolError, error_response, ok_response, parse_request
from helper.validation import ValidationError

logger = logging.getLogger("helper.server")

_shutdown = threading.Event()


class RequestHandler(socketserver.StreamRequestHandler):
    # A scan can take minutes; do not drop the connection under it.
    timeout = max(config.nmap_timeout_seconds, config.default_op_timeout_seconds) + 60

    def handle(self) -> None:
        while not _shutdown.is_set():
            try:
                line = self.rfile.readline(config.max_request_bytes + 1)
            except (TimeoutError, socket.timeout):
                logger.info("connection idle timeout")
                return
            except OSError as exc:
                logger.info("connection read error: %s", exc)
                return

            if not line:
                return  # client closed

            if len(line) > config.max_request_bytes:
                self._respond(error_response("", "request_too_large", "Request exceeds size limit"))
                return

            self._handle_line(line.strip())

    def _handle_line(self, line: bytes) -> None:
        if not line:
            return

        request_id = ""
        try:
            op, request_id, params = parse_request(line)
        except ProtocolError as exc:
            logger.warning("rejected malformed request: %s", exc.message)
            self._respond(error_response(request_id, exc.code, exc.message))
            return

        if not request_id:
            request_id = str(uuid.uuid4())

        handler = OPS.get(op)
        if handler is None:
            # Unknown ops are refused outright — no fallback, no passthrough.
            logger.warning("request_id=%s rejected unknown op=%r", request_id, op)
            self._respond(error_response(request_id, "unknown_op", f"Unknown operation: {op}"))
            return

        logger.info("request_id=%s op=%s params=%s", request_id, op, sorted(params))

        try:
            data = handler(params)
        except ValidationError as exc:
            logger.warning("request_id=%s op=%s rejected: %s", request_id, op, exc.message)
            self._respond(error_response(request_id, exc.code, exc.message))
        except ExecutionError as exc:
            logger.error("request_id=%s op=%s failed: %s", request_id, op, exc.message)
            self._respond(error_response(request_id, exc.code, exc.message))
        except Exception:
            # Never leak a traceback across the socket.
            logger.exception("request_id=%s op=%s crashed", request_id, op)
            self._respond(error_response(request_id, "internal_error", "Internal helper error"))
        else:
            logger.info("request_id=%s op=%s ok", request_id, op)
            self._respond(ok_response(request_id, data))

    def _respond(self, payload: bytes) -> None:
        try:
            self.wfile.write(payload)
            self.wfile.flush()
        except OSError as exc:
            logger.info("failed to write response: %s", exc)


class ThreadedUnixServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True
    # Do not let socketserver unlink/recreate on its own; we manage the path.
    allow_reuse_address = False


def _prepare_shared_dirs() -> None:
    """Make the rule staging directory writable by the backend.

    The backend composes a candidate rule file and drops it here; the helper
    then verifies its checksum and promotes it. A named volume is created
    root:root, so without this the unprivileged backend cannot stage anything
    and every rule update fails at the first write.

    setgid (2770) so files the backend creates inherit the sentinelcore group
    and stay readable by this process.
    """
    try:
        gid = grp.getgrnam(config.socket_group).gr_gid
    except KeyError:
        logger.error("group %r missing; cannot prepare shared directories", config.socket_group)
        return

    for directory in (config.suricata_staging_dir, config.suricata_rules_dir):
        try:
            directory.mkdir(parents=True, exist_ok=True)
            os.chown(directory, 0, gid)
            os.chmod(directory, 0o2770)
            logger.info("prepared %s as root:%s mode 2770", directory, config.socket_group)
        except PermissionError:
            logger.warning(
                "cannot adjust ownership of %s (needs CAP_CHOWN); "
                "the backend may be unable to stage rule files",
                directory,
            )
        except OSError as exc:
            logger.warning("could not prepare %s: %s", directory, exc)


def _prepare_socket_path() -> None:
    socket_path = config.socket_path
    socket_path.parent.mkdir(parents=True, exist_ok=True)

    # A stale socket from an unclean shutdown would block bind().
    if socket_path.exists() or socket_path.is_socket():
        logger.info("removing stale socket at %s", socket_path)
        socket_path.unlink(missing_ok=True)


def _secure_socket_path() -> None:
    """Own the socket root:sentinelcore with mode 0660.

    Done *after* bind, because the socket file only exists from then on. The
    backend container joins the `sentinelcore` group to gain access; nothing
    else on the host can open it.
    """
    socket_path = config.socket_path
    try:
        gid = grp.getgrnam(config.socket_group).gr_gid
    except KeyError:
        logger.error(
            "group %r does not exist in the helper image; refusing to expose the socket",
            config.socket_group,
        )
        raise

    try:
        os.chown(socket_path, 0, gid)
    except PermissionError:
        # Missing CAP_CHOWN. Tolerable only if the socket already carries the
        # right group (e.g. inherited from a setgid mount point).
        current_gid = socket_path.stat().st_gid
        if current_gid != gid:
            socket_path.unlink(missing_ok=True)
            raise RuntimeError(
                f"Cannot set socket group to {config.socket_group} (needs CAP_CHOWN) and it is "
                f"currently gid={current_gid}. Refusing to expose a wrongly-owned socket."
            ) from None
        logger.warning("CAP_CHOWN unavailable, but socket group is already correct")

    os.chmod(socket_path, config.socket_mode)

    stat = socket_path.stat()
    # Fail closed rather than serve a socket anything on the host can open.
    if stat.st_mode & 0o007:
        socket_path.unlink(missing_ok=True)
        raise RuntimeError("Refusing to serve: helper socket is world-accessible")

    logger.info(
        "socket %s secured uid=%d gid=%d mode=%o",
        socket_path,
        stat.st_uid,
        stat.st_gid,
        stat.st_mode & 0o777,
    )


def serve() -> int:
    logging.basicConfig(
        level=os.getenv("HELPER_LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        stream=sys.stdout,
    )

    if os.geteuid() != 0:
        logger.warning("helper is not running as root; privileged ops will fail")

    logger.info(
        "helper starting: monitored_network=%s nmap=%s ops=%s",
        config.monitored_network,
        config.nmap_path or "MISSING",
        sorted(OPS),
    )

    _prepare_shared_dirs()
    _prepare_socket_path()

    server = ThreadedUnixServer(str(config.socket_path), RequestHandler)
    _secure_socket_path()

    def _stop(signum, _frame):
        logger.info("received signal %s, shutting down", signum)
        _shutdown.set()
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)

    try:
        logger.info("listening on %s", config.socket_path)
        server.serve_forever(poll_interval=0.5)
    finally:
        server.server_close()
        config.socket_path.unlink(missing_ok=True)
        logger.info("helper stopped")

    return 0


if __name__ == "__main__":
    sys.exit(serve())
