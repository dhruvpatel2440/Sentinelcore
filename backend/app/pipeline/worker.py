"""Pipeline worker entrypoint.

Runs as a SEPARATE container from the API, sharing the backend image with a
different command. The API must never tail a file in a background thread: an
API restart would then lose the reader position, and API replicas would each
tail the same file and duplicate every event.

    python -m app.pipeline.worker
"""

from __future__ import annotations

import asyncio
import logging
import signal
import sys

from app.core.config import settings
from app.core.redis import close_redis, get_redis
from app.correlation.engine import run_forever as run_correlation_engine
from app.db.session import SessionLocal, engine
from app.pipeline.partitions import ensure_partitions
from app.pipeline.retention import enforce_retention
from app.pipeline.tailer import EveTailer
from app.pipeline.writer import EventWriter
from app.pcap.generator import enforce_pcap_retention
from app.pcap.generator import run_forever as run_pcap_parser
from app.reports.generator import enforce_report_retention
from app.reports.generator import run_forever as run_report_generator
from app.reports.scheduling import run_forever as run_report_scheduler
from app.services.firewall import run_expiry_loop as run_firewall_expiry
from app.services.firewall import run_reconcile_loop as run_firewall_reconcile
from app.services.promotion import run_forever as run_promotion_subscriber

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
    stream=sys.stdout,
)
logger = logging.getLogger("sentinelcore.pipeline.worker")

MAINTENANCE_INTERVAL_SECONDS = 24 * 3600


async def maintenance_loop(stop: asyncio.Event) -> None:
    """Pre-create next month's partition and enforce retention, daily."""
    while not stop.is_set():
        try:
            async with SessionLocal() as db:
                await ensure_partitions(db)
                result = await enforce_retention(db)
                if result["dropped"]:
                    logger.info("retention dropped: %s", result["dropped"])
            expired_reports = await enforce_report_retention(SessionLocal)
            if expired_reports:
                logger.info("report retention removed %d expired report(s)", expired_reports)
            expired_pcaps = await enforce_pcap_retention(SessionLocal)
            if expired_pcaps:
                logger.info("pcap retention removed %d expired capture(s)", expired_pcaps)
        except Exception as exc:  # noqa: BLE001
            logger.error("maintenance pass failed: %s", exc)

        try:
            await asyncio.wait_for(stop.wait(), timeout=MAINTENANCE_INTERVAL_SECONDS)
        except asyncio.TimeoutError:
            continue


async def main() -> int:
    logger.info(
        "pipeline worker starting (eve=%s retention=%dd)",
        settings.suricata_eve_log,
        settings.event_retention_days,
    )

    redis = get_redis()

    # Partitions must exist before the first insert, or every write fails.
    async with SessionLocal() as db:
        await ensure_partitions(db)

    tailer = EveTailer(settings.suricata_eve_log, redis)
    writer = EventWriter(redis)
    stop = asyncio.Event()

    def _shutdown(signum, _frame=None):
        logger.info("received signal %s, shutting down", signum)
        tailer.stop()
        writer.stop()
        stop.set()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            loop.add_signal_handler(sig, _shutdown, sig)
        except NotImplementedError:  # pragma: no cover
            signal.signal(sig, _shutdown)

    tasks = [
        asyncio.create_task(tailer.run(), name="tailer"),
        asyncio.create_task(writer.run(), name="writer"),
        asyncio.create_task(maintenance_loop(stop), name="maintenance"),
        asyncio.create_task(run_correlation_engine(SessionLocal, redis, stop), name="correlation"),
        asyncio.create_task(run_promotion_subscriber(SessionLocal, redis, stop), name="promotion"),
        asyncio.create_task(run_report_generator(SessionLocal, redis, stop), name="report_generator"),
        asyncio.create_task(run_report_scheduler(SessionLocal, redis, stop), name="report_scheduler"),
        asyncio.create_task(run_firewall_expiry(SessionLocal, stop), name="firewall_expiry"),
        asyncio.create_task(run_firewall_reconcile(SessionLocal, redis, stop), name="firewall_reconcile"),
        asyncio.create_task(run_pcap_parser(SessionLocal, redis, stop), name="pcap_parser"),
    ]

    done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_EXCEPTION)

    for task in done:
        if task.exception() is not None:
            logger.error("stage %s crashed: %s", task.get_name(), task.exception())

    _shutdown("shutdown")
    for task in pending:
        task.cancel()
    await asyncio.gather(*pending, return_exceptions=True)

    await close_redis()
    await engine.dispose()
    logger.info("pipeline worker stopped")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
