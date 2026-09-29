"""M5 writer tests: redelivery of stranded messages, ack ordering, dedup."""

from __future__ import annotations

import json

import pytest

from app.pipeline.writer import CLAIM_MIN_IDLE_MS, GROUP_NAME, EventWriter
from app.pipeline.tailer import STREAM_KEY


class FakeRedis:
    """Records what was asked of it so ordering can be asserted."""

    def __init__(self, autoclaim_result=None) -> None:
        self.acked: list[bytes] = []
        self.autoclaim_calls: list[dict] = []
        self.autoclaim_result = autoclaim_result
        self.hashes: dict = {}

    async def xack(self, stream, group, *ids):
        self.acked.extend(ids)
        return len(ids)

    async def xautoclaim(self, stream, group, consumer, min_idle_time=None, count=None):
        self.autoclaim_calls.append(
            {"stream": stream, "group": group, "consumer": consumer,
             "min_idle_time": min_idle_time, "count": count}
        )
        if self.autoclaim_result is None:
            return (b"0-0", [], [])
        return self.autoclaim_result

    async def xlen(self, key):
        return 0

    async def xpending(self, key, group):
        return {"pending": 0}

    async def hset(self, key, mapping=None, **kw):
        self.hashes.update(mapping or {})


def message(seq: int, event_type: str = "alert") -> tuple[bytes, dict]:
    record = {
        "timestamp": "2026-09-14T16:42:26.000000+0000",
        "event_type": event_type,
        "src_ip": "192.168.56.10",
        "dest_ip": "192.168.56.1",
        "src_port": 1000 + seq,
        "dest_port": 22,
        "proto": "TCP",
        "alert": {"signature": "test", "signature_id": 1000 + seq, "rev": 1, "severity": 2},
    }
    return (f"{seq}-0".encode(), {b"record": json.dumps(record).encode()})


# --------------------------------------------------------------------------
# Redelivery of stranded messages
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_claim_stale_uses_xautoclaim_with_the_idle_threshold():
    """Regression: XREADGROUP with '>' never returns already-pending messages.

    A batch left unacked by a database outage would sit pending forever and its
    events would be silently lost. XAUTOCLAIM is what makes at-least-once
    delivery actually hold.
    """
    redis = FakeRedis(autoclaim_result=(b"0-0", [message(1), message(2)], []))
    writer = EventWriter(redis)

    claimed = await writer._claim_stale()

    assert len(claimed) == 2
    call = redis.autoclaim_calls[0]
    assert call["stream"] == STREAM_KEY
    assert call["group"] == GROUP_NAME
    assert call["min_idle_time"] == CLAIM_MIN_IDLE_MS


@pytest.mark.asyncio
async def test_claim_stale_handles_the_two_element_redis6_shape():
    redis = FakeRedis(autoclaim_result=(b"0-0", [message(1)]))
    assert len(await EventWriter(redis)._claim_stale()) == 1


@pytest.mark.asyncio
async def test_claim_stale_returns_empty_when_nothing_is_pending():
    assert await EventWriter(FakeRedis())._claim_stale() == []


@pytest.mark.asyncio
async def test_claim_stale_survives_a_redis_error():
    class Broken(FakeRedis):
        async def xautoclaim(self, *a, **kw):
            raise RuntimeError("redis is down")

    assert await EventWriter(Broken())._claim_stale() == []


# --------------------------------------------------------------------------
# Batch parsing
# --------------------------------------------------------------------------


def test_decode_returns_none_and_counts_unparseable_records():
    writer = EventWriter(FakeRedis())
    assert writer._decode({b"record": b"{not json"}) is None
    assert writer.parse_errors == 1


def test_decode_handles_a_missing_record_field():
    assert EventWriter(FakeRedis())._decode({b"other": b"x"}) is None


def test_enrich_maps_ips_to_assets():
    writer = EventWriter(FakeRedis())
    writer._asset_map = {"192.168.56.10": "asset-a", "192.168.56.1": "asset-b"}

    row = writer._enrich({"src_ip": "192.168.56.10", "dst_ip": "192.168.56.1"})
    assert row["src_asset_id"] == "asset-a"
    assert row["dst_asset_id"] == "asset-b"


def test_enrich_leaves_unknown_ips_null():
    writer = EventWriter(FakeRedis())
    writer._asset_map = {}
    row = writer._enrich({"src_ip": "8.8.8.8", "dst_ip": None})
    assert row["src_asset_id"] is None
    assert row["dst_asset_id"] is None
