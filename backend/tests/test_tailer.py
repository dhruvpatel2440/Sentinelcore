"""M5 tailer tests: rotation and truncation against a real file on disk.

Rotation is the most common cause of silent event loss, so these use actual
files and actual inode changes rather than mocks.
"""

from __future__ import annotations

import json

import pytest

from app.pipeline.tailer import EveTailer, FileIdentity


class FakeRedis:
    """Minimal in-memory stand-in: enough for offsets, XADD and metrics."""

    def __init__(self) -> None:
        self.store: dict[str, bytes] = {}
        self.stream: list[bytes] = []
        self.hashes: dict[str, dict] = {}

    async def get(self, key):
        return self.store.get(key)

    async def set(self, key, value):
        self.store[key] = value if isinstance(value, bytes) else str(value).encode()

    async def hset(self, key, mapping=None, **kw):
        self.hashes.setdefault(key, {}).update(mapping or {})

    def pipeline(self, transaction=False):
        return FakePipeline(self)


class FakePipeline:
    def __init__(self, redis: FakeRedis) -> None:
        self.redis = redis
        self.queued: list[bytes] = []

    def xadd(self, key, fields, maxlen=None, approximate=True):
        self.queued.append(fields[b"record"])

    async def execute(self):
        self.redis.stream.extend(self.queued)
        self.queued = []


def line(n: int, event_type: str = "alert") -> str:
    return json.dumps(
        {
            "timestamp": "2026-09-14T16:42:26.000000+0000",
            "event_type": event_type,
            "src_ip": f"192.168.56.{n % 250 + 1}",
            "dest_ip": "192.168.56.1",
            "proto": "TCP",
            "seq": n,
        }
    )


def write_lines(path, start: int, count: int, mode: str = "a") -> None:
    with open(path, mode) as fh:
        for i in range(start, start + count):
            fh.write(line(i) + "\n")


def published_seqs(redis: FakeRedis) -> list[int]:
    return [json.loads(raw)["seq"] for raw in redis.stream]


@pytest.fixture
def eve(tmp_path):
    path = tmp_path / "eve.json"
    path.write_text("")
    return path


@pytest.fixture
def redis():
    return FakeRedis()


# --------------------------------------------------------------------------
# Basic reading
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_reads_all_complete_lines(eve, redis):
    write_lines(eve, 0, 10)
    tailer = EveTailer(eve, redis)
    assert await tailer._open()

    await tailer._publish(tailer._read_lines(100))
    assert published_seqs(redis) == list(range(10))


@pytest.mark.asyncio
async def test_partial_trailing_line_is_not_consumed(eve, redis):
    """Suricata can be mid-write. A line without a newline must be left alone
    and re-read once complete — never emitted as a truncated record."""
    write_lines(eve, 0, 3)
    with open(eve, "a") as fh:
        fh.write('{"timestamp": "2026-09-14T16:42:26.00')  # no newline

    tailer = EveTailer(eve, redis)
    await tailer._open()
    offset_before = tailer._offset

    lines = tailer._read_lines(100)
    assert len(lines) == 3
    assert tailer._offset > offset_before

    # Complete the line; the next pass picks it up whole.
    with open(eve, "a") as fh:
        fh.write('0000+0000", "event_type": "alert", "seq": 99}\n')

    more = tailer._read_lines(100)
    assert len(more) == 1
    assert json.loads(more[0])["seq"] == 99


@pytest.mark.asyncio
async def test_malformed_line_is_counted_and_skipped_not_fatal(eve, redis):
    with open(eve, "w") as fh:
        fh.write(line(1) + "\n")
        fh.write("{this is not json at all}\n")
        fh.write(line(2) + "\n")

    tailer = EveTailer(eve, redis)
    await tailer._open()
    await tailer._publish(tailer._read_lines(100))

    assert published_seqs(redis) == [1, 2]
    assert tailer.parse_errors == 1


# --------------------------------------------------------------------------
# Rotation: new inode (logrotate `create`)
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_rotation_to_new_inode_is_detected(eve, redis, tmp_path):
    write_lines(eve, 0, 5)
    tailer = EveTailer(eve, redis)
    await tailer._open()
    tailer._read_lines(100)

    assert tailer._rotation_state() == "same"

    # logrotate: move the old file aside, create a fresh one.
    eve.rename(tmp_path / "eve.json.1")
    eve.write_text("")

    assert tailer._rotation_state() == "rotated"


@pytest.mark.asyncio
async def test_rotation_loses_no_events(eve, redis, tmp_path):
    """The definition-of-done case: lines written between the last read and
    the rename must still be drained from the OLD handle."""
    write_lines(eve, 0, 5)
    tailer = EveTailer(eve, redis)
    await tailer._open()
    await tailer._publish(tailer._read_lines(100))

    # Written after our last read, before rotation — easily lost if the old
    # handle is discarded instead of drained.
    write_lines(eve, 5, 3)

    eve.rename(tmp_path / "eve.json.1")
    eve.write_text("")

    assert tailer._rotation_state() == "rotated"
    # Drain the old handle first, exactly as run() does.
    await tailer._publish(tailer._read_lines(1000))

    tailer._close()
    tailer._identity = None
    tailer._offset = 0
    await tailer._open()

    write_lines(eve, 8, 4)
    await tailer._publish(tailer._read_lines(1000))

    assert published_seqs(redis) == list(range(12)), "no gap across rotation"


@pytest.mark.asyncio
async def test_rotation_creates_no_duplicates(eve, redis, tmp_path):
    write_lines(eve, 0, 5)
    tailer = EveTailer(eve, redis)
    await tailer._open()
    await tailer._publish(tailer._read_lines(100))

    eve.rename(tmp_path / "eve.json.1")
    eve.write_text("")
    await tailer._publish(tailer._read_lines(1000))

    tailer._close()
    tailer._identity = None
    tailer._offset = 0
    await tailer._open()
    write_lines(eve, 5, 5)
    await tailer._publish(tailer._read_lines(1000))

    seqs = published_seqs(redis)
    assert seqs == list(range(10))
    assert len(seqs) == len(set(seqs)), "no duplicates across rotation"


# --------------------------------------------------------------------------
# Truncation (logrotate `copytruncate`)
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_truncation_without_rotation_is_detected(eve, redis):
    write_lines(eve, 0, 10)
    tailer = EveTailer(eve, redis)
    await tailer._open()
    tailer._read_lines(100)
    assert tailer._offset > 0

    # copytruncate: same inode, size reset to 0.
    with open(eve, "w"):
        pass

    assert tailer._rotation_state() == "truncated"


@pytest.mark.asyncio
async def test_truncation_resets_offset_and_keeps_reading(eve, redis):
    write_lines(eve, 0, 10)
    tailer = EveTailer(eve, redis)
    await tailer._open()
    await tailer._publish(tailer._read_lines(100))

    with open(eve, "w"):
        pass
    assert tailer._rotation_state() == "truncated"

    tailer._offset = 0
    tailer._handle.seek(0)

    write_lines(eve, 100, 3)
    await tailer._publish(tailer._read_lines(100))

    assert published_seqs(redis) == list(range(10)) + [100, 101, 102]


# --------------------------------------------------------------------------
# Offset persistence
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_offset_is_persisted_with_inode(eve, redis):
    write_lines(eve, 0, 5)
    tailer = EveTailer(eve, redis)
    await tailer._open()
    tailer._read_lines(100)
    await tailer._save_offset()

    saved = json.loads(redis.store["pipeline:eve:offset"])
    assert saved["offset"] == tailer._offset
    assert saved["ino"] == eve.stat().st_ino


@pytest.mark.asyncio
async def test_restart_resumes_from_persisted_offset(eve, redis):
    """Exactly right, not approximately: no replay and no skip."""
    write_lines(eve, 0, 5)
    first = EveTailer(eve, redis)
    await first._open()
    await first._publish(first._read_lines(100))
    await first._save_offset()
    first._close()

    write_lines(eve, 5, 5)

    second = EveTailer(eve, redis)
    await second._open()
    await second._publish(second._read_lines(100))

    assert published_seqs(redis) == list(range(10))


@pytest.mark.asyncio
async def test_new_inode_ignores_a_stale_saved_offset(eve, redis, tmp_path):
    """A saved offset from a different file must not be applied to a new one,
    or the first N bytes of the new file are silently skipped."""
    write_lines(eve, 0, 20)
    first = EveTailer(eve, redis)
    await first._open()
    first._read_lines(100)
    await first._save_offset()
    first._close()

    eve.unlink()
    eve.write_text("")
    write_lines(eve, 100, 3)

    second = EveTailer(eve, redis)
    await second._open()
    assert second._offset == 0
    await second._publish(second._read_lines(100))
    assert published_seqs(redis) == [100, 101, 102]


@pytest.mark.asyncio
async def test_saved_offset_beyond_file_size_is_treated_as_truncation(eve, redis):
    write_lines(eve, 0, 10)
    tailer = EveTailer(eve, redis)
    await tailer._open()
    tailer._read_lines(100)
    await tailer._save_offset()
    tailer._close()

    # File shrank while we were away (copytruncate during downtime).
    with open(eve, "w"):
        pass
    write_lines(eve, 50, 2)

    resumed = EveTailer(eve, redis)
    await resumed._open()
    assert resumed._offset == 0
    await resumed._publish(resumed._read_lines(100))
    assert published_seqs(resumed.redis) == [50, 51]


@pytest.mark.asyncio
async def test_missing_file_is_handled(tmp_path, redis):
    tailer = EveTailer(tmp_path / "does-not-exist.json", redis)
    assert await tailer._open() is False


def test_file_identity_equality(tmp_path):
    a = tmp_path / "a"
    a.write_text("x")
    stat = a.stat()
    assert FileIdentity.of(stat) == FileIdentity.of(a.stat())
    assert FileIdentity.of(stat) != FileIdentity(dev=stat.st_dev, ino=stat.st_ino + 1)
