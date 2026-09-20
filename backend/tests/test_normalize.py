"""M5 normalizer tests: severity mapping, timestamps, dedup key stability."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from app.models.event import Severity
from app.pipeline.normalize import (
    SEVERITY_BY_SURICATA_PRIORITY,
    NormalizeError,
    compute_dedup_key,
    normalize,
    parse_timestamp,
)

ALERT = {
    "timestamp": "2026-09-14T16:42:26.123456+0000",
    "flow_id": 1234567890123456,
    "event_type": "alert",
    "src_ip": "192.168.56.100",
    "src_port": 54321,
    "dest_ip": "192.168.56.1",
    "dest_port": 22,
    "proto": "TCP",
    "alert": {
        "signature": "ET SCAN Potential SSH Scan",
        "signature_id": 2001219,
        "rev": 5,
        "severity": 2,
        "category": "Attempted Information Leak",
    },
}


# --------------------------------------------------------------------------
# Severity mapping — the platform-wide contract
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "priority,expected",
    [
        (1, Severity.CRITICAL),
        (2, Severity.HIGH),
        (3, Severity.MEDIUM),
        (4, Severity.LOW),
    ],
)
def test_suricata_priority_maps_to_platform_severity(priority, expected):
    """1→critical, 2→high, 3→medium, 4→low. M2 Badge, M7 scoring and M9
    reports all depend on this exact mapping."""
    record = {**ALERT, "alert": {**ALERT["alert"], "severity": priority}}
    assert normalize(record).severity == expected.value


def test_mapping_table_is_complete_and_exclusive():
    assert set(SEVERITY_BY_SURICATA_PRIORITY) == {1, 2, 3, 4}
    assert set(SEVERITY_BY_SURICATA_PRIORITY.values()) == {
        Severity.CRITICAL,
        Severity.HIGH,
        Severity.MEDIUM,
        Severity.LOW,
    }


def test_unknown_priority_falls_back_to_info():
    for bad in [0, 5, 99, None, "high"]:
        record = {**ALERT, "alert": {**ALERT["alert"], "severity": bad}}
        assert normalize(record).severity == Severity.INFO.value


@pytest.mark.parametrize("event_type", ["flow", "dns", "http", "tls"])
def test_non_alert_types_are_info(event_type):
    """Context records are not detections and must not inflate severity."""
    record = {"timestamp": ALERT["timestamp"], "event_type": event_type, "src_ip": "10.0.0.1"}
    assert normalize(record).severity == Severity.INFO.value


# --------------------------------------------------------------------------
# Timestamps
# --------------------------------------------------------------------------


def test_timestamp_is_parsed_to_utc_aware():
    parsed = parse_timestamp("2026-09-14T16:42:26.123456+0000")
    assert parsed.tzinfo is not None
    assert parsed.utcoffset() == timedelta(0)
    assert parsed.year == 2026 and parsed.hour == 16


def test_offset_timestamps_are_converted_not_stripped():
    plus_two = parse_timestamp("2026-09-14T18:42:26.000000+0200")
    utc = parse_timestamp("2026-09-14T16:42:26.000000+0000")
    assert plus_two == utc


def test_colon_style_offset_also_parses():
    assert parse_timestamp("2026-09-14T16:42:26+00:00").hour == 16


def test_naive_timestamp_is_assumed_utc_not_dropped():
    parsed = parse_timestamp("2026-09-14T16:42:26")
    assert parsed.tzinfo is not None


@pytest.mark.parametrize("bad", [None, "", "not-a-date", 12345, "2026-13-45T99:99:99"])
def test_bad_timestamps_raise(bad):
    with pytest.raises(NormalizeError):
        parse_timestamp(bad)


def test_normalized_event_never_has_a_naive_timestamp():
    assert normalize(ALERT).ts.tzinfo is not None


# --------------------------------------------------------------------------
# Dedup key
# --------------------------------------------------------------------------


def test_dedup_key_is_stable_for_identical_records():
    assert normalize(ALERT).dedup_key == normalize(dict(ALERT)).dedup_key


def test_dedup_key_ignores_sub_second_jitter():
    """Suricata can re-emit the same alert across a reload with microsecond
    drift. Those are duplicates, not two detections."""
    a = normalize(ALERT)
    b = normalize({**ALERT, "timestamp": "2026-09-14T16:42:26.999999+0000"})
    assert a.dedup_key == b.dedup_key


def test_dedup_key_differs_across_seconds():
    a = normalize(ALERT)
    b = normalize({**ALERT, "timestamp": "2026-09-14T16:42:27.123456+0000"})
    assert a.dedup_key != b.dedup_key


@pytest.mark.parametrize(
    "field,value",
    [
        ("src_ip", "192.168.56.200"),
        ("dest_ip", "192.168.56.9"),
        ("src_port", 9999),
        ("dest_port", 80),
        ("proto", "UDP"),
    ],
)
def test_dedup_key_changes_with_each_identity_field(field, value):
    assert normalize(ALERT).dedup_key != normalize({**ALERT, field: value}).dedup_key


def test_dedup_key_changes_with_signature_id():
    other = {**ALERT, "alert": {**ALERT["alert"], "signature_id": 9999999}}
    assert normalize(ALERT).dedup_key != normalize(other).dedup_key


def test_dedup_key_is_32_bytes():
    assert len(normalize(ALERT).dedup_key) == 32


def test_same_tuple_different_event_type_is_not_a_duplicate():
    """An alert and a flow describing the same connection are distinct rows."""
    flow = {**ALERT, "event_type": "flow"}
    assert normalize(ALERT).dedup_key != normalize(flow).dedup_key


def test_compute_dedup_key_is_deterministic_across_calls():
    ts = datetime(2026, 9, 14, 16, 42, 26, tzinfo=timezone.utc)
    args = (ts, 2001219, "10.0.0.1", 1234, "10.0.0.2", 80, "tcp")
    assert compute_dedup_key(*args) == compute_dedup_key(*args)


# --------------------------------------------------------------------------
# Field extraction
# --------------------------------------------------------------------------


def test_alert_fields_are_extracted():
    event = normalize(ALERT)
    assert event.signature == "ET SCAN Potential SSH Scan"
    assert event.signature_id == 2001219
    assert event.rev == 5
    assert event.category == "Attempted Information Leak"
    assert event.flow_id == 1234567890123456
    assert event.proto == "tcp"  # lowercased
    assert event.src_ip == "192.168.56.100"
    assert event.dst_ip == "192.168.56.1"


def test_raw_record_is_preserved_in_full():
    """The field you did not model is the one the investigation needs."""
    event = normalize(ALERT)
    assert event.raw == ALERT
    assert event.raw["alert"]["category"] == "Attempted Information Leak"


def test_stats_records_are_skipped_not_errors():
    record = {"timestamp": ALERT["timestamp"], "event_type": "stats", "stats": {"uptime": 30}}
    assert normalize(record) is None


def test_unmodelled_event_types_are_skipped():
    for event_type in ["fileinfo", "anomaly", "ssh", "smtp"]:
        record = {"timestamp": ALERT["timestamp"], "event_type": event_type}
        assert normalize(record) is None


def test_missing_event_type_raises():
    with pytest.raises(NormalizeError):
        normalize({"timestamp": ALERT["timestamp"]})


def test_non_dict_raises():
    with pytest.raises(NormalizeError):
        normalize(["not", "a", "dict"])


def test_out_of_range_ports_become_none():
    event = normalize({**ALERT, "src_port": 99999, "dest_port": -1})
    assert event.src_port is None
    assert event.dst_port is None


def test_flow_record_without_alert_block_normalizes():
    record = {
        "timestamp": ALERT["timestamp"],
        "event_type": "flow",
        "src_ip": "192.168.56.5",
        "dest_ip": "8.8.8.8",
        "proto": "UDP",
        "flow_id": 42,
    }
    event = normalize(record)
    assert event.signature is None
    assert event.signature_id is None
    assert event.severity == Severity.INFO.value
    assert event.flow_id == 42
