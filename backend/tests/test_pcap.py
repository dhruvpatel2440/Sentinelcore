"""M11 regressions: flow serialisation and capinfos metadata parsing."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from ipaddress import ip_address
from types import SimpleNamespace

from app.pcap.parser import _parse_capinfos_datetime
from app.schemas.pcap import PcapFlowOut


def test_flow_out_accepts_inet_objects():
    # asyncpg hands INET columns back as ipaddress objects, not str.
    row = SimpleNamespace(
        id=uuid.uuid4(), pcap_id=uuid.uuid4(), stream_id=0, protocol="tcp",
        src_ip=ip_address("10.0.0.5"), src_port=40000, dst_ip=ip_address("2001:db8::1"), dst_port=80,
        packet_count=2, byte_count=205, start_ts=None, end_ts=None, duration_ms=None,
        app_protocol="http", summary=None, src_asset_id=None, dst_asset_id=None,
    )
    out = PcapFlowOut.model_validate(row, from_attributes=True)
    assert out.src_ip == "10.0.0.5"
    assert out.dst_ip == "2001:db8::1"


def test_capinfos_datetime_micro_and_nanosecond():
    expected = datetime(2026, 10, 5, 5, 5, 51, 461986, tzinfo=timezone.utc)
    assert _parse_capinfos_datetime("2026-10-05 05:05:51.461986") == expected
    assert _parse_capinfos_datetime("2026-10-05 05:05:51.461986123") == expected
    assert _parse_capinfos_datetime("2026-10-05 05:05:51") == expected.replace(microsecond=0)
    assert _parse_capinfos_datetime("n/a") is None
