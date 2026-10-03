from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict

from app.models.pcap import ArtifactType, PcapStatus


class PcapFileOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    filename: str
    sha256: str
    size_bytes: int
    status: PcapStatus
    packet_count: int | None
    first_packet_ts: datetime | None
    last_packet_ts: datetime | None
    duration_seconds: float | None
    link_type: str | None
    capture_interface: str | None
    flow_truncated: bool
    error: str | None
    uploaded_by: uuid.UUID | None
    uploaded_at: datetime
    parsed_at: datetime | None
    incident_id: uuid.UUID | None


class PcapUploadAccepted(BaseModel):
    id: uuid.UUID
    status: PcapStatus
    sha256: str
    duplicate: bool


class PcapFlowOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    pcap_id: uuid.UUID
    stream_id: int
    protocol: str
    src_ip: str
    src_port: int | None
    dst_ip: str
    dst_port: int | None
    packet_count: int
    byte_count: int
    start_ts: datetime | None
    end_ts: datetime | None
    duration_ms: int | None
    app_protocol: str | None
    summary: str | None
    src_asset_id: uuid.UUID | None
    dst_asset_id: uuid.UUID | None
    src_asset_hostname: str | None = None
    dst_asset_hostname: str | None = None


class PcapArtifactOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    pcap_id: uuid.UUID
    flow_id: uuid.UUID | None
    artifact_type: ArtifactType
    value: str
    detail: dict[str, Any] | None
    packet_number: int | None
    ts: datetime | None


class PcapAttachRequest(BaseModel):
    incident_id: uuid.UUID
