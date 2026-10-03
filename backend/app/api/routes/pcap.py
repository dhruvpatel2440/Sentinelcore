"""M11 — PCAP upload and analysis.

Threat model: an uploaded capture is attacker-controlled, sometimes literally
captured from an attack. The upload handler never trusts the client filename,
the declared Content-Length, or the extension — see the inline notes below.
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, File, HTTPException, Query, Request, UploadFile, status
from fastapi.responses import FileResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, require_role
from app.core.config import settings
from app.core.redis import get_redis
from app.db.session import get_db
from app.models.asset import Asset
from app.models.pcap import ArtifactType, PcapArtifact, PcapFile, PcapFlow, PcapStatus
from app.models.user import User
from app.pcap import parser
from app.pcap.parser import ParseError
from app.schemas.pcap import PcapArtifactOut, PcapAttachRequest, PcapFileOut, PcapFlowOut, PcapUploadAccepted
from app.services import audit

router = APIRouter(prefix="/pcap", tags=["pcap"])

# pcap: 0xa1b2c3d4 / 0xd4c3b2a1 and the nanosecond-resolution variants.
# pcapng: 0x0a0d0d0a. Checked by magic bytes, never by extension.
_MAGIC_PREFIXES = (
    b"\xa1\xb2\xc3\xd4", b"\xd4\xc3\xb2\xa1",
    b"\xa1\xb2\x3c\x4d", b"\x4d\x3c\xb2\xa1",
    b"\x0a\x0d\x0d\x0a",
)


def _storage_root() -> Path:
    root = Path(settings.pcap_storage_path)
    root.mkdir(parents=True, exist_ok=True)
    return root


def _assert_contained(path: Path, root: Path) -> None:
    if root.resolve() not in path.resolve().parents:
        raise HTTPException(status_code=500, detail="resolved pcap path escaped the storage root")


@router.post("/upload", response_model=PcapUploadAccepted, status_code=status.HTTP_202_ACCEPTED)
async def upload_pcap(
    request: Request,
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
    actor: User = Depends(require_role("analyst", "admin")),
) -> PcapUploadAccepted:
    root = _storage_root()
    tmp_path = root / f"{uuid.uuid4()}.tmp"
    max_bytes = settings.max_pcap_size_mb * 1024 * 1024

    digest = hashlib.sha256()
    size = 0
    checked_magic = False

    try:
        with tmp_path.open("wb") as out:
            while True:
                chunk = await file.read(settings.pcap_upload_chunk_bytes)
                if not chunk:
                    break

                if not checked_magic:
                    if not any(chunk.startswith(sig) for sig in _MAGIC_PREFIXES):
                        raise HTTPException(
                            status_code=400, detail="not a valid pcap/pcapng file (magic bytes did not match)"
                        )
                    checked_magic = True

                size += len(chunk)
                if size > max_bytes:
                    raise HTTPException(
                        status_code=413, detail=f"capture exceeds the {settings.max_pcap_size_mb}MB limit"
                    )
                digest.update(chunk)
                out.write(chunk)

        if not checked_magic:
            raise HTTPException(status_code=400, detail="empty upload")
    except HTTPException:
        tmp_path.unlink(missing_ok=True)
        raise
    except Exception:
        tmp_path.unlink(missing_ok=True)
        raise

    sha256 = digest.hexdigest()

    # Re-upload during an investigation is routine — return the existing
    # record rather than storing a duplicate capture.
    existing = (await db.execute(select(PcapFile).where(PcapFile.sha256 == sha256))).scalar_one_or_none()
    if existing is not None:
        tmp_path.unlink(missing_ok=True)
        await audit.record(
            db, action="pcap.uploaded", user=actor, resource_type="pcap_file", resource_id=existing.id,
            detail={"filename": file.filename, "duplicate": True}, request=request,
        )
        await db.commit()
        return PcapUploadAccepted(id=existing.id, status=existing.status, sha256=sha256, duplicate=True)

    final_path = root / f"{uuid.uuid4()}.pcap"
    _assert_contained(final_path, root)
    tmp_path.rename(final_path)

    pcap = PcapFile(
        filename=(file.filename or "capture.pcap")[:255],
        stored_path=str(final_path),
        sha256=sha256,
        size_bytes=size,
        status=PcapStatus.UPLOADED,
        uploaded_by=actor.id,
    )
    db.add(pcap)
    await db.flush()

    await audit.record(
        db, action="pcap.uploaded", user=actor, resource_type="pcap_file", resource_id=pcap.id,
        detail={"filename": pcap.filename, "size_bytes": size, "duplicate": False}, request=request,
    )
    await db.commit()
    await db.refresh(pcap)

    redis = get_redis()
    await redis.lpush(settings.pcap_queue_key, str(pcap.id))

    return PcapUploadAccepted(id=pcap.id, status=pcap.status, sha256=sha256, duplicate=False)


@router.get("", response_model=list[PcapFileOut])
async def list_pcaps(
    status_filter: PcapStatus | None = Query(default=None, alias="status"),
    uploaded_by: uuid.UUID | None = Query(default=None),
    incident_id: uuid.UUID | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
) -> list[PcapFileOut]:
    stmt = select(PcapFile)
    if status_filter:
        stmt = stmt.where(PcapFile.status == status_filter)
    if uploaded_by:
        stmt = stmt.where(PcapFile.uploaded_by == uploaded_by)
    if incident_id:
        stmt = stmt.where(PcapFile.incident_id == incident_id)
    stmt = stmt.order_by(PcapFile.uploaded_at.desc()).limit(limit).offset(offset)
    rows = (await db.execute(stmt)).scalars().all()
    return [PcapFileOut.model_validate(r, from_attributes=True) for r in rows]


async def _get_pcap(db: AsyncSession, pcap_id: uuid.UUID) -> PcapFile:
    pcap = await db.get(PcapFile, pcap_id)
    if pcap is None:
        raise HTTPException(status_code=404, detail="Capture not found")
    return pcap


@router.get("/{pcap_id}", response_model=dict)
async def get_pcap(
    pcap_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
) -> dict:
    pcap = await _get_pcap(db, pcap_id)
    out = PcapFileOut.model_validate(pcap, from_attributes=True).model_dump(mode="json")

    progress = None
    if pcap.status == PcapStatus.PARSING:
        raw = await get_redis().get(f"pcap:progress:{pcap_id}")
        progress = int(raw) if raw else 0
    out["progress"] = progress

    if pcap.status == PcapStatus.PARSED:
        proto_counts = (
            await db.execute(
                select(PcapFlow.app_protocol, PcapFlow.protocol).where(PcapFlow.pcap_id == pcap_id)
            )
        ).all()
        distribution: dict[str, int] = {}
        for app_proto, proto in proto_counts:
            key = app_proto or proto
            distribution[key] = distribution.get(key, 0) + 1
        out["protocol_distribution"] = distribution
        out["flow_count"] = len(proto_counts)
        out["unique_hosts"] = len(
            {ip for row in (await db.execute(select(PcapFlow.src_ip, PcapFlow.dst_ip).where(PcapFlow.pcap_id == pcap_id))).all() for ip in row}
        )

    return out


@router.get("/{pcap_id}/flows", response_model=list[PcapFlowOut])
async def list_flows(
    pcap_id: uuid.UUID,
    ip: str | None = Query(default=None),
    protocol: str | None = Query(default=None),
    app_protocol: str | None = Query(default=None),
    sort: str = Query(default="byte_count", pattern="^(byte_count|packet_count|start_ts)$"),
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
) -> list[PcapFlowOut]:
    await _get_pcap(db, pcap_id)

    stmt = select(PcapFlow).where(PcapFlow.pcap_id == pcap_id)
    if ip:
        stmt = stmt.where((PcapFlow.src_ip == ip) | (PcapFlow.dst_ip == ip))
    if protocol:
        stmt = stmt.where(PcapFlow.protocol == protocol)
    if app_protocol:
        stmt = stmt.where(PcapFlow.app_protocol == app_protocol)
    stmt = stmt.order_by(getattr(PcapFlow, sort).desc()).limit(limit).offset(offset)

    rows = (await db.execute(stmt)).scalars().all()
    asset_ids = {r.src_asset_id for r in rows if r.src_asset_id} | {r.dst_asset_id for r in rows if r.dst_asset_id}
    assets = {}
    if asset_ids:
        assets = {a.id: a.display_hostname for a in (await db.execute(select(Asset).where(Asset.id.in_(asset_ids)))).scalars()}

    out = []
    for r in rows:
        item = PcapFlowOut.model_validate(r, from_attributes=True)
        item.src_asset_hostname = assets.get(r.src_asset_id)
        item.dst_asset_hostname = assets.get(r.dst_asset_id)
        out.append(item)
    return out


async def _get_flow(db: AsyncSession, pcap_id: uuid.UUID, flow_id: uuid.UUID) -> PcapFlow:
    flow = await db.get(PcapFlow, flow_id)
    if flow is None or flow.pcap_id != pcap_id:
        raise HTTPException(status_code=404, detail="Flow not found")
    return flow


@router.get("/{pcap_id}/flows/{flow_id}/packets", response_model=list[dict])
async def flow_packets(
    pcap_id: uuid.UUID,
    flow_id: uuid.UUID,
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
) -> list[dict]:
    pcap = await _get_pcap(db, pcap_id)
    flow = await _get_flow(db, pcap_id, flow_id)
    try:
        return await parser.list_packets_for_flow(
            Path(pcap.stored_path), flow.protocol, flow.stream_id, limit=limit, offset=offset
        )
    except ParseError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@router.get("/{pcap_id}/flows/{flow_id}/follow", response_model=dict)
async def flow_follow(
    pcap_id: uuid.UUID,
    flow_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
) -> dict:
    pcap = await _get_pcap(db, pcap_id)
    flow = await _get_flow(db, pcap_id, flow_id)
    try:
        return await parser.follow_stream(Path(pcap.stored_path), flow.protocol, flow.stream_id)
    except ParseError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@router.get("/{pcap_id}/artifacts", response_model=list[PcapArtifactOut])
async def list_artifacts(
    pcap_id: uuid.UUID,
    artifact_type: ArtifactType | None = Query(default=None),
    q: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
) -> list[PcapArtifactOut]:
    await _get_pcap(db, pcap_id)
    stmt = select(PcapArtifact).where(PcapArtifact.pcap_id == pcap_id)
    if artifact_type:
        stmt = stmt.where(PcapArtifact.artifact_type == artifact_type)
    if q:
        stmt = stmt.where(PcapArtifact.value.ilike(f"%{q}%"))
    stmt = stmt.order_by(PcapArtifact.ts.desc().nulls_last()).limit(limit).offset(offset)
    rows = (await db.execute(stmt)).scalars().all()
    return [PcapArtifactOut.model_validate(r, from_attributes=True) for r in rows]


@router.post("/{pcap_id}/attach", response_model=PcapFileOut)
async def attach_to_incident(
    pcap_id: uuid.UUID,
    payload: PcapAttachRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    actor: User = Depends(require_role("analyst", "admin")),
) -> PcapFileOut:
    pcap = await _get_pcap(db, pcap_id)
    pcap.incident_id = payload.incident_id
    await audit.record(
        db, action="pcap.attached", user=actor, resource_type="pcap_file", resource_id=pcap.id,
        detail={"incident_id": str(payload.incident_id)}, request=request,
    )
    await db.commit()
    await db.refresh(pcap)
    return PcapFileOut.model_validate(pcap, from_attributes=True)


@router.delete("/{pcap_id}", status_code=status.HTTP_204_NO_CONTENT, response_model=None)
async def delete_pcap(
    pcap_id: uuid.UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    actor: User = Depends(get_current_user),
) -> None:
    pcap = await _get_pcap(db, pcap_id)
    if actor.role.value != "admin" and pcap.uploaded_by != actor.id:
        raise HTTPException(status_code=403, detail="Only the uploader or an admin can delete this capture")
    Path(pcap.stored_path).unlink(missing_ok=True)
    await audit.record(
        db, action="pcap.deleted", user=actor, resource_type="pcap_file", resource_id=pcap.id,
        detail={"filename": pcap.filename}, request=request,
    )
    await db.delete(pcap)
    await db.commit()


@router.get("/{pcap_id}/download")
async def download_pcap(
    pcap_id: uuid.UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    actor: User = Depends(require_role("admin")),
):
    """A capture may contain credentials and personal data — downloading the
    raw file is a privileged act, admin-only and audited."""
    pcap = await _get_pcap(db, pcap_id)
    storage_root = Path(settings.pcap_storage_path).resolve()
    resolved = Path(pcap.stored_path).resolve()
    if storage_root not in resolved.parents:
        raise HTTPException(status_code=500, detail="pcap file path is invalid")
    if not resolved.is_file():
        raise HTTPException(status_code=404, detail="pcap file is missing from storage")

    await audit.record(
        db, action="pcap.downloaded", user=actor, resource_type="pcap_file", resource_id=pcap.id,
        detail={"filename": pcap.filename}, request=request,
    )
    await db.commit()

    filename = f"{pcap.id}.pcap"
    return FileResponse(
        path=resolved, media_type="application/vnd.tcpdump.pcap", filename=filename,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
