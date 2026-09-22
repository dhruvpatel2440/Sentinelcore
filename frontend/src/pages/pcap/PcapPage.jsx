import { FileSearch, Plus, RefreshCw } from "lucide-react";
import { useCallback, useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";

import { api } from "../../api/client";
import { useAuth } from "../../auth/AuthContext";
import Badge from "../../components/Badge";
import Button from "../../components/Button";
import EmptyState from "../../components/EmptyState";
import PageHeader from "../../components/PageHeader";
import Table from "../../components/Table";
import { useToast } from "../../components/Toast";
import { duration, formatBytes, relativeTime } from "../../lib/format";
import { STATUS_LABEL, STATUS_TONE } from "./constants";
import PcapUploadModal from "./PcapUploadModal";

const POLL_MS = 4_000;

export default function PcapPage() {
  const toast = useToast();
  const navigate = useNavigate();
  const { hasRole } = useAuth();
  const canUpload = hasRole("analyst", "admin");

  const [captures, setCaptures] = useState([]);
  const [loading, setLoading] = useState(true);
  const [modalOpen, setModalOpen] = useState(false);

  const load = useCallback(
    async (silent = false) => {
      if (!silent) setLoading(true);
      try {
        const data = await api.get("/pcap?limit=100");
        setCaptures(data);
      } catch (err) {
        if (!silent) toast.error(err.message || "Could not load captures");
      } finally {
        if (!silent) setLoading(false);
      }
    },
    [toast],
  );

  useEffect(() => {
    load();
  }, [load]);

  // Poll only while something is still parsing, same pattern as Reports.
  useEffect(() => {
    const hasPending = captures.some((c) => c.status === "parsing");
    if (!hasPending) return undefined;
    const timer = setInterval(() => load(true), POLL_MS);
    return () => clearInterval(timer);
  }, [captures, load]);

  const columns = [
    { key: "filename", header: "Filename", className: "max-w-xs truncate text-slate-100" },
    { key: "size", header: "Size", render: (c) => formatBytes(c.size_bytes) },
    { key: "packets", header: "Packets", render: (c) => (c.packet_count != null ? c.packet_count.toLocaleString() : "—") },
    {
      key: "span",
      header: "Time span",
      render: (c) => (c.duration_seconds != null ? duration(c.duration_seconds) : "—"),
    },
    {
      key: "status",
      header: "Status",
      render: (c) => <Badge tone={STATUS_TONE[c.status]}>{STATUS_LABEL[c.status] || c.status}</Badge>,
    },
    { key: "uploaded_by", header: "Uploader", render: (c) => c.uploaded_by || "—" },
    { key: "incident_id", header: "Incident", render: (c) => (c.incident_id ? c.incident_id.slice(0, 8) : "—") },
    { key: "uploaded_at", header: "Uploaded", render: (c) => relativeTime(c.uploaded_at) },
  ];

  return (
    <>
      <PageHeader
        title="PCAP"
        description="Upload packet captures for flow, artifact and stream analysis."
        actions={
          <div className="flex items-center gap-2">
            <Button variant="secondary" icon={RefreshCw} onClick={() => load()} disabled={loading}>
              Refresh
            </Button>
            {canUpload && (
              <Button icon={Plus} onClick={() => setModalOpen(true)}>
                Upload
              </Button>
            )}
          </div>
        }
      />

      <Table
        columns={columns}
        rows={captures}
        loading={loading}
        rowKey={(c) => c.id}
        onRowClick={(row) => navigate(`/pcap/${row.id}`)}
        empty={
          <EmptyState
            icon={FileSearch}
            title="No captures yet"
            description="Upload a .pcap/.pcapng file to extract flows, artifacts and stream content."
          />
        }
      />

      <PcapUploadModal open={modalOpen} onClose={() => setModalOpen(false)} onUploaded={() => load()} />
    </>
  );
}
