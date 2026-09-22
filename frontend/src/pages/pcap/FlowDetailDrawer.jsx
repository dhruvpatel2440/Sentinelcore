import { useEffect, useState } from "react";

import { api } from "../../api/client";
import Badge from "../../components/Badge";
import Button from "../../components/Button";
import Drawer from "../../components/Drawer";
import Table from "../../components/Table";
import { useToast } from "../../components/Toast";
import { absoluteTime, formatBytes } from "../../lib/format";

const PACKET_LIMIT = 100;

/**
 * Flow detail: packets tab (paginated) and follow-stream tab. The follow
 * content is attacker-controlled capture data — it is rendered as a plain
 * text node inside <pre>, never as HTML.
 */
export default function FlowDetailDrawer({ pcapId, flow, open, onClose }) {
  const toast = useToast();
  const [tab, setTab] = useState("packets");
  const [packets, setPackets] = useState([]);
  const [packetOffset, setPacketOffset] = useState(0);
  const [packetsLoading, setPacketsLoading] = useState(false);
  const [hasMorePackets, setHasMorePackets] = useState(false);

  const [follow, setFollow] = useState(null);
  const [followLoading, setFollowLoading] = useState(false);
  const [followError, setFollowError] = useState(null);

  useEffect(() => {
    if (!open || !flow) return;
    setTab("packets");
    setPackets([]);
    setPacketOffset(0);
    setFollow(null);
    setFollowError(null);
  }, [open, flow]);

  const loadPackets = async (offset) => {
    setPacketsLoading(true);
    try {
      const data = await api.get(`/pcap/${pcapId}/flows/${flow.id}/packets?limit=${PACKET_LIMIT}&offset=${offset}`);
      setPackets(offset === 0 ? data : (list) => [...list, ...data]);
      setHasMorePackets(data.length === PACKET_LIMIT);
      setPacketOffset(offset);
    } catch (err) {
      toast.error(err.message || "Could not load packets");
    } finally {
      setPacketsLoading(false);
    }
  };

  useEffect(() => {
    if (open && flow && tab === "packets" && packets.length === 0) {
      loadPackets(0);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, flow, tab]);

  useEffect(() => {
    if (open && flow && tab === "follow" && follow === null && !followLoading) {
      setFollowLoading(true);
      setFollowError(null);
      api
        .get(`/pcap/${pcapId}/flows/${flow.id}/follow`)
        .then(setFollow)
        .catch((err) => setFollowError(err.message || "Could not load stream content"))
        .finally(() => setFollowLoading(false));
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, flow, tab]);

  if (!flow) return null;

  return (
    <Drawer
      open={open}
      onClose={onClose}
      title={`${flow.src_ip}:${flow.src_port ?? "-"} → ${flow.dst_ip}:${flow.dst_port ?? "-"}`}
      description={`${flow.protocol?.toUpperCase()}${flow.app_protocol ? ` · ${flow.app_protocol}` : ""} · ${formatBytes(flow.byte_count)} · ${flow.packet_count} packets`}
      width="xl"
    >
      <div className="mb-3 flex gap-1 border-b border-slate-700">
        {[
          { key: "packets", label: "Packets" },
          { key: "follow", label: "Follow stream" },
        ].map((t) => (
          <button
            key={t.key}
            onClick={() => setTab(t.key)}
            className={`border-b-2 px-3 py-2 text-sm font-medium transition-colors ${
              tab === t.key ? "border-sky-500 text-slate-100" : "border-transparent text-slate-400 hover:text-slate-200"
            }`}
          >
            {t.label}
          </button>
        ))}
      </div>

      {tab === "packets" && (
        <>
          <Table
            columns={[
              { key: "frame_number", header: "#", render: (p) => p.frame_number },
              { key: "ts", header: "Time", render: (p) => absoluteTime(p.ts) },
              { key: "length", header: "Length", render: (p) => `${p.length}B` },
              { key: "protocol", header: "Proto", render: (p) => p.protocol },
              { key: "info", header: "Info", className: "max-w-md truncate", render: (p) => p.info },
            ]}
            rows={packets}
            loading={packetsLoading && packets.length === 0}
            rowKey={(p) => p.frame_number}
            empty={<p className="px-4 py-6 text-center text-xs text-slate-500">No packets captured for this flow.</p>}
          />
          {hasMorePackets && (
            <div className="mt-3 flex justify-center">
              <Button variant="secondary" size="sm" onClick={() => loadPackets(packetOffset + PACKET_LIMIT)} loading={packetsLoading}>
                Load more
              </Button>
            </div>
          )}
        </>
      )}

      {tab === "follow" && (
        <div>
          {followLoading && <p className="text-xs text-slate-500">Loading stream…</p>}
          {followError && <p className="text-xs text-rose-400">{followError}</p>}
          {follow && (
            <>
              {follow.truncated && (
                <div className="mb-2 flex items-center gap-2">
                  <Badge tone="warning">Truncated</Badge>
                  <span className="text-xs text-slate-500">Only part of this stream is shown.</span>
                </div>
              )}
              <pre className="max-h-[60vh] overflow-auto whitespace-pre-wrap break-all rounded-md border border-slate-700 bg-slate-900 p-3 font-mono text-xs text-slate-300">
                {follow.content}
              </pre>
            </>
          )}
        </div>
      )}
    </Drawer>
  );
}
