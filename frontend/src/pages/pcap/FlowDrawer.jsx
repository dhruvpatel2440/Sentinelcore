import { useEffect, useState } from "react";

import { api } from "../../api/client";
import Button from "../../components/Button";
import Drawer from "../../components/Drawer";
import Spinner from "../../components/Spinner";
import Table from "../../components/Table";
import { useToast } from "../../components/Toast";
import { absoluteTime, formatBytes } from "../../lib/format";

function toHex(text) {
  let out = "";
  for (let i = 0; i < text.length; i += 1) {
    out += text.charCodeAt(i).toString(16).padStart(2, "0");
    out += i % 16 === 15 ? "\n" : " ";
  }
  return out;
}

/**
 * Packet list + reassembled stream content for one flow. Follow-stream
 * content is attacker-controlled — rendered as a plain text node inside
 * <pre>, never dangerouslySetInnerHTML, so a payload like `<script>` shows
 * up as literal text rather than executing.
 */
export default function FlowDrawer({ pcapId, flow, open, onClose }) {
  const toast = useToast();
  const [tab, setTab] = useState("packets");
  const [packets, setPackets] = useState([]);
  const [loadingPackets, setLoadingPackets] = useState(false);
  const [follow, setFollow] = useState(null);
  const [loadingFollow, setLoadingFollow] = useState(false);
  const [viewMode, setViewMode] = useState("ascii"); // "ascii" | "hex"

  useEffect(() => {
    if (!open || !flow) return;
    setTab("packets");
    setPackets([]);
    setFollow(null);
    setViewMode("ascii");
  }, [open, flow]);

  useEffect(() => {
    if (!open || !flow || tab !== "packets" || packets.length > 0) return;
    setLoadingPackets(true);
    api
      .get(`/pcap/${pcapId}/flows/${flow.id}/packets?limit=500`)
      .then(setPackets)
      .catch((err) => toast.error(err.message || "Could not load packets"))
      .finally(() => setLoadingPackets(false));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, flow, tab]);

  useEffect(() => {
    if (!open || !flow || tab !== "follow" || follow) return;
    setLoadingFollow(true);
    api
      .get(`/pcap/${pcapId}/flows/${flow.id}/follow`)
      .then(setFollow)
      .catch((err) => toast.error(err.message || "Could not reassemble stream"))
      .finally(() => setLoadingFollow(false));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, flow, tab]);

  if (!flow) return null;

  return (
    <Drawer
      open={open}
      onClose={onClose}
      title={`${flow.src_ip}${flow.src_port ? `:${flow.src_port}` : ""} → ${flow.dst_ip}${flow.dst_port ? `:${flow.dst_port}` : ""}`}
      description={`${flow.protocol.toUpperCase()} stream #${flow.stream_id} · ${flow.packet_count} packets · ${formatBytes(flow.byte_count)}`}
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
        <Table
          columns={[
            { key: "frame_number", header: "#" },
            { key: "ts", header: "Time", render: (p) => absoluteTime(p.ts ? p.ts * 1000 : null) },
            { key: "length", header: "Len" },
            { key: "protocol", header: "Proto" },
            { key: "info", header: "Info", className: "max-w-md truncate", render: (p) => p.info },
          ]}
          rows={packets}
          loading={loadingPackets}
          rowKey={(p) => p.frame_number}
          empty={<p className="px-4 py-6 text-center text-xs text-slate-500">No packets returned for this stream.</p>}
        />
      )}

      {tab === "follow" && (
        <div>
          {loadingFollow && (
            <div className="flex justify-center py-8">
              <Spinner />
            </div>
          )}
          {!loadingFollow && follow && (
            <>
              <div className="mb-2 flex items-center justify-between">
                <div className="flex gap-1">
                  <Button size="sm" variant={viewMode === "ascii" ? "primary" : "secondary"} onClick={() => setViewMode("ascii")}>
                    ASCII
                  </Button>
                  <Button size="sm" variant={viewMode === "hex" ? "primary" : "secondary"} onClick={() => setViewMode("hex")}>
                    Hex
                  </Button>
                </div>
                {follow.truncated && <span className="text-xs text-amber-400">Truncated — showing a size-capped prefix.</span>}
              </div>
              <pre className="max-h-[28rem] overflow-auto whitespace-pre-wrap break-all rounded-md border border-slate-700 bg-slate-950 p-3 font-mono text-xs text-slate-300">
                {viewMode === "ascii" ? follow.content : toHex(follow.content)}
              </pre>
            </>
          )}
          {!loadingFollow && !follow && <p className="text-xs text-slate-500">No stream content.</p>}
        </div>
      )}
    </Drawer>
  );
}
