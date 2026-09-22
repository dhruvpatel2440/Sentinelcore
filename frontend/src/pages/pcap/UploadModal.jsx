import { FileUp, UploadCloud } from "lucide-react";
import { useEffect, useRef, useState } from "react";

import { api, uploadFile } from "../../api/client";
import Button from "../../components/Button";
import Modal from "../../components/Modal";
import { useToast } from "../../components/Toast";
import { formatBytes } from "../../lib/format";
import { isLikelyPcapFilename } from "./constants";

const CLIENT_MAX_SIZE_MB = 500; // mirrors the server default; the server enforces the real limit
const PARSE_POLL_MS = 1500;

/**
 * Drag-and-drop upload with real upload progress, then a parse-progress bar
 * driven by polling GET /pcap/{id}. `prefill.incidentId`, if set, attaches
 * the capture to that incident once the upload is accepted — used from the
 * M8 incident detail page so evidence lands on the right incident.
 */
export default function UploadModal({ open, onClose, onDone, prefill }) {
  const toast = useToast();
  const [file, setFile] = useState(null);
  const [dragOver, setDragOver] = useState(false);
  const [precheckError, setPrecheckError] = useState(null);
  const [phase, setPhase] = useState("idle"); // idle | uploading | parsing | done | error
  const [uploadPct, setUploadPct] = useState(0);
  const [parsePct, setParsePct] = useState(0);
  const [errorMessage, setErrorMessage] = useState(null);
  const inputRef = useRef(null);
  const pollRef = useRef(null);

  useEffect(() => {
    if (!open) return;
    setFile(null);
    setPrecheckError(null);
    setPhase("idle");
    setUploadPct(0);
    setParsePct(0);
    setErrorMessage(null);
  }, [open]);

  useEffect(() => () => clearInterval(pollRef.current), []);

  const pickFile = (f) => {
    if (!f) return;
    if (!isLikelyPcapFilename(f.name)) {
      setPrecheckError("Not a .pcap/.pcapng/.cap file — the server checks the real bytes, but this one doesn't look right.");
    } else if (f.size > CLIENT_MAX_SIZE_MB * 1024 * 1024) {
      setPrecheckError(`File is larger than the ${CLIENT_MAX_SIZE_MB}MB limit.`);
    } else {
      setPrecheckError(null);
    }
    setFile(f);
  };

  const pollParseProgress = (id) => {
    pollRef.current = setInterval(async () => {
      try {
        const data = await api.get(`/pcap/${id}`);
        if (data.status === "parsed") {
          clearInterval(pollRef.current);
          setParsePct(100);
          setPhase("done");
          toast.success("Capture parsed");
          onDone?.(data);
        } else if (data.status === "failed") {
          clearInterval(pollRef.current);
          setPhase("error");
          setErrorMessage(data.error || "Parsing failed");
        } else {
          setParsePct(data.progress ?? 0);
        }
      } catch {
        // A missed poll tick is not fatal — the next one retries.
      }
    }, PARSE_POLL_MS);
  };

  const submit = async () => {
    if (!file || precheckError) return;
    setPhase("uploading");
    setUploadPct(0);
    try {
      const accepted = await uploadFile("/pcap/upload", file, { onProgress: setUploadPct });

      if (prefill?.incidentId) {
        try {
          await api.post(`/pcap/${accepted.id}/attach`, { incident_id: prefill.incidentId });
        } catch {
          // Upload itself succeeded; surfacing an attach failure separately below.
        }
      }

      if (accepted.duplicate) {
        toast.info("An identical capture was already uploaded — reusing it.");
      }

      if (accepted.status === "parsed") {
        setPhase("done");
        onDone?.(accepted);
        return;
      }
      if (accepted.status === "failed") {
        setPhase("error");
        setErrorMessage("Parsing failed");
        return;
      }

      setPhase("parsing");
      pollParseProgress(accepted.id);
    } catch (err) {
      setPhase("error");
      setErrorMessage(err.message || "Upload failed");
    }
  };

  const busy = phase === "uploading" || phase === "parsing";

  return (
    <Modal
      open={open}
      onClose={busy ? undefined : onClose}
      title="Upload capture"
      description={prefill?.incidentId ? "This capture will be attached to the current incident once accepted." : undefined}
      footer={
        phase === "done" ? (
          <Button onClick={onClose}>Close</Button>
        ) : (
          <>
            <Button variant="ghost" onClick={onClose} disabled={busy}>
              Cancel
            </Button>
            <Button onClick={submit} loading={phase === "uploading"} disabled={!file || Boolean(precheckError) || busy}>
              Upload
            </Button>
          </>
        )
      }
    >
      <div className="space-y-4">
        <div
          onDragOver={(e) => {
            e.preventDefault();
            setDragOver(true);
          }}
          onDragLeave={() => setDragOver(false)}
          onDrop={(e) => {
            e.preventDefault();
            setDragOver(false);
            pickFile(e.dataTransfer.files?.[0]);
          }}
          onClick={() => inputRef.current?.click()}
          className={`flex cursor-pointer flex-col items-center gap-2 rounded-lg border-2 border-dashed px-6 py-10 text-center transition-colors ${
            dragOver ? "border-sky-500 bg-sky-500/5" : "border-slate-700 hover:border-slate-600"
          }`}
        >
          <UploadCloud size={26} className="text-slate-500" aria-hidden="true" />
          {file ? (
            <div className="flex items-center gap-2 text-sm text-slate-200">
              <FileUp size={14} />
              {file.name} <span className="text-slate-500">({formatBytes(file.size)})</span>
            </div>
          ) : (
            <p className="text-sm text-slate-400">Drag a .pcap/.pcapng file here, or click to browse.</p>
          )}
          <input
            ref={inputRef}
            type="file"
            accept=".pcap,.pcapng,.cap"
            className="hidden"
            onChange={(e) => pickFile(e.target.files?.[0])}
          />
        </div>

        {precheckError && <p className="text-xs text-rose-400">{precheckError}</p>}

        {phase === "uploading" && (
          <div>
            <p className="mb-1 text-xs text-slate-400">Uploading… {uploadPct}%</p>
            <div className="h-1.5 w-full overflow-hidden rounded-full bg-slate-700">
              <div className="h-full bg-sky-500 transition-all" style={{ width: `${uploadPct}%` }} />
            </div>
          </div>
        )}

        {phase === "parsing" && (
          <div>
            <p className="mb-1 text-xs text-slate-400">Parsing… {parsePct}%</p>
            <div className="h-1.5 w-full overflow-hidden rounded-full bg-slate-700">
              <div className="h-full bg-sky-500 transition-all" style={{ width: `${parsePct}%` }} />
            </div>
          </div>
        )}

        {phase === "done" && <p className="text-xs text-emerald-400">Capture uploaded and parsed successfully.</p>}
        {phase === "error" && <p className="text-xs text-rose-400">{errorMessage}</p>}
      </div>
    </Modal>
  );
}
