import { UploadCloud } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";

import { api, uploadFile } from "../../api/client";
import Button from "../../components/Button";
import Modal from "../../components/Modal";
import { useToast } from "../../components/Toast";
import { formatBytes } from "../../lib/format";
import { isLikelyPcapFilename } from "./constants";

const SIZE_WARNING_BYTES = 500 * 1024 * 1024; // 500MB — server enforces the real cap.

/**
 * Upload flow: pick/drop a file, client-side pre-check (extension + size
 * warning only — the backend is the real gate on both), then upload via XHR
 * for real progress. On success, optionally attach to `incidentId` and
 * redirect into the new capture's detail page.
 */
export default function PcapUploadModal({ open, onClose, onUploaded, incidentId }) {
  const toast = useToast();
  const navigate = useNavigate();
  const [file, setFile] = useState(null);
  const [dragOver, setDragOver] = useState(false);
  const [warning, setWarning] = useState(null);
  const [progress, setProgress] = useState(null);
  const [uploading, setUploading] = useState(false);
  const [error, setError] = useState(null);
  const [done, setDone] = useState(false);
  const inputRef = useRef(null);
  const abortRef = useRef(null);

  useEffect(() => {
    if (!open) return;
    setFile(null);
    setWarning(null);
    setProgress(null);
    setUploading(false);
    setError(null);
    setDone(false);
  }, [open]);

  const pickFile = (f) => {
    if (!f) return;
    setFile(f);
    setError(null);
    const warnings = [];
    if (!isLikelyPcapFilename(f.name)) {
      warnings.push("This doesn't look like a .pcap/.pcapng/.cap file — the server will reject it if it isn't one.");
    }
    if (f.size > SIZE_WARNING_BYTES) {
      warnings.push(`This is a large capture (${formatBytes(f.size)}) — upload and parsing may take a while.`);
    }
    setWarning(warnings.length ? warnings.join(" ") : null);
  };

  const submit = async () => {
    if (!file) return;
    setUploading(true);
    setProgress(0);
    setError(null);
    const controller = new AbortController();
    abortRef.current = controller;
    try {
      const result = await uploadFile("/pcap/upload", file, {
        onProgress: setProgress,
        signal: controller.signal,
      });
      if (result.duplicate) {
        toast.info("This capture was already uploaded — showing the existing record.");
      } else {
        toast.success("Upload accepted — queued for parsing");
      }
      if (incidentId) {
        try {
          await api.post(`/pcap/${result.id}/attach`, { incident_id: incidentId });
        } catch (err) {
          toast.error(err.message || "Uploaded, but could not attach to the incident");
        }
      }
      setDone(true);
      onUploaded?.(result);
      onClose();
      navigate(`/pcap/${result.id}`);
    } catch (err) {
      setError(err.message || "Upload failed");
    } finally {
      setUploading(false);
    }
  };

  return (
    <Modal
      open={open}
      onClose={uploading ? undefined : onClose}
      title="Upload PCAP"
      description={incidentId ? "The capture will be attached to this incident once uploaded." : undefined}
      footer={
        <>
          <Button variant="ghost" onClick={onClose} disabled={uploading}>
            Cancel
          </Button>
          <Button onClick={submit} loading={uploading} disabled={!file || done}>
            Upload
          </Button>
        </>
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
          className={`flex cursor-pointer flex-col items-center gap-2 rounded-lg border-2 border-dashed px-4 py-8 text-center transition-colors ${
            dragOver ? "border-sky-500 bg-sky-500/5" : "border-slate-700 hover:border-slate-600"
          }`}
        >
          <UploadCloud size={24} className="text-slate-500" aria-hidden="true" />
          {file ? (
            <p className="text-sm text-slate-200">
              {file.name} <span className="text-slate-500">({formatBytes(file.size)})</span>
            </p>
          ) : (
            <p className="text-sm text-slate-400">Drag a .pcap/.pcapng/.cap file here, or click to browse.</p>
          )}
          <input
            ref={inputRef}
            type="file"
            accept=".pcap,.pcapng,.cap"
            className="hidden"
            onChange={(e) => pickFile(e.target.files?.[0])}
          />
        </div>

        {warning && <p className="text-xs text-amber-300">{warning}</p>}

        {progress != null && (
          <div>
            <div className="h-1.5 w-full overflow-hidden rounded-full bg-slate-700">
              <div className="h-full bg-sky-500 transition-all" style={{ width: `${progress}%` }} />
            </div>
            <p className="mt-1 text-xs text-slate-500">{progress}%</p>
          </div>
        )}

        {error && <p className="text-xs text-rose-400">{error}</p>}
      </div>
    </Modal>
  );
}
