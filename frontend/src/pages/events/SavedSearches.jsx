import { BookmarkPlus, ChevronDown, Globe2, Lock, Trash2 } from "lucide-react";
import { useEffect, useRef, useState } from "react";

import { api } from "../../api/client";
import Button from "../../components/Button";
import Modal from "../../components/Modal";
import { useToast } from "../../components/Toast";

export default function SavedSearches({ currentFilters, onLoad }) {
  const toast = useToast();
  const [searches, setSearches] = useState([]);
  const [open, setOpen] = useState(false);
  const [saveOpen, setSaveOpen] = useState(false);
  const [name, setName] = useState("");
  const [isShared, setIsShared] = useState(false);
  const [saving, setSaving] = useState(false);
  const boxRef = useRef(null);

  const load = () => api.get("/events/searches").then(setSearches).catch(() => {});

  useEffect(() => {
    load();
  }, []);

  useEffect(() => {
    if (!open) return undefined;
    const onClick = (e) => {
      if (boxRef.current && !boxRef.current.contains(e.target)) setOpen(false);
    };
    document.addEventListener("mousedown", onClick);
    return () => document.removeEventListener("mousedown", onClick);
  }, [open]);

  const save = async () => {
    if (!name.trim()) return;
    setSaving(true);
    try {
      await api.post("/events/searches", { name: name.trim(), filters: currentFilters, is_shared: isShared });
      toast.success("Search saved");
      setSaveOpen(false);
      setName("");
      setIsShared(false);
      load();
    } catch (err) {
      toast.error(err.message || "Could not save search");
    } finally {
      setSaving(false);
    }
  };

  const remove = async (id, e) => {
    e.stopPropagation();
    try {
      await api.del(`/events/searches/${id}`);
      setSearches((list) => list.filter((s) => s.id !== id));
    } catch (err) {
      toast.error(err.message || "Could not delete search");
    }
  };

  return (
    <>
      <div className="relative" ref={boxRef}>
        <Button variant="secondary" icon={ChevronDown} onClick={() => setOpen((v) => !v)}>
          Saved searches
        </Button>
        {open && (
          <div className="absolute right-0 z-20 mt-1 w-72 rounded-md border border-slate-700 bg-slate-800 py-1 shadow-xl">
            <button
              onClick={() => {
                setOpen(false);
                setSaveOpen(true);
              }}
              className="flex w-full items-center gap-2 border-b border-slate-700 px-3 py-2 text-left text-xs text-sky-300 hover:bg-slate-700/50"
            >
              <BookmarkPlus size={13} /> Save current search…
            </button>
            {searches.length === 0 && (
              <p className="px-3 py-3 text-xs text-slate-500">No saved searches yet.</p>
            )}
            {searches.map((s) => (
              <button
                key={s.id}
                onClick={() => {
                  onLoad(s.filters);
                  setOpen(false);
                }}
                className="flex w-full items-center justify-between gap-2 px-3 py-2 text-left text-xs hover:bg-slate-700/50"
              >
                <span className="flex min-w-0 items-center gap-1.5">
                  {s.is_shared ? (
                    <Globe2 size={12} className="shrink-0 text-slate-500" />
                  ) : (
                    <Lock size={12} className="shrink-0 text-slate-500" />
                  )}
                  <span className="truncate text-slate-200">{s.name}</span>
                </span>
                {s.is_owner && (
                  <span
                    role="button"
                    tabIndex={-1}
                    onClick={(e) => remove(s.id, e)}
                    aria-label={`Delete ${s.name}`}
                    className="shrink-0 rounded p-1 text-slate-500 hover:bg-slate-600 hover:text-rose-300"
                  >
                    <Trash2 size={12} />
                  </span>
                )}
              </button>
            ))}
          </div>
        )}
      </div>

      <Modal
        open={saveOpen}
        onClose={() => setSaveOpen(false)}
        title="Save current search"
        size="sm"
        footer={
          <>
            <Button variant="ghost" onClick={() => setSaveOpen(false)}>
              Cancel
            </Button>
            <Button onClick={save} loading={saving} disabled={!name.trim()}>
              Save
            </Button>
          </>
        }
      >
        <label htmlFor="saved-search-name" className="block text-xs font-medium text-slate-300">
          Name
        </label>
        <input
          id="saved-search-name"
          autoFocus
          value={name}
          onChange={(e) => setName(e.target.value)}
          className="mt-1 w-full rounded-md border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-100 focus:border-sky-500 focus:outline-none focus:ring-1 focus:ring-sky-500"
        />
        <label className="mt-3 flex items-center gap-2 text-xs text-slate-400">
          <input
            type="checkbox"
            checked={isShared}
            onChange={(e) => setIsShared(e.target.checked)}
            className="rounded border-slate-600 bg-slate-900 text-sky-500 focus:ring-sky-500"
          />
          Share with all analysts
        </label>
      </Modal>
    </>
  );
}
