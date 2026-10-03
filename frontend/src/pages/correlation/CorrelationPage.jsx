import { useState } from "react";

import PageHeader from "../../components/PageHeader";
import CandidatesTab from "./CandidatesTab";
import RulesTab from "./RulesTab";

const TABS = [
  { key: "rules", label: "Rules" },
  { key: "candidates", label: "Candidates" },
];

export default function CorrelationPage() {
  const [tab, setTab] = useState("rules");

  return (
    <>
      <PageHeader
        title="Correlation"
        description="Rules that turn a stream of alerts into a small number of meaningful findings."
      />

      <div className="mb-4 flex gap-1 border-b border-slate-800">
        {TABS.map((t) => (
          <button
            key={t.key}
            onClick={() => setTab(t.key)}
            className={`border-b-2 px-3 py-2 text-sm font-medium transition-colors ${
              tab === t.key
                ? "border-sky-500 text-slate-100"
                : "border-transparent text-slate-400 hover:text-slate-200"
            }`}
          >
            {t.label}
          </button>
        ))}
      </div>

      {tab === "rules" ? <RulesTab /> : <CandidatesTab />}
    </>
  );
}
