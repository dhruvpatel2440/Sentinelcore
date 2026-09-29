import { Construction } from "lucide-react";

import Card from "../components/Card";
import PageHeader from "../components/PageHeader";

/**
 * Stand-in for a feature module not yet built, so the shell is navigable end
 * to end from day one. Each of these is replaced by its milestone.
 */
export default function Placeholder({ title, description, milestone, capabilities = [] }) {
  return (
    <>
      <PageHeader title={title} description={description} />
      <Card>
        <div className="flex flex-col items-center gap-3 py-10 text-center">
          <Construction size={28} className="text-slate-600" aria-hidden="true" />
          <p className="text-sm font-medium text-slate-300">Coming in {milestone}</p>
          {capabilities.length > 0 && (
            <ul className="mt-1 space-y-1 text-xs text-slate-500">
              {capabilities.map((c) => (
                <li key={c}>{c}</li>
              ))}
            </ul>
          )}
        </div>
      </Card>
    </>
  );
}
