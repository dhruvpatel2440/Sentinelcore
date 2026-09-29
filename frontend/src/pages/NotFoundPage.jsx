import { FileQuestion } from "lucide-react";
import { Link } from "react-router-dom";

export default function NotFoundPage() {
  return (
    <div className="flex min-h-[60vh] items-center justify-center">
      <div className="max-w-md text-center">
        <FileQuestion size={32} className="mx-auto text-slate-600" aria-hidden="true" />
        <h1 className="mt-3 text-lg font-semibold text-slate-100">Page not found</h1>
        <p className="mt-1 text-sm text-slate-400">
          That route does not exist in SentinelCore.
        </p>
        <Link
          to="/"
          className="mt-5 inline-block rounded-md bg-sky-600 px-3.5 py-2 text-sm font-medium text-white hover:bg-sky-500"
        >
          Back to overview
        </Link>
      </div>
    </div>
  );
}
