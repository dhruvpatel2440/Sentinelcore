import { AlertOctagon } from "lucide-react";
import { Component } from "react";

/**
 * Wraps the router so a render crash in any feature module shows a recovery
 * screen instead of a white page. Must stay a class component — React has no
 * hook equivalent for componentDidCatch.
 */
export default class ErrorBoundary extends Component {
  constructor(props) {
    super(props);
    this.state = { error: null };
  }

  static getDerivedStateFromError(error) {
    return { error };
  }

  componentDidCatch(error, info) {
    // eslint-disable-next-line no-console
    console.error("Unhandled render error:", error, info?.componentStack);
  }

  handleReset = () => {
    this.setState({ error: null });
  };

  render() {
    const { error } = this.state;
    if (!error) return this.props.children;

    return (
      <div className="flex min-h-screen items-center justify-center bg-slate-900 px-4">
        <div className="w-full max-w-md rounded-lg border border-slate-800 bg-slate-800/50 p-6 text-center">
          <AlertOctagon size={32} className="mx-auto text-rose-400" aria-hidden="true" />
          <h1 className="mt-3 text-lg font-semibold text-slate-100">Something broke</h1>
          <p className="mt-1 text-sm text-slate-400">
            The interface hit an unexpected error. Your session is still active.
          </p>

          {import.meta.env.DEV && (
            <pre className="mt-4 max-h-40 overflow-auto rounded bg-slate-900 p-3 text-left text-xs text-rose-300">
              {String(error?.stack || error)}
            </pre>
          )}

          <div className="mt-5 flex justify-center gap-2">
            <button
              type="button"
              onClick={this.handleReset}
              className="rounded-md bg-slate-700 px-3.5 py-2 text-sm font-medium text-slate-100 hover:bg-slate-600"
            >
              Try again
            </button>
            <button
              type="button"
              onClick={() => window.location.assign("/")}
              className="rounded-md bg-sky-600 px-3.5 py-2 text-sm font-medium text-white hover:bg-sky-500"
            >
              Back to overview
            </button>
          </div>
        </div>
      </div>
    );
  }
}
