import { useEffect, useState } from "react";

function App() {
  const [apiStatus, setApiStatus] = useState("checking...");

  useEffect(() => {
    fetch("/api/health")
      .then((res) => res.json())
      .then((data) => setApiStatus(data.status))
      .catch(() => setApiStatus("unreachable"));
  }, []);

  return (
    <div className="min-h-screen bg-slate-900 text-slate-100 flex items-center justify-center">
      <div className="text-center space-y-2">
        <h1 className="text-3xl font-bold">SentinelCore</h1>
        <p className="text-slate-400">API status: {apiStatus}</p>
      </div>
    </div>
  );
}

export default App;
