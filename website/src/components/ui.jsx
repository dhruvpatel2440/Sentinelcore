import { useEffect } from "react";

export function usePageTitle(title) {
  useEffect(() => {
    document.title = title ? `${title} | SentinelCore` : "SentinelCore: network detection and incident response you run yourself";
  }, [title]);
}

export function PageHead({ title, children, label }) {
  usePageTitle(title);
  return (
    <div className="page-head container">
      {label && <p className="label">{label}</p>}
      <h1>{title}</h1>
      {children && <p>{children}</p>}
    </div>
  );
}

export function Severity({ level }) {
  return <span className={`badge badge--${level}`}>{level}</span>;
}

export function BrowserFrame({ url = "https://localhost", children, caption }) {
  return (
    <figure style={{ margin: 0 }}>
      <div className="browser">
        <div className="browser__bar" aria-hidden="true">
          <span className="browser__dot" style={{ background: "var(--critical)" }} />
          <span className="browser__dot" style={{ background: "var(--medium)" }} />
          <span className="browser__dot" style={{ background: "var(--mint)" }} />
          <span className="browser__url">{url}</span>
        </div>
        <div className="browser__body">{children}</div>
      </div>
      {caption && <figcaption className="caption">{caption}</figcaption>}
    </figure>
  );
}

/*
 * Real screenshots go in src/assets/screens/<name>.png (or .webp/.jpg).
 * Until one exists for a name, the illustration passed as `fallback` renders
 * instead and is labelled as an illustration.
 */
const shots = import.meta.glob("../assets/screens/*.{png,webp,jpg,jpeg}", {
  eager: true,
  query: "?url",
  import: "default",
});

export function Screenshot({ name, alt, url, fallback, caption }) {
  const match = Object.entries(shots).find(([path]) => path.split("/").pop().replace(/\.[a-z]+$/i, "") === name);
  return (
    <BrowserFrame url={url} caption={match ? caption : `Illustration with sample data. ${caption ?? ""}`}>
      {match ? <img src={match[1]} alt={alt} loading="lazy" width="1200" height="720" /> : fallback}
    </BrowserFrame>
  );
}

export function CodeBlock({ title, children, label }) {
  return (
    <div className="terminal" role="group" aria-label={label ?? title ?? "Terminal"}>
      <div className="terminal__bar" aria-hidden="true">
        <span className="browser__dot" style={{ background: "var(--critical)" }} />
        <span className="browser__dot" style={{ background: "var(--medium)" }} />
        <span className="browser__dot" style={{ background: "var(--mint)" }} />
        {title && <span className="terminal__title">{title}</span>}
      </div>
      <pre tabIndex={0}>{children}</pre>
    </div>
  );
}
