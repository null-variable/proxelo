// Route Simulator: one request through the serving engine,
// against the latest revision and, side by side, the active change set.
import { useEffect, useState, type FormEvent } from "react";
import { api } from "../api/client";
import type { Header, SimRun } from "../api/types";
import { useApp } from "../app/context";
import { Card, ErrorBanner, Field, PageHeader } from "../components/ui";
import { useList } from "./Resources";

const METHODS = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"];

interface Req {
  listener: string;
  method: string;
  target: string;
  host: string;
  headers: string;
  remote: string;
  tls: boolean;
}

export function Simulator() {
  const app = useApp();
  const listeners = useList("listeners", app.changeset);
  const [req, setReq] = useState<Req>({ listener: "", method: "GET", target: "/", host: "example.com", headers: "", remote: "192.0.2.1", tls: false });
  const [compare, setCompare] = useState(true);
  const [out, setOut] = useState<SimRun[] | null>(null);
  const [err, setErr] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const ls = listeners.data?.items ?? [];

  useEffect(() => {
    const first = ls[0];
    if (!req.listener && first) setReq((r) => ({ ...r, listener: first.id }));
  }, [ls, req.listener]);

  const set = <K extends keyof Req>(k: K, v: Req[K]) => setReq((r) => ({ ...r, [k]: v }));

  const run = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setErr(null);
    const headers: Header[] = [{ name: "host", value: req.host }];
    for (const line of req.headers.split("\n")) {
      const i = line.indexOf(":");
      if (i > 0) headers.push({ name: line.slice(0, i).trim(), value: line.slice(i + 1).trim() });
    }
    try {
      const r = await api.post<{ items: SimRun[] }>("/simulate", {
        changeset: compare ? app.changeset : "",
        requests: [{ listener: req.listener, method: req.method, target: req.target, headers, remoteAddr: req.remote, tls: req.tls }],
      });
      setOut(r.items);
    } catch (e2) {
      setErr(e2);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="stack">
      <PageHeader title="Simulator" sub="Runs a request through the same routing engine the proxy serves with, without sending traffic." />
      <form className="card" onSubmit={run}>
        <div className="card__body stack">
          <div className="grid grid--2">
            <Field id="sim-l" label="Listener">
              <select id="sim-l" className="input" value={req.listener} onChange={(e) => set("listener", e.target.value)}>
                {ls.map((l) => <option key={l.id} value={l.id}>{l.name} ({l.spec.address})</option>)}
              </select>
            </Field>
            <Field id="sim-h" label="Host">
              <input id="sim-h" className="input" value={req.host} onChange={(e) => set("host", e.target.value)} />
            </Field>
            <Field id="sim-m" label="Method">
              <select id="sim-m" className="input" value={req.method} onChange={(e) => set("method", e.target.value)}>
                {METHODS.map((m) => <option key={m} value={m}>{m}</option>)}
              </select>
            </Field>
            <Field id="sim-t" label="Path and query">
              <input id="sim-t" className="input mono" value={req.target} onChange={(e) => set("target", e.target.value)} />
            </Field>
            <Field id="sim-r" label="Client address">
              <input id="sim-r" className="input mono" value={req.remote} onChange={(e) => set("remote", e.target.value)} />
            </Field>
            <Field id="sim-hd" label="Extra headers" hint="One per line: Name: value">
              <textarea id="sim-hd" className="code code--sm" value={req.headers} onChange={(e) => set("headers", e.target.value)} placeholder="User-Agent: curl/8.0" />
            </Field>
          </div>
          <div className="row row--between">
            <div className="row">
              <label className="row small"><input type="checkbox" checked={req.tls} onChange={(e) => set("tls", e.target.checked)} /> Over TLS</label>
              {app.changeset && (
                <label className="row small">
                  <input type="checkbox" checked={compare} onChange={(e) => setCompare(e.target.checked)} /> Compare with change set <span className="mono">{app.changeset}</span>
                </label>
              )}
            </div>
            <button className="btn btn--primary" disabled={busy || !req.listener}>Simulate</button>
          </div>
        </div>
      </form>
      {ls.length === 0 && !listeners.isPending && <div className="banner banner--warning" role="status">No listeners yet. Create one before simulating.</div>}
      <ErrorBanner error={err} />
      {out && <div className={out.length > 1 ? "grid grid--2" : "stack"}>{out.map((o, i) => <SimResultCard key={i} run={o} />)}</div>}
    </div>
  );
}

function Headers({ title, items }: { title: string; items?: Header[] }) {
  if (!items?.length) return null;
  return (
    <div>
      <div className="field__label">{title}</div>
      <pre className="code">{items.map((h) => `${h.name}: ${h.value}`).join("\n")}</pre>
    </div>
  );
}

function SimResultCard({ run }: { run: SimRun }) {
  const r = run.results[0] ?? {};
  const kind = (r.kind ?? "").replace("KIND_", "").toLowerCase();
  const rows: [string, string | undefined][] = [
    ["Site", r.site], ["Route", r.route], ["URI", r.uri], ["Location", r.location], ["Upstream", r.upstream],
    ["Targets", r.targets?.join(", ")], ["File", r.file], ["Body", r.body],
  ];
  return (
    <Card title={run.changeset ? <>Change set <span className="mono">{run.changeset}</span></> : `Revision ${run.revision}`}>
      {run.error ? <ErrorBanner error={new Error(run.error)} /> : (
        <div className="stack">
          <div className="row">
            <span className="stat__value">{r.status ?? "–"}</span>
            <span className="badge badge--outline">{kind}</span>
          </div>
          <table className="data-table">
            <tbody>
              {rows.filter(([, v]) => v).map(([k, v]) => (
                <tr key={k}><th scope="row">{k}</th><td className="mono break">{v}</td></tr>
              ))}
            </tbody>
          </table>
          {r.trace && r.trace.length > 0 && (
            <div>
              <div className="field__label">Trace</div>
              <ol className="mono small stack" style={{ gap: 4 }}>{r.trace.map((t, i) => <li key={i}>{t}</li>)}</ol>
            </div>
          )}
          <Headers title="Response headers" items={r.responseHeaders} />
          <Headers title="Upstream request headers" items={r.requestHeaders} />
        </div>
      )}
    </Card>
  );
}
