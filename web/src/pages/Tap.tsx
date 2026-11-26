// Live Tap: requests matching a filter as proxies finish them. Proxies
// filter and sample; only matches reach the console.
import { useEffect, useRef, useState, type FormEvent } from "react";
import { useApp } from "../app/context";
import { Card, Empty, ErrorBanner, Field, PageHeader, Status, type Tone } from "../components/ui";
import { refName, useList, useRefs } from "./Resources";

interface TapEvent {
  time: string;
  node: string;
  site: string;
  route?: string;
  client: string;
  method: string;
  host: string;
  uri: string;
  protocol: string;
  status: number;
  durationMs: number;
  upstream?: string;
  upstreamStatus?: number;
  bytesSent: number;
  headers?: Record<string, string>;
}

// Rows kept on screen; older ones scroll off.
const KEEP = 500;

function statusTone(s: number): Tone {
  if (s >= 500) return "danger";
  if (s >= 400) return "warning";
  return s >= 200 && s < 400 ? "success" : "";
}

export function Tap() {
  const app = useApp();
  const sites = useList("sites", "");
  const refs = useRefs("");
  const [f, setF] = useState({ site: "", route: "", cidr: "", sample: "1", headers: "user-agent" });
  const [events, setEvents] = useState<TapEvent[]>([]);
  const [running, setRunning] = useState(false);
  const [dropped, setDropped] = useState(0);
  const [err, setErr] = useState<unknown>(null);
  const [open, setOpen] = useState<TapEvent | null>(null);
  const src = useRef<EventSource | null>(null);
  // Whether the current stream opened, to tell a refused filter apart
  // from a dropped connection that EventSource retries.
  const opened = useRef(false);

  const stop = () => {
    src.current?.close();
    src.current = null;
    setRunning(false);
  };
  useEffect(() => stop, []);

  const start = (e: FormEvent) => {
    e.preventDefault();
    stop();
    setErr(null);
    setDropped(0);
    const q = new URLSearchParams();
    if (f.site) q.append("site", f.site);
    if (f.route) q.append("route", f.route);
    for (const c of f.cidr.split(/[\s,]+/).filter(Boolean)) q.append("cidr", c);
    if (f.sample && f.sample !== "1") q.set("sample", f.sample);
    for (const h of f.headers.split(/[\s,]+/).filter(Boolean)) q.append("header", h.toLowerCase());
    const es = new EventSource(`/api/v1/tap?${q}`, { withCredentials: true });
    src.current = es;
    opened.current = false;
    setRunning(true);
    es.onopen = () => { opened.current = true; };
    es.addEventListener("request", (m) => {
      const ev = JSON.parse((m as MessageEvent<string>).data) as TapEvent;
      setEvents((xs) => [ev, ...xs].slice(0, KEEP));
    });
    es.addEventListener("dropped", (m) => {
      const d = JSON.parse((m as MessageEvent<string>).data) as { count: number };
      setDropped((n) => n + d.count);
    });
    es.addEventListener("end", () => stop());
    es.onerror = () => {
      // EventSource retries a dropped stream on its own; one that never
      // opened was refused (filter or access).
      if (es.readyState === EventSource.CLOSED || !opened.current) {
        setErr(new Error("The tap was refused or closed. Check the filter and your access to the site."));
        stop();
      }
    };
  };

  const siteItems = sites.data?.items ?? [];
  const routeIDs = (siteItems.find((s) => s.id === f.site)?.spec as { routes?: string[] } | undefined)?.routes ?? [];
  const name = (kind: "sites" | "routes", id?: string) => (id ? refName(refs.data, kind, id) ?? id : "");

  return (
    <div className="stack">
      <PageHeader title="Live Tap" sub="Requests as the proxies finish them. Proxies filter and sample, so only matching requests leave them; bodies are never captured." />
      <form className="card" onSubmit={start}>
        <div className="card__body stack">
          <div className="grid grid--2">
            <Field id="tap-s" label="Site" hint={app.can("viewer") ? "Empty: every site." : "Required: you can read only some sites."}>
              <select id="tap-s" className="input" value={f.site} onChange={(e) => setF({ ...f, site: e.target.value, route: "" })}>
                <option value="">Any site</option>
                {siteItems.map((s) => <option key={s.id} value={s.id}>{s.name}</option>)}
              </select>
            </Field>
            <Field id="tap-r" label="Route">
              <select id="tap-r" className="input" value={f.route} disabled={!f.site} onChange={(e) => setF({ ...f, route: e.target.value })}>
                <option value="">Any route</option>
                {routeIDs.map((id) => <option key={id} value={id}>{name("routes", id)}</option>)}
              </select>
            </Field>
            <Field id="tap-c" label="Client addresses" hint="CIDRs, comma-separated. Empty: any.">
              <input id="tap-c" className="input mono" value={f.cidr} onChange={(e) => setF({ ...f, cidr: e.target.value })} placeholder="203.0.113.0/24" />
            </Field>
            <Field id="tap-n" label="Sample" hint="Show one in N matching requests.">
              <input id="tap-n" className="input" type="number" min={1} value={f.sample} onChange={(e) => setF({ ...f, sample: e.target.value })} />
            </Field>
            <Field id="tap-h" label="Request headers to show" hint="Credentials (Authorization, Cookie) are never shown.">
              <input id="tap-h" className="input mono" value={f.headers} onChange={(e) => setF({ ...f, headers: e.target.value })} placeholder="user-agent, x-request-id" />
            </Field>
          </div>
          <div className="row row--between">
            <div className="row small">
              {running ? <Status tone="success">Tapping</Status> : <Status tone="">Stopped</Status>}
              <span className="muted">{events.length} shown{dropped > 0 && `, ${dropped} left out by rate limits`}</span>
            </div>
            <div className="row">
              <button type="button" className="btn" disabled={!events.length} onClick={() => { setEvents([]); setOpen(null); }}>Clear</button>
              {running
                ? <button type="button" className="btn btn--destructive" onClick={stop}>Stop</button>
                : <button className="btn btn--primary">Start</button>}
            </div>
          </div>
        </div>
      </form>
      <ErrorBanner error={err} />
      {events.length === 0 ? (
        <Empty title={running ? "Waiting for requests" : "Not tapping"} text={running ? "Matching requests appear here as they finish." : "Choose a filter and start."} />
      ) : (
        <Card flush>
          <div className="data-table-wrap">
            <table className="data-table">
              <thead><tr><th>Time</th><th>Status</th><th>Method</th><th>Host and URI</th><th>Route</th><th>Upstream</th><th>Duration</th><th>Client</th></tr></thead>
              <tbody>
                {events.map((e, i) => (
                  <tr key={`${e.time}-${i}`} className="clickable" onClick={() => setOpen(e)}>
                    <td className="mono nowrap small">{e.time.slice(11, 23)}</td>
                    <td><Status tone={statusTone(e.status)}>{e.status}</Status></td>
                    <td className="mono">{e.method}</td>
                    <td className="mono small ellipsis">{e.host}{e.uri}</td>
                    <td className="small">{name("routes", e.route)}</td>
                    <td className="mono small">{e.upstream ? `${e.upstream}${e.upstreamStatus ? ` → ${e.upstreamStatus}` : ""}` : ""}</td>
                    <td className="mono small nowrap">{e.durationMs.toFixed(1)} ms</td>
                    <td className="mono small">{e.client}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      )}
      {open && (
        <Card title={`${open.method} ${open.uri}`} actions={<button className="btn btn--sm" onClick={() => setOpen(null)}>Close</button>}>
          <table className="data-table">
            <tbody>
              {([
                ["Time", open.time], ["Node", open.node], ["Site", name("sites", open.site)], ["Route", name("routes", open.route)],
                ["Host", open.host], ["Protocol", `HTTP/${open.protocol}`], ["Client", open.client], ["Status", String(open.status)],
                ["Upstream", open.upstream], ["Upstream status", open.upstreamStatus ? String(open.upstreamStatus) : ""],
                ["Duration", `${open.durationMs.toFixed(3)} ms`], ["Bytes sent", String(open.bytesSent)],
                ...Object.entries(open.headers ?? {}).map(([k, v]) => [k, v]),
              ] as [string, string | undefined][]).filter(([, v]) => v).map(([k, v]) => (
                <tr key={k}><th scope="row">{k}</th><td className="mono break">{v}</td></tr>
              ))}
            </tbody>
          </table>
        </Card>
      )}
    </div>
  );
}
