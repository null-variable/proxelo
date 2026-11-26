import { Link } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { api } from "../api/client";
import type { Items, NodeStatus, Resource, Revision, Traffic } from "../api/types";
import { useApp } from "../app/context";
import { Card, Empty, ErrorBanner, Loading, PageHeader, Status, timeAgo } from "../components/ui";
import { PendingBanner, RevisionTable } from "./Changes";

const WINDOW_SECONDS = 300;
const DAY = 86400e3;

function pct(a: number, b: number): string {
  return b ? ((a / b) * 100).toFixed(2) + "%" : "–";
}

function Stat({ label, value, sub, danger }: { label: string; value: string; sub?: string; danger?: boolean }) {
  return (
    <div className="card">
      <div className="card__body">
        <div className="stat__label">{label}</div>
        <div className={"stat__value" + (danger ? " danger-text" : "")}>{value}</div>
        {sub && <div className="muted small">{sub}</div>}
      </div>
    </div>
  );
}

export function Dashboard() {
  const app = useApp();
  // Fleet traffic and nodes are instance-wide; group-only accounts see
  // their groups' changes and certificates.
  const fleet = app.can("viewer");
  const traffic = useQuery({
    queryKey: ["traffic"],
    queryFn: () => api.get<{ traffic: Traffic }>("/traffic?window=5m"),
    refetchInterval: 10000,
    enabled: fleet,
  });
  const nodes = useQuery({ queryKey: ["nodes"], queryFn: () => api.get<Items<NodeStatus>>("/nodes"), refetchInterval: 10000, enabled: fleet });
  const revs = useQuery({ queryKey: ["revisions"], queryFn: () => api.get<Items<Revision>>("/revisions") });
  const certs = useQuery({ queryKey: ["certificates", ""], queryFn: () => api.get<Items<Resource>>("/certificates") });

  const t = traffic.data?.traffic;
  const latest = revs.data?.items[0];
  const nodeItems = nodes.data?.items ?? [];
  const behind = latest ? nodeItems.filter((n) => n.activeRevision !== latest.revision).length : 0;
  const attention = (certs.data?.items ?? [])
    .filter((c) => c.spec.status?.error || (c.spec.status?.notAfter && new Date(c.spec.status.notAfter).getTime() - Date.now() < 30 * DAY))
    .sort((a, b) => new Date(a.spec.status?.notAfter ?? 0).getTime() - new Date(b.spec.status?.notAfter ?? 0).getTime());

  return (
    <div className="stack">
      <PageHeader title="Dashboard" sub={fleet ? "Traffic over the last 5 minutes, nodes and recent changes." : "Recent changes to your groups."} />
      {fleet && <div className="grid grid--3">
        <Stat label="Requests" value={t ? t.requests.toLocaleString() : "–"} sub={t && `${(t.requests / WINDOW_SECONDS).toFixed(1)} req/s`} />
        <Stat label="5xx rate" value={t ? pct(t.serverErrors, t.requests) : "–"} sub={t && `${t.serverErrors.toLocaleString()} responses`}
          danger={!!t && t.requests > 0 && t.serverErrors / t.requests > 0.05} />
        <Stat label="Upstream failure rate" value={t ? pct(t.upstreamFailures, t.upstreamAttempts) : "–"} sub={t && `${t.upstreamAttempts.toLocaleString()} attempts`}
          danger={!!t && t.upstreamAttempts > 0 && t.upstreamFailures / t.upstreamAttempts > 0.05} />
      </div>}
      {app.pending && <PendingBanner rev={app.pending} />}
      <div className={fleet ? "grid grid--2" : "stack"}>
        {fleet && <Card title="Nodes" actions={<Link className="btn btn--ghost btn--sm" to="/nodes">View all</Link>}>
          {nodes.isPending ? <Loading /> : nodes.error ? <ErrorBanner error={nodes.error} /> : nodeItems.length === 0 ? (
            <Empty title="No proxy connected" text="Start proxelo-proxy with the control socket to serve traffic." />
          ) : (
            <div className="stack">
              <div className="row">
                <span className="strong">{nodeItems.length}</span>
                <span className="muted">connected</span>
                {behind ? <Status tone="warning">{behind} behind</Status> : <Status tone="success">All on revision {latest?.revision}</Status>}
              </div>
              {nodeItems.filter((n) => n.error).map((n) => (
                <div key={n.nodeId} className="banner banner--danger" role="alert"><span className="mono">{n.nodeId}</span>: {n.error}</div>
              ))}
            </div>
          )}
        </Card>}
        <Card title="Certificates needing attention" actions={<Link className="btn btn--ghost btn--sm" to="/$kind" params={{ kind: "certificates" }}>View all</Link>}>
          {certs.isPending ? <Loading /> : attention.length === 0 ? (
            <p className="muted">No certificate expires within 30 days.</p>
          ) : (
            <ul className="stack">
              {attention.slice(0, 5).map((c) => (
                <li key={c.id} className="row row--between">
                  <Link to="/$kind/$id" params={{ kind: "certificates", id: c.id }}>{c.name}</Link>
                  {c.spec.status.error ? <Status tone="danger">Error</Status> : <Status tone="warning">Expires {timeAgo(c.spec.status.notAfter)}</Status>}
                </li>
              ))}
            </ul>
          )}
        </Card>
      </div>
      <Card title="Recent changes" flush actions={<Link className="btn btn--ghost btn--sm" to="/changes">Changes</Link>}>
        {revs.isPending ? <div className="card__body"><Loading /></div> : <RevisionTable items={(revs.data?.items ?? []).slice(0, 5)} actions={false} />}
      </Card>
    </div>
  );
}
