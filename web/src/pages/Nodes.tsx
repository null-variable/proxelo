import { useQuery } from "@tanstack/react-query";
import { api } from "../api/client";
import type { Items, NodeStatus } from "../api/types";
import { Empty, ErrorBanner, Loading, PageHeader, Status, timeAgo } from "../components/ui";

export function Nodes() {
  const nodes = useQuery({ queryKey: ["nodes"], queryFn: () => api.get<Items<NodeStatus>>("/nodes"), refetchInterval: 10000 });
  const items = nodes.data?.items ?? [];
  return (
    <div className="stack">
      <PageHeader title="Nodes" sub="Proxies connected to this control plane." />
      <ErrorBanner error={nodes.error} />
      {nodes.isPending ? <Loading /> : items.length === 0 ? <Empty title="No proxy connected" /> : (
        <div className="data-table-wrap">
          <table className="data-table">
            <thead><tr><th>Node</th><th>Version</th><th>Active</th><th>Sent</th><th>Status</th><th>Connected</th></tr></thead>
            <tbody>
              {items.map((n) => (
                <tr key={n.nodeId}>
                  <td className="mono">{n.nodeId}</td>
                  <td>{n.proxyVersion}</td>
                  <td className="mono">r{n.activeRevision}</td>
                  <td className="mono">r{n.sentRevision}</td>
                  <td>
                    {n.error ? <><Status tone="danger">Failed r{n.failedRevision}</Status> <span className="small">{n.error}</span></>
                      : n.activeRevision === n.sentRevision ? <Status tone="success">In sync</Status> : <Status tone="warning">Loading</Status>}
                  </td>
                  <td className="muted nowrap">{timeAgo(n.connectedAt)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
