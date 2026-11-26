// Routes (code-based TanStack Router). Paths match the Go server's SPA
// fallback: any extensionless path serves index.html.
import { createRootRoute, createRoute, createRouter, Link, useNavigate } from "@tanstack/react-router";
import { isKind } from "../api/types";
import { Empty } from "../components/ui";
import { ChangeSetDetail, Changes } from "../pages/Changes";
import { Dashboard } from "../pages/Dashboard";
import { Nodes } from "../pages/Nodes";
import { ResourceEdit, ResourceList } from "../pages/Resources";
import { Settings } from "../pages/Settings";
import { Simulator } from "../pages/Simulator";
import { Tap } from "../pages/Tap";
import { Topology } from "../pages/Topology";
import { Shell } from "./Shell";

function NotFound() {
  return (
    <Empty title="Page not found" text={location.pathname}>
      <Link className="btn" to="/">Go to the dashboard</Link>
    </Empty>
  );
}

const root = createRootRoute({ component: Shell, notFoundComponent: NotFound });

const dashboard = createRoute({ getParentRoute: () => root, path: "/", component: Dashboard });
const nodes = createRoute({ getParentRoute: () => root, path: "/nodes", component: Nodes });
const simulator = createRoute({ getParentRoute: () => root, path: "/simulator", component: Simulator });
const tap = createRoute({ getParentRoute: () => root, path: "/tap", component: Tap });
const topology = createRoute({ getParentRoute: () => root, path: "/topology", component: Topology });
const settings = createRoute({ getParentRoute: () => root, path: "/settings", component: Settings });

type ChangesTab = "changesets" | "revisions";
const changes = createRoute({
  getParentRoute: () => root,
  path: "/changes",
  validateSearch: (s: Record<string, unknown>): { tab?: ChangesTab } => (s.tab === "revisions" ? { tab: "revisions" } : {}),
  component: function ChangesPage() {
    const { tab } = changes.useSearch();
    const navigate = useNavigate();
    return <Changes tab={tab ?? "changesets"} onTab={(t) => void navigate({ to: "/changes", search: t === "revisions" ? { tab: t } : {} })} />;
  },
});
const changeSet = createRoute({
  getParentRoute: () => root,
  path: "/changes/$id",
  component: function ChangeSetPage() {
    const { id } = changeSet.useParams();
    return <ChangeSetDetail key={id} id={id} />;
  },
});

const resources = createRoute({
  getParentRoute: () => root,
  path: "/$kind",
  component: function ResourcesPage() {
    const { kind } = resources.useParams();
    return isKind(kind) ? <ResourceList key={kind} kind={kind} /> : <NotFound />;
  },
});
const resource = createRoute({
  getParentRoute: () => root,
  path: "/$kind/$id",
  component: function ResourcePage() {
    const { kind, id } = resource.useParams();
    return isKind(kind) ? <ResourceEdit key={kind + id} kind={kind} id={id} /> : <NotFound />;
  },
});

export const router = createRouter({
  routeTree: root.addChildren([dashboard, nodes, simulator, tap, topology, settings, changes, changeSet, resources, resource]),
  scrollRestoration: true,
});

declare module "@tanstack/react-router" {
  interface Register {
    router: typeof router;
  }
}
