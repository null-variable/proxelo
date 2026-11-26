// App shell: topbar, side navigation, the
// draft bar (pending changes, review and apply) and the
// pending-revision banner.
import { useEffect, useState } from "react";
import { Link, Outlet, useRouterState } from "@tanstack/react-router";
import { KINDS, type Kind } from "../api/types";
import { Toasts, timeAgo } from "../components/ui";
import { useApp } from "./context";

interface NavItem {
  to: string;
  label: string;
  badge?: boolean;
}

const RESOURCE_NAV: Kind[] = ["sites", "routes", "upstreams", "certificates", "policies", "listeners"];

const NAV: { group: string; items: NavItem[] }[] = [
  { group: "Overview", items: [{ to: "/", label: "Dashboard" }, { to: "/nodes", label: "Nodes" }] },
  { group: "Configuration", items: RESOURCE_NAV.map((k) => ({ to: `/${k}`, label: KINDS[k].label })) },
  { group: "Operate", items: [{ to: "/changes", label: "Changes", badge: true }, { to: "/simulator", label: "Simulator" }] },
  { group: "Settings", items: [{ to: "/settings", label: "Settings" }] },
];

function ModeToggle() {
  const [mode, setMode] = useState(document.documentElement.dataset.mode ?? "light");
  const next = mode === "dark" ? "light" : "dark";
  const flip = () => {
    document.documentElement.dataset.mode = next;
    localStorage.setItem("proxelo.mode", next);
    setMode(next);
  };
  return (
    <button className="btn btn--ghost btn--sm" onClick={flip} aria-label={`Switch to ${next} mode`}>
      {next === "dark" ? "Dark" : "Light"}
    </button>
  );
}

function DraftBar() {
  const app = useApp();
  const cs = app.changesets.find((c) => c.id === app.changeset);
  if (!cs) return null;
  const n = cs.items.length;
  return (
    <div className="banner" role="status" style={{ marginBottom: 16 }}>
      <div className="grow">
        Editing change set <b>{cs.message || cs.id}</b> · {n} pending {n === 1 ? "change" : "changes"}
      </div>
      <div className="row">
        <button className="btn btn--ghost btn--sm" onClick={() => app.setChangeSet("")}>Leave</button>
        <Link className="btn btn--sm" to="/changes/$id" params={{ id: cs.id }}>Review and apply</Link>
      </div>
    </div>
  );
}

export function Shell() {
  const app = useApp();
  const path = useRouterState({ select: (s) => s.location.pathname });
  const [menu, setMenu] = useState(false);
  useEffect(() => setMenu(false), [path]);
  const current = (to: string) => (to === "/" ? path === "/" : path === to || path.startsWith(to + "/"));

  return (
    <div className="app">
      <header className="topbar">
        <div className="topbar__brand">
          <button className="btn btn--ghost btn--sm menu-btn" aria-label="Menu" aria-expanded={menu} onClick={() => setMenu(!menu)}>☰</button>
          <span className="logo-mark" aria-hidden="true" />
          Proxelo
        </div>
        <select className="input input--sm topbar__changeset" aria-label="Active change set" value={app.changeset} onChange={(e) => app.setChangeSet(e.target.value)}>
          <option value="">Current configuration</option>
          {app.changesets.map((c) => <option key={c.id} value={c.id}>{c.message || c.id} ({c.items.length})</option>)}
        </select>
        <span className="topbar__spacer" />
        <ModeToggle />
        <Link className="btn btn--ghost btn--sm topbar__wide" to="/settings" aria-label={`Account: ${app.me.user.name}, ${app.me.role}`}>
          {app.me.user.name} <span className="badge badge--outline">{app.me.role}</span>
        </Link>
        <button className="btn btn--ghost btn--sm topbar__wide" onClick={app.logout}>Log out</button>
      </header>
      <nav className="sidenav" aria-label="Main" data-open={menu}>
        {NAV.map((g) => (
          <div key={g.group} style={{ display: "contents" }}>
            <div className="sidenav__group">{g.group}</div>
            {g.items.map((it) => (
              <Link key={it.to} className="sidenav__item" to={it.to} aria-current={current(it.to) ? "page" : undefined}>
                <i className="sidenav__icon" aria-hidden="true" />
                {it.label}
                {it.badge && app.changesets.length > 0 && <span className="badge sidenav__badge">{app.changesets.length}</span>}
              </Link>
            ))}
          </div>
        ))}
        <div className="sidenav__group sidenav__narrow">{app.me.user.name} · {app.me.role}</div>
        <button className="sidenav__item sidenav__narrow" onClick={app.logout}>
          <i className="sidenav__icon" aria-hidden="true" />
          Log out
        </button>
      </nav>
      <main className="main">
        <DraftBar />
        {app.pending && path !== "/" && !path.startsWith("/changes") && (
          <div className="banner banner--warning" role="status" style={{ marginBottom: 16 }}>
            Revision {app.pending.revision} reverts {timeAgo(app.pending.confirmBy)} unless confirmed.{" "}
            <Link to="/changes" search={{ tab: "revisions" }}>Review</Link>
          </div>
        )}
        <Outlet />
      </main>
      <Toasts />
    </div>
  );
}
