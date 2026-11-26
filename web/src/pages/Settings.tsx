// Settings: account (password, TOTP), API tokens, users and the audit log.
import { useState, type FormEvent } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../api/client";
import { GROUP_ROLES, ROLE_RANK, ROLES, type AuditEntry, type Group, type Items, type Role, type Token, type User } from "../api/types";
import { useApp } from "../app/context";
import { Card, Dialog, Empty, ErrorBanner, Field, Loading, PageHeader, SettingRow, Status, fmtTime, timeAgo, toast, toastError } from "../components/ui";

type Tab = "account" | "tokens" | "groups" | "users" | "audit";

export function Settings() {
  const app = useApp();
  const [tab, setTab] = useState<Tab>("account");
  const tabs: { id: Tab; label: string }[] = [{ id: "account", label: "Account" }, { id: "tokens", label: "API tokens" }];
  if (app.canAny("viewer")) tabs.push({ id: "groups", label: "Groups" });
  if (app.can("admin")) tabs.push({ id: "users", label: "Users" }, { id: "audit", label: "Audit log" });
  return (
    <div className="stack">
      <PageHeader title="Settings" />
      <div className="settings-layout">
        <nav className="settings-nav" aria-label="Settings">
          {tabs.map((t) => (
            <a key={t.id} href="#" className="sidenav__item" aria-current={tab === t.id ? "page" : undefined} onClick={(e) => { e.preventDefault(); setTab(t.id); }}>
              {t.label}
            </a>
          ))}
        </nav>
        <div className="stack">
          {tab === "account" && <Account />}
          {tab === "tokens" && <Tokens />}
          {tab === "groups" && <Groups />}
          {tab === "users" && <Users />}
          {tab === "audit" && <Audit />}
        </div>
      </div>
    </div>
  );
}

function useAction() {
  const [busy, setBusy] = useState(false);
  const run = async (fn: () => Promise<void>) => {
    setBusy(true);
    try {
      await fn();
    } catch (e) {
      toastError(e);
    } finally {
      setBusy(false);
    }
  };
  return { busy, run };
}

function Account() {
  const app = useApp();
  const qc = useQueryClient();
  const { busy, run } = useAction();
  const [pw, setPw] = useState({ current: "", password: "" });
  const [totp, setTotp] = useState<{ secret: string; uri: string } | null>(null);
  const [code, setCode] = useState("");
  const [disabling, setDisabling] = useState(false);
  const [disablePw, setDisablePw] = useState("");
  const reloadMe = () => qc.invalidateQueries({ queryKey: ["me"] });

  const changePassword = (e: FormEvent) => {
    e.preventDefault();
    void run(async () => {
      await api.post("/auth/password", pw);
      toast("Password changed", "Other sessions were signed out.");
      setPw({ current: "", password: "" });
    });
  };
  const enable = (e: FormEvent) => {
    e.preventDefault();
    void run(async () => {
      await api.post("/auth/totp/enable", { code });
      toast("Two-factor authentication enabled");
      setTotp(null);
      setCode("");
      await reloadMe();
    });
  };
  const disable = (e: FormEvent) => {
    e.preventDefault();
    void run(async () => {
      await api.post("/auth/totp/disable", { password: disablePw });
      toast("Two-factor authentication disabled");
      setDisabling(false);
      setDisablePw("");
      await reloadMe();
    });
  };

  return (
    <>
      <Card title="Password">
        <form className="stack" onSubmit={changePassword}>
          <Field id="pw-c" label="Current password">
            <input id="pw-c" className="input" type="password" autoComplete="current-password" value={pw.current} onChange={(e) => setPw({ ...pw, current: e.target.value })} required />
          </Field>
          <Field id="pw-n" label="New password" hint="At least 12 characters.">
            <input id="pw-n" className="input" type="password" autoComplete="new-password" minLength={12} value={pw.password} onChange={(e) => setPw({ ...pw, password: e.target.value })} required />
          </Field>
          <div><button className="btn btn--primary" disabled={busy}>Change password</button></div>
        </form>
      </Card>
      <Card title="Two-factor authentication">
        {app.me.user.totpEnabled && !totp ? (
          <SettingRow title={<Status tone="success">Enabled</Status>} text="Logins ask for a code from your authenticator app.">
            <button className="btn btn--danger-text" disabled={busy} onClick={() => setDisabling(true)}>Disable</button>
          </SettingRow>
        ) : totp ? (
          <form className="stack" onSubmit={enable}>
            <p>Add this key to your authenticator app, then enter the code it shows.</p>
            <div className="field"><span className="field__label">Key</span><span className="mono">{totp.secret}</span></div>
            <div className="field"><span className="field__label">Setup URI</span><span className="mono small break">{totp.uri}</span></div>
            <Field id="tf-c" label="Code">
              <input id="tf-c" className="input mono" inputMode="numeric" autoComplete="one-time-code" pattern="[0-9]{6}" value={code} onChange={(e) => setCode(e.target.value)} required />
            </Field>
            <div className="row">
              <button type="button" className="btn" onClick={() => setTotp(null)}>Cancel</button>
              <button className="btn btn--primary" disabled={busy}>Enable</button>
            </div>
          </form>
        ) : (
          <SettingRow title={<Status tone="warning">Not enabled</Status>} text="Protect the account with a time-based code (TOTP).">
            <button className="btn" disabled={busy} onClick={() => run(async () => setTotp(await api.post("/auth/totp/setup")))}>Set up</button>
          </SettingRow>
        )}
      </Card>
      {disabling && (
        <Dialog title="Disable two-factor authentication" text="Confirm with your password." onClose={() => setDisabling(false)}>
          <form className="stack" onSubmit={disable}>
            <Field id="tf-p" label="Password">
              <input id="tf-p" className="input" type="password" autoComplete="current-password" value={disablePw} onChange={(e) => setDisablePw(e.target.value)} required />
            </Field>
            <div className="dialog__actions">
              <button type="button" className="btn" onClick={() => setDisabling(false)}>Cancel</button>
              <button className="btn btn--destructive" disabled={busy}>Disable</button>
            </div>
          </form>
        </Dialog>
      )}
    </>
  );
}

function Tokens() {
  const app = useApp();
  const list = useQuery({ queryKey: ["tokens"], queryFn: () => api.get<Items<Token>>("/auth/tokens") });
  const roles = ROLES.filter((r) => r !== "owner" && ROLE_RANK[r] <= ROLE_RANK[app.me.role]);
  const [form, setForm] = useState<{ name: string; role: Role; cidrs: string; days: string } | null>(null);
  const [secret, setSecret] = useState("");
  const { busy, run } = useAction();
  const items = list.data?.items ?? [];

  const create = (e: FormEvent) => {
    e.preventDefault();
    if (!form) return;
    void run(async () => {
      const out = await api.post<{ secret: string }>("/auth/tokens", {
        name: form.name,
        role: form.role,
        cidrs: form.cidrs ? form.cidrs.split(/[\s,]+/).filter(Boolean) : undefined,
        expiresIn: `${Number(form.days) * 24}h`,
      });
      setSecret(out.secret);
      setForm(null);
      await list.refetch();
    });
  };
  const revoke = (t: Token) =>
    run(async () => {
      await api.del(`/auth/tokens/${t.id}`);
      toast(`Token ${t.name} revoked`);
      await list.refetch();
    });

  return (
    <Card title="API tokens" flush actions={app.me.via === "session" && (
      <button className="btn btn--sm" onClick={() => setForm({ name: "", role: roles[0] ?? "viewer", cidrs: "", days: "90" })}>Create token</button>
    )}>
      {secret && (
        <div className="card__body">
          <div className="banner banner--warning" role="status">
            <div><div className="strong">Copy the token now; it is not shown again.</div><span className="mono break">{secret}</span></div>
          </div>
        </div>
      )}
      {list.isPending ? <div className="card__body"><Loading /></div> : items.length === 0 ? (
        <div className="card__body"><Empty title="No tokens" text="Tokens let scripts call the API as you, with a role up to yours." /></div>
      ) : (
        <div className="data-table-wrap">
          <table className="data-table">
            <thead><tr><th>Name</th><th>Role</th><th>Networks</th><th>Expires</th><th>Last used</th><th /></tr></thead>
            <tbody>
              {items.map((t) => (
                <tr key={t.id}>
                  <td>{t.name}</td>
                  <td>{t.role}</td>
                  <td className="mono small">{t.cidrs?.join(", ") || "any"}</td>
                  <td className="nowrap">{fmtTime(t.expiresAt)}</td>
                  <td className="muted">{t.lastUsed ? timeAgo(t.lastUsed) : "never"}</td>
                  <td className="row-actions"><button className="btn btn--danger-text btn--sm" disabled={busy} onClick={() => revoke(t)}>Revoke</button></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {form && (
        <Dialog title="Create API token" onClose={() => setForm(null)}>
          <form className="stack" onSubmit={create}>
            <Field id="tk-n" label="Name">
              <input id="tk-n" className="input" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} required />
            </Field>
            <Field id="tk-r" label="Role" hint="At most your own role.">
              <select id="tk-r" className="input" value={form.role} onChange={(e) => setForm({ ...form, role: e.target.value as Role })}>
                {roles.map((r) => <option key={r} value={r}>{r}</option>)}
              </select>
            </Field>
            <Field id="tk-c" label="Allowed networks" hint="CIDRs, comma separated. Empty: any.">
              <input id="tk-c" className="input mono" placeholder="192.0.2.0/24" value={form.cidrs} onChange={(e) => setForm({ ...form, cidrs: e.target.value })} />
            </Field>
            <Field id="tk-d" label="Valid for (days)" hint="At most 366.">
              <input id="tk-d" className="input" type="number" min={1} max={366} value={form.days} onChange={(e) => setForm({ ...form, days: e.target.value })} />
            </Field>
            <div className="dialog__actions">
              <button type="button" className="btn" onClick={() => setForm(null)}>Cancel</button>
              <button className="btn btn--primary" disabled={busy}>Create</button>
            </div>
          </form>
        </Dialog>
      )}
    </Card>
  );
}

function Users() {
  const app = useApp();
  const list = useQuery({ queryKey: ["users"], queryFn: () => api.get<Items<User>>("/users") });
  const [form, setForm] = useState<{ name: string; password: string; role: Role } | null>(null);
  const [deleting, setDeleting] = useState<User | null>(null);
  const { busy, run } = useAction();
  const items = list.data?.items ?? [];
  // Only owners manage owners.
  const roles = ROLES.filter((r) => app.me.role === "owner" || r !== "owner");

  const act = (fn: () => Promise<unknown>, msg: string) =>
    run(async () => {
      await fn();
      toast(msg);
      await list.refetch();
    });

  return (
    <Card title="Users" flush actions={<button className="btn btn--sm" onClick={() => setForm({ name: "", password: "", role: "viewer" })}>Add user</button>}>
      {list.error && <div className="card__body"><ErrorBanner error={list.error} /></div>}
      {list.isPending ? <div className="card__body"><Loading /></div> : (
        <div className="data-table-wrap">
          <table className="data-table">
            <thead><tr><th>Name</th><th>Role</th><th>Two-factor</th><th>Created</th><th /></tr></thead>
            <tbody>
              {items.map((u) => {
                const locked = u.role === "owner" && app.me.role !== "owner";
                return (
                  <tr key={u.id}>
                    <td>{u.name}{u.id === app.me.user.id && <> <span className="badge badge--info">You</span></>}</td>
                    <td>
                      <select className="input input--sm" aria-label={`Role of ${u.name}`} value={u.role} disabled={locked || busy}
                        onChange={(e) => act(() => api.patch(`/users/${u.id}`, { role: e.target.value }), `${u.name} is now ${e.target.value}`)}>
                        {(locked ? ["owner"] : roles).map((r) => <option key={r} value={r}>{r}</option>)}
                      </select>
                    </td>
                    <td>{u.totpEnabled ? <Status tone="success">On</Status> : <Status tone="warning">Off</Status>}</td>
                    <td className="muted">{timeAgo(u.createdAt)}</td>
                    <td className="row-actions">
                      {u.id !== app.me.user.id && !locked && <button className="btn btn--danger-text btn--sm" onClick={() => setDeleting(u)}>Delete</button>}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
      {form && (
        <Dialog title="Add user" onClose={() => setForm(null)}>
          <form className="stack" onSubmit={(e) => { e.preventDefault(); void act(() => api.post("/users", form), `${form.name} added`).then(() => setForm(null)); }}>
            <Field id="us-n" label="User name">
              <input id="us-n" className="input" autoComplete="off" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} required />
            </Field>
            <Field id="us-p" label="Initial password" hint="At least 12 characters.">
              <input id="us-p" className="input" type="password" autoComplete="new-password" minLength={12} value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} required />
            </Field>
            <Field id="us-r" label="Role">
              <select id="us-r" className="input" value={form.role} onChange={(e) => setForm({ ...form, role: e.target.value as Role })}>
                {roles.map((r) => <option key={r} value={r}>{r}</option>)}
              </select>
            </Field>
            <div className="dialog__actions">
              <button type="button" className="btn" onClick={() => setForm(null)}>Cancel</button>
              <button className="btn btn--primary" disabled={busy}>Add</button>
            </div>
          </form>
        </Dialog>
      )}
      {deleting && (
        <Dialog title={`Delete user ${deleting.name}`} text="Their sessions and API tokens stop working." onClose={() => setDeleting(null)}
          actions={<>
            <button className="btn" onClick={() => setDeleting(null)}>Cancel</button>
            <button className="btn btn--destructive" disabled={busy} onClick={() => act(() => api.del(`/users/${deleting.id}`), `${deleting.name} deleted`).then(() => setDeleting(null))}>Delete</button>
          </>} />
      )}
    </Card>
  );
}

function Audit() {
  const list = useQuery({ queryKey: ["audit"], queryFn: () => api.get<Items<AuditEntry>>("/audit?limit=200") });
  const verify = useQuery({ queryKey: ["audit", "verify"], queryFn: () => api.get<{ ok: boolean; entries: number; error?: string }>("/audit/verify") });
  const items = [...(list.data?.items ?? [])].reverse();
  return (
    <Card title="Audit log" flush actions={verify.data && (verify.data.ok ? <Status tone="success">Chain intact</Status> : <Status tone="danger">Chain broken</Status>)}>
      {verify.data?.error && <div className="card__body"><ErrorBanner error={new Error(verify.data.error)} /></div>}
      {list.isPending ? <div className="card__body"><Loading /></div> : items.length === 0 ? <div className="card__body"><Empty title="No entries" /></div> : (
        <div className="data-table-wrap">
          <table className="data-table">
            <thead><tr><th>#</th><th>Time</th><th>Actor</th><th>Action</th><th>Target</th></tr></thead>
            <tbody>
              {items.map((e) => (
                <tr key={e.seq}>
                  <td className="mono muted">{e.seq}</td>
                  <td className="nowrap" title={fmtTime(e.at)}>{timeAgo(e.at)}</td>
                  <td>{e.actor}</td>
                  <td className="mono">{e.action}</td>
                  <td className="mono small ellipsis">{e.target}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Card>
  );
}

// Groups: a tree of groups, each bounded to domains, whose members' roles
// apply to the group's resources and every subgroup's.
function Groups() {
  const app = useApp();
  const list = useQuery({ queryKey: ["groups"], queryFn: () => api.get<Items<Group>>("/groups") });
  const dir = useQuery({ queryKey: ["directory"], queryFn: () => api.get<Items<{ id: string; name: string }>>("/directory"), enabled: app.canAny("admin") });
  const [form, setForm] = useState<{ id?: string; name: string; parent: string; description: string; domains: string } | null>(null);
  const [deleting, setDeleting] = useState<Group | null>(null);
  const [member, setMember] = useState<Record<string, { user: string; role: Role }>>({});
  const { busy, run } = useAction();
  const items = list.data?.items ?? [];
  const byID = new Map(items.map((g) => [g.id, g]));
  const userName = (id: string) => dir.data?.items.find((u) => u.id === id)?.name ?? (id === app.me.user.id ? app.me.user.name : id);
  const depth = (g: Group): number => (g.parent && byID.has(g.parent) ? 1 + depth(byID.get(g.parent)!) : 0);
  const path = (g: Group): string => (g.parent && byID.has(g.parent) ? path(byID.get(g.parent)!) + " / " : "") + g.name;
  // Parents first, children right below them.
  const ordered: Group[] = [];
  const walk = (parent: string | undefined) =>
    items.filter((g) => (g.parent || undefined) === parent || (parent === undefined && g.parent && !byID.has(g.parent))).forEach((g) => {
      ordered.push(g);
      walk(g.id);
    });
  walk(undefined);
  const roleIn = (id: string) => (app.can("admin") ? "admin" : app.me.groupRoles[id]);
  const isAdmin = (id: string) => app.can("admin", id);

  const act = (fn: () => Promise<unknown>, msg: string) =>
    run(async () => {
      await fn();
      toast(msg);
      await list.refetch();
    });
  const domains = (s: string) => s.split(/[\s,]+/).filter(Boolean);
  const save = () => {
    if (!form) return;
    const body = { name: form.name, parent: form.parent, description: form.description, domains: domains(form.domains) };
    void act(() => (form.id ? api.patch(`/groups/${form.id}`, body) : api.post("/groups", body)), `Group ${form.name} saved`).then(() => setForm(null));
  };

  return (
    <Card title="Groups" flush actions={app.can("admin") && <button className="btn btn--sm" onClick={() => setForm({ name: "", parent: "", description: "", domains: "" })}>Add group</button>}>
      <div className="card__body muted small">
        Group members get their role (viewer, editor, operator, admin) on the group's resources and those of every subgroup. Sites of a group with domains may only serve hostnames inside them.
      </div>
      {list.error && <div className="card__body"><ErrorBanner error={list.error} /></div>}
      {list.isPending ? <div className="card__body"><Loading /></div> : ordered.length === 0 ? <div className="card__body"><Empty title="No groups" text="Groups scope resources to teams or domains." /></div> : (
        <div className="stack card__body">
          {ordered.map((g) => {
            const m = member[g.id] ?? { user: "", role: "viewer" as Role };
            return (
              <div key={g.id} className="group-row" style={{ marginLeft: depth(g) * 20 }}>
                <div className="row row--between">
                  <div>
                    <b>{path(g)}</b>{roleIn(g.id) && <> <span className="badge badge--outline">{roleIn(g.id)}</span></>}
                    <div className="muted small">{g.domains.length ? g.domains.join(", ") : g.parent ? "Domains of the parent group" : "Any domain"}{g.description ? ` · ${g.description}` : ""}</div>
                  </div>
                  {isAdmin(g.id) && (
                    <div className="row">
                      <button className="btn btn--sm" onClick={() => setForm({ name: "", parent: g.id, description: "", domains: "" })}>Add subgroup</button>
                      <button className="btn btn--sm" onClick={() => setForm({ id: g.id, name: g.name, parent: g.parent ?? "", description: g.description ?? "", domains: g.domains.join(", ") })}>Edit</button>
                      <button className="btn btn--danger-text btn--sm" onClick={() => setDeleting(g)}>Delete</button>
                    </div>
                  )}
                </div>
                <table className="data-table mt">
                  <tbody>
                    {g.members.map((mm) => (
                      <tr key={mm.user}>
                        <td>{userName(mm.user)}</td>
                        <td>
                          {isAdmin(g.id) ? (
                            <select className="input input--sm" aria-label={`Role of ${userName(mm.user)} in ${g.name}`} value={mm.role} disabled={busy}
                              onChange={(e) => act(() => api.put(`/groups/${g.id}/members`, { user: userName(mm.user), role: e.target.value }), `${userName(mm.user)} is now ${e.target.value} in ${g.name}`)}>
                              {GROUP_ROLES.filter((r) => app.can(r, g.id)).map((r) => <option key={r} value={r}>{r}</option>)}
                            </select>
                          ) : mm.role}
                        </td>
                        <td className="row-actions">
                          {(isAdmin(g.id) || mm.user === app.me.user.id) && (
                            <button className="btn btn--danger-text btn--sm" disabled={busy} onClick={() => act(() => api.del(`/groups/${g.id}/members/${mm.user}`), `${userName(mm.user)} removed from ${g.name}`)}>
                              {mm.user === app.me.user.id ? "Leave" : "Remove"}
                            </button>
                          )}
                        </td>
                      </tr>
                    ))}
                    {g.members.length === 0 && <tr><td className="muted" colSpan={3}>No direct members{g.parent ? "; members of parent groups apply" : ""}.</td></tr>}
                  </tbody>
                </table>
                {isAdmin(g.id) && (
                  <form className="row mt member-form" onSubmit={(e) => { e.preventDefault(); void act(() => api.put(`/groups/${g.id}/members`, m), `${m.user} added to ${g.name}`).then(() => setMember({ ...member, [g.id]: { user: "", role: "viewer" } })); }}>
                    <select className="input input--sm grow" aria-label={`Add member to ${g.name}`} value={m.user} onChange={(e) => setMember({ ...member, [g.id]: { ...m, user: e.target.value } })} required>
                      <option value="">Add member…</option>
                      {(dir.data?.items ?? []).filter((u) => !g.members.some((x) => x.user === u.id)).map((u) => <option key={u.id} value={u.name}>{u.name}</option>)}
                    </select>
                    <select className="input input--sm" aria-label="Role" value={m.role} onChange={(e) => setMember({ ...member, [g.id]: { ...m, role: e.target.value as Role } })}>
                      {GROUP_ROLES.filter((r) => app.can(r, g.id)).map((r) => <option key={r} value={r}>{r}</option>)}
                    </select>
                    <button className="btn btn--sm" disabled={busy || !m.user}>Add</button>
                  </form>
                )}
              </div>
            );
          })}
        </div>
      )}
      {form && (
        <Dialog title={form.id ? `Edit group ${form.name}` : form.parent ? `Add subgroup of ${byID.get(form.parent)?.name}` : "Add group"} onClose={() => setForm(null)}>
          <form className="stack" onSubmit={(e) => { e.preventDefault(); save(); }}>
            <Field id="gr-n" label="Name">
              <input id="gr-n" className="input" autoComplete="off" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} required />
            </Field>
            <Field id="gr-d" label="Description">
              <input id="gr-d" className="input" value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} />
            </Field>
            <Field id="gr-dm" label="Domains" hint={form.parent ? "Inside the parent's domains. Empty: the parent's." : "Comma-separated, for example shop.example; each covers its subdomains. Empty: any."}>
              <input id="gr-dm" className="input mono" value={form.domains} disabled={!!form.id && !app.can("admin", form.parent || undefined)} onChange={(e) => setForm({ ...form, domains: e.target.value })} />
            </Field>
            <div className="dialog__actions">
              <button type="button" className="btn" onClick={() => setForm(null)}>Cancel</button>
              <button className="btn btn--primary" disabled={busy}>Save</button>
            </div>
          </form>
        </Dialog>
      )}
      {deleting && (
        <Dialog title={`Delete group ${deleting.name}`} text="Only groups without subgroups or resources can be deleted." onClose={() => setDeleting(null)}
          actions={<>
            <button className="btn" onClick={() => setDeleting(null)}>Cancel</button>
            <button className="btn btn--destructive" disabled={busy} onClick={() => act(() => api.del(`/groups/${deleting.id}`), `${deleting.name} deleted`).then(() => setDeleting(null))}>Delete</button>
          </>} />
      )}
    </Card>
  );
}
