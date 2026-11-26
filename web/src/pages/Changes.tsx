// Changes: change sets with diff, validation, apply and
// import; revisions with confirm and rollback.
import { useState, type FormEvent, type ReactNode } from "react";
import { Link, useNavigate } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { api, requestText, request } from "../api/client";
import { KINDS, isKind, type ChangeSet, type Change, type DiffResult, type Items, type Revision, type Validation } from "../api/types";
import { useApp } from "../app/context";
import {
  Dialog, Empty, ErrorBanner, Field, Loading, PageHeader, SettingRow, Status, Tabs, Toggle,
  fmtTime, revisionTone, shortHash, timeAgo, toast, toastError, type Tone,
} from "../components/ui";
import { refName, useRefs } from "./Resources";

type Tab = "changesets" | "revisions";

export function Changes({ tab, onTab }: { tab: Tab; onTab: (t: Tab) => void }) {
  return (
    <div className="stack">
      <PageHeader title="Changes" sub="Edits collect in change sets. Applying one creates a revision; every revision can be rolled back." />
      <Tabs underline tabs={[{ id: "changesets", label: "Change sets" }, { id: "revisions", label: "Revisions" }]} value={tab} onChange={onTab} />
      {tab === "changesets" ? <ChangeSetList /> : <Revisions />}
    </div>
  );
}

function ChangeSetList() {
  const app = useApp();
  const navigate = useNavigate();
  const list = useQuery({ queryKey: ["changesets"], queryFn: () => api.get<Items<ChangeSet>>("/changesets") });
  const [creating, setCreating] = useState(false);
  const items = list.data?.items ?? [];
  return (
    <div className="stack">
      {app.can("editor") && (
        <div className="row row--between">
          <span />
          <button className="btn btn--primary" onClick={() => setCreating(true)}>New change set</button>
        </div>
      )}
      <ErrorBanner error={list.error} />
      {list.isPending ? <Loading /> : items.length === 0 ? (
        <Empty title="No open change sets" text="Editing a resource opens one automatically." />
      ) : (
        <div className="data-table-wrap">
          <table className="data-table">
            <thead><tr><th>Message</th><th>Author</th><th>Items</th><th>Base</th><th>Updated</th><th /></tr></thead>
            <tbody>
              {items.map((c) => (
                <tr key={c.id}>
                  <td>
                    <Link to="/changes/$id" params={{ id: c.id }}>{c.message || c.id}</Link>
                    {app.changeset === c.id && <> <span className="badge badge--info">Active</span></>}
                  </td>
                  <td>{c.author}</td>
                  <td>{c.items.length}</td>
                  <td className="mono">r{c.baseRevision}</td>
                  <td className="muted nowrap">{timeAgo(c.updatedAt)}</td>
                  <td className="row-actions">
                    {app.changeset !== c.id && <button className="btn btn--ghost btn--sm" onClick={() => app.setChangeSet(c.id)}>Make active</button>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {creating && (
        <NewChangeSet
          onClose={() => setCreating(false)}
          onCreated={(c) => {
            setCreating(false);
            app.setChangeSet(c.id);
            app.refresh();
            void navigate({ to: "/changes/$id", params: { id: c.id } });
          }}
        />
      )}
    </div>
  );
}

export function NewChangeSet({ onClose, onCreated }: { onClose: () => void; onCreated: (c: ChangeSet) => void }) {
  const [msg, setMsg] = useState("");
  const [busy, setBusy] = useState(false);
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    try {
      onCreated(await api.post<ChangeSet>("/changesets", { message: msg }));
    } catch (err) {
      toastError(err);
      setBusy(false);
    }
  };
  return (
    <Dialog title="New change set" text="Edits are collected here until you apply them." onClose={onClose}>
      <form onSubmit={submit} className="stack">
        <Field id="cs-msg" label="Message" hint="What this change is for, as shown in the revision history.">
          <input id="cs-msg" className="input" value={msg} onChange={(e) => setMsg(e.target.value)} placeholder="Add example.com" />
        </Field>
        <div className="dialog__actions">
          <button type="button" className="btn" onClick={onClose}>Cancel</button>
          <button className="btn btn--primary" disabled={busy}>Create</button>
        </div>
      </form>
    </Dialog>
  );
}

export function ChangeSetDetail({ id }: { id: string }) {
  const app = useApp();
  const navigate = useNavigate();
  const cs = useQuery({ queryKey: ["changesets", id], queryFn: () => api.get<ChangeSet>(`/changesets/${id}`) });
  const diff = useQuery({ queryKey: ["changesets", id, "diff"], queryFn: () => api.get<DiffResult>(`/changesets/${id}/diff`) });
  const refs = useRefs(id);
  const [validation, setValidation] = useState<Validation | null>(null);
  const [dialog, setDialog] = useState<"apply" | "discard" | "import" | null>(null);
  const [busy, setBusy] = useState(false);
  const [tab, setTab] = useState<"resources" | "effective">("resources");

  const validate = async () => {
    setBusy(true);
    try {
      setValidation(await api.post<Validation>(`/changesets/${id}/validate`));
    } catch (e) {
      toastError(e);
    } finally {
      setBusy(false);
    }
  };
  const exportCurrent = async () => {
    try {
      const text = await requestText("/export");
      const a = document.createElement("a");
      a.href = URL.createObjectURL(new Blob([text], { type: "application/yaml" }));
      a.download = "proxelo-config.yaml";
      a.click();
      URL.revokeObjectURL(a.href);
    } catch (e) {
      toastError(e);
    }
  };
  const discard = async () => {
    setBusy(true);
    try {
      await api.del(`/changesets/${id}`);
      toast("Change set discarded");
      if (app.changeset === id) app.setChangeSet("");
      app.refresh();
      void navigate({ to: "/changes" });
    } catch (e) {
      toastError(e);
      setBusy(false);
    }
  };

  const crumbs = [{ label: "Changes", to: "/changes" }];
  if (cs.error) {
    return (
      <div className="stack">
        <PageHeader crumbs={crumbs} title={id} />
        <ErrorBanner error={cs.error} />
      </div>
    );
  }
  if (!cs.data) return <Loading />;
  const c = cs.data;
  const res = diff.data?.resources ?? [];
  const eff = diff.data?.effective ?? [];
  // Effective diff kinds are singular ("route"); refs are keyed by plural.
  const plural = (k: string) => (k === "policy" ? "policies" : `${k}s`);

  return (
    <div className="stack">
      <PageHeader
        crumbs={[...crumbs, { label: c.id }]}
        title={c.message || "Change set"}
        sub={<><span className="mono">{c.id}</span> · by {c.author} · based on revision {c.baseRevision} · {c.items.length} items</>}
      >
        {app.changeset !== c.id && <button className="btn" onClick={() => app.setChangeSet(c.id)}>Make active</button>}
        <button className="btn" onClick={exportCurrent} title="Download the current configuration as a bundle">Export current</button>
        {app.can("editor") && <button className="btn" onClick={() => setDialog("import")}>Import</button>}
        <button className="btn" disabled={busy} onClick={validate}>Validate</button>
        {app.can("operator") && (
          <button className="btn btn--primary" disabled={busy || c.items.length === 0 || !!app.pending} onClick={() => setDialog("apply")}>Apply</button>
        )}
      </PageHeader>
      {app.pending && (
        <div className="banner banner--warning" role="status">
          Revision {app.pending.revision} is waiting for confirmation; confirm or roll it back before applying.
        </div>
      )}
      {diff.data?.errors && (
        <div className="banner banner--danger" role="alert">
          <div>
            <div className="strong">This change set does not compile</div>
            <FindingList items={diff.data.errors} />
          </div>
        </div>
      )}
      {validation && <ValidationResult v={validation} />}
      <Tabs underline value={tab} onChange={setTab} tabs={[{ id: "resources", label: `Resources (${res.length})` }, { id: "effective", label: `Effective (${eff.length})` }]} />
      {diff.isPending ? <Loading /> : diff.error ? <ErrorBanner error={diff.error} /> : tab === "resources" ? (
        res.length === 0 ? <Empty title="No changes yet" text="Edit a resource while this change set is active." /> : res.map((r) => (
          <DiffCard
            key={r.kind + r.id}
            title={<>{isKind(r.kind) ? <Link to="/$kind/$id" params={{ kind: r.kind, id: r.id }}>{r.name || r.id}</Link> : r.name} <span className="muted small">{isKind(r.kind) ? KINDS[r.kind].one : r.kind}</span></>}
            op={r.op}
            drifted={r.drifted}
            changes={r.changes}
          />
        ))
      ) : eff.length === 0 ? (
        <Empty title="No behavior change" text="The compiled configuration is the same as the current revision's." />
      ) : eff.map((e) => {
        const k = plural(e.kind);
        return (
          <DiffCard
            key={e.kind + e.id}
            title={<>{isKind(k) ? refName(refs.data, k, e.id) : ""} <span className="mono small">{e.id}</span> <span className="muted small">{e.kind}</span></>}
            op={e.op}
            changes={e.changes}
          />
        );
      })}
      {app.can("editor") && (
        <div className="danger-zone card__body">
          <SettingRow title="Discard change set" text="Deletes every edit in it. The served configuration is not affected.">
            <button className="btn btn--destructive" onClick={() => setDialog("discard")}>Discard</button>
          </SettingRow>
        </div>
      )}
      {dialog === "apply" && (
        <ApplyDialog
          id={id}
          onClose={() => setDialog(null)}
          onApplied={(rev) => {
            setDialog(null);
            if (app.changeset === id) app.setChangeSet("");
            app.refresh();
            toast(`Revision ${rev.revision} created`, rev.status === "pending" ? "Confirm it before it reverts." : undefined);
            void navigate({ to: "/changes", search: { tab: "revisions" } });
          }}
        />
      )}
      {dialog === "discard" && (
        <Dialog
          title="Discard change set"
          text="Every edit in this change set is deleted. This cannot be undone."
          onClose={() => setDialog(null)}
          actions={<><button className="btn" onClick={() => setDialog(null)}>Cancel</button><button className="btn btn--destructive" disabled={busy} onClick={discard}>Discard</button></>}
        />
      )}
      {dialog === "import" && <ImportDialog id={id} onClose={() => setDialog(null)} onDone={() => { setDialog(null); app.refresh(); }} />}
    </div>
  );
}

function FindingList({ items }: { items: { path: string; message: string }[] }) {
  return (
    <ul>
      {items.map((e, i) => <li key={i}><span className="mono">{e.path}</span>: {e.message}</li>)}
    </ul>
  );
}

function ValidationResult({ v }: { v: Validation }) {
  const safety = (v.warnings ?? []).filter((w) => w.level === "safety");
  const warn = (v.warnings ?? []).filter((w) => w.level !== "safety");
  return (
    <div className="stack">
      {v.valid ? (
        <div className="banner" role="status"><Status tone="success">Valid</Status> <span>The change set compiles and the proxy accepts it.</span></div>
      ) : (
        <div className="banner banner--danger" role="alert"><div><div className="strong">Validation failed</div><FindingList items={v.errors ?? []} /></div></div>
      )}
      {safety.length > 0 && (
        <div className="banner banner--danger" role="alert"><div><div className="strong">Safety findings: applying requires confirmation</div><FindingList items={safety} /></div></div>
      )}
      {warn.length > 0 && (
        <div className="banner banner--warning" role="status"><div><div className="strong">Warnings</div><FindingList items={warn} /></div></div>
      )}
    </div>
  );
}

const OP_TONE: Record<string, Tone> = { added: "success", create: "success", removed: "danger", delete: "danger" };

function fmt(v: unknown): string {
  return typeof v === "string" ? v : JSON.stringify(v);
}

// withoutMeta hides server bookkeeping in whole-resource diffs.
function withoutMeta(r: unknown): unknown {
  if (!r || typeof r !== "object") return r;
  const { id: _i, resourceVersion: _v, createdAt: _c, updatedAt: _u, ...rest } = r as Record<string, unknown>;
  return rest;
}

function DiffCard({ title, op, drifted, changes }: { title: ReactNode; op: string; drifted?: boolean; changes?: Change[] }) {
  const whole = changes?.length === 1 && changes[0]!.path === "" ? changes[0]! : null;
  return (
    <section className="card">
      <div className="card__head">
        <div className="row">{title}</div>
        <div className="row">
          {drifted && <Status tone="warning">Changed in the current revision too</Status>}
          <Status tone={OP_TONE[op] ?? "info"}>{op}</Status>
        </div>
      </div>
      {whole ? (
        <div className="card__body">
          <pre className={"code " + (whole.new !== undefined ? "diff__new" : "diff__old")}>{JSON.stringify(withoutMeta(whole.new ?? whole.old), null, 2)}</pre>
        </div>
      ) : changes && changes.length > 0 && (
        <div className="card__body card__body--flush">
          <table className="diff">
            <tbody>
              {changes.map((c) => (
                <tr key={c.path}>
                  <td className="diff__path">{c.path}</td>
                  <td className={c.old !== undefined ? "diff__old" : ""}>{c.old !== undefined && <><span className="sr-only">old </span>− {fmt(c.old)}</>}</td>
                  <td className={c.new !== undefined ? "diff__new" : ""}>{c.new !== undefined && <><span className="sr-only">new </span>+ {fmt(c.new)}</>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

function ApplyDialog({ id, onClose, onApplied }: { id: string; onClose: () => void; onApplied: (r: Revision) => void }) {
  const [confirm, setConfirm] = useState(true);
  const [timeout, setTimeoutS] = useState("120");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<unknown>(null);
  const submit = async () => {
    setBusy(true);
    setErr(null);
    try {
      const out = await api.post<{ revision: Revision }>(`/changesets/${id}/apply`, {
        mode: confirm ? "confirm" : "direct",
        confirmTimeout: confirm ? Number(timeout) : 0,
      });
      onApplied(out.revision);
    } catch (e) {
      setErr(e);
      setBusy(false);
    }
  };
  return (
    <Dialog title="Apply change set" onClose={onClose} wide
      actions={<><button className="btn" onClick={onClose}>Cancel</button><button className="btn btn--primary" disabled={busy} onClick={submit}>Apply</button></>}>
      <div className="stack">
        <p className="dialog__text">The change set is merged into the current configuration and sent to every proxy as a new revision.</p>
        <ErrorBanner error={err} />
        <SettingRow title="Commit-confirm" text="The revision reverts by itself unless you confirm it in time. Safety findings force this on.">
          <Toggle checked={confirm} onChange={setConfirm} label="Commit-confirm" />
        </SettingRow>
        {confirm && (
          <Field id="ap-to" label="Confirm within (seconds)" hint="At most 3600.">
            <input id="ap-to" className="input" type="number" min={10} max={3600} value={timeout} onChange={(e) => setTimeoutS(e.target.value)} />
          </Field>
        )}
      </div>
    </Dialog>
  );
}

function ImportDialog({ id, onClose, onDone }: { id: string; onClose: () => void; onDone: () => void }) {
  const [text, setText] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<unknown>(null);
  const submit = async () => {
    setBusy(true);
    setErr(null);
    try {
      const json = text.trim().startsWith("{");
      await request("POST", `/changesets/${id}/import`, text, { contentType: json ? "application/json" : "application/yaml" });
      toast("Bundle imported");
      onDone();
    } catch (e) {
      setErr(e);
      setBusy(false);
    }
  };
  return (
    <Dialog title="Import bundle" text="Resources in the bundle replace the matching ones in this change set." onClose={onClose} wide
      actions={<><button className="btn" onClick={onClose}>Cancel</button><button className="btn btn--primary" disabled={busy || !text} onClick={submit}>Import</button></>}>
      <div className="stack">
        <ErrorBanner error={err} />
        <input type="file" accept=".yaml,.yml,.json" aria-label="Bundle file" onChange={async (e) => {
          const f = e.target.files?.[0];
          if (f) setText(await f.text());
        }} />
        <textarea className="code" aria-label="Bundle" spellCheck={false} value={text} onChange={(e) => setText(e.target.value)} placeholder="apiVersion: proxelo/v1" />
      </div>
    </Dialog>
  );
}

export function PendingBanner({ rev }: { rev: Revision }) {
  const app = useApp();
  const [busy, setBusy] = useState(false);
  const act = async (what: "confirm" | "rollback") => {
    setBusy(true);
    try {
      await api.post(`/revisions/${rev.revision}/${what}`);
      toast(what === "confirm" ? `Revision ${rev.revision} confirmed` : `Revision ${rev.revision} rolled back`);
      app.refresh();
    } catch (e) {
      toastError(e);
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="banner banner--warning" role="status">
      <div className="grow">
        <div className="strong">Revision {rev.revision} is waiting for confirmation</div>
        <div className="small">It reverts automatically {timeAgo(rev.confirmBy)} unless confirmed.{rev.guard && ` Guard: ${rev.guard}`}</div>
      </div>
      {app.can("operator") && (
        <div className="row">
          <button className="btn btn--sm" disabled={busy} onClick={() => act("rollback")}>Roll back</button>
          <button className="btn btn--primary btn--sm" disabled={busy} onClick={() => act("confirm")}>Confirm</button>
        </div>
      )}
    </div>
  );
}

function Revisions() {
  const app = useApp();
  const revs = useQuery({ queryKey: ["revisions"], queryFn: () => api.get<Items<Revision>>("/revisions") });
  return (
    <div className="stack">
      {app.pending && <PendingBanner rev={app.pending} />}
      <ErrorBanner error={revs.error} />
      {revs.isPending ? <Loading /> : (
        <div className="data-table-wrap">
          <RevisionTable items={revs.data?.items ?? []} actions={app.can("operator")} />
        </div>
      )}
    </div>
  );
}

export function RevisionTable({ items, actions }: { items: Revision[]; actions: boolean }) {
  const app = useApp();
  const [target, setTarget] = useState<Revision | null>(null);
  const [busy, setBusy] = useState(false);
  if (items.length === 0) return <Empty title="No revisions yet" text="Apply a change set to create the first one." />;
  const rollback = async (to: Revision) => {
    setBusy(true);
    try {
      const rev = await api.post<Revision>(`/revisions/${to.revision}/rollback`);
      toast(`Rolled back to revision ${to.revision}`, `As revision ${rev.revision}`);
      app.refresh();
    } catch (e) {
      toastError(e);
    } finally {
      setBusy(false);
      setTarget(null);
    }
  };
  return (
    <>
      <table className="data-table">
        <thead>
          <tr><th>Revision</th><th>Message</th><th>Author</th><th>Status</th><th>Hash</th><th>Created</th>{actions && <th />}</tr>
        </thead>
        <tbody>
          {items.map((r) => (
            <tr key={r.revision}>
              <td className="mono strong">r{r.revision}{r.tag && <> <span className="badge badge--outline">{r.tag}</span></>}</td>
              <td className="ellipsis">{r.message}</td>
              <td>{r.author}</td>
              <td><Status tone={revisionTone(r.status)}>{r.status}</Status>{r.guard && <> <span className="muted small">{r.guard}</span></>}</td>
              <td className="mono muted small">{shortHash(r.hash)}</td>
              <td className="muted nowrap" title={fmtTime(r.createdAt)}>{timeAgo(r.createdAt)}</td>
              {actions && (
                <td className="row-actions">
                  {r.revision !== items[0]!.revision && <button className="btn btn--ghost btn--sm" onClick={() => setTarget(r)}>Roll back to this</button>}
                </td>
              )}
            </tr>
          ))}
        </tbody>
      </table>
      {target && (
        <Dialog
          title={`Roll back to revision ${target.revision}`}
          text="A new revision with that configuration is created and sent to every proxy."
          onClose={() => setTarget(null)}
          actions={<><button className="btn" onClick={() => setTarget(null)}>Cancel</button><button className="btn btn--destructive" disabled={busy} onClick={() => rollback(target)}>Roll back</button></>}
        />
      )}
    </>
  );
}
