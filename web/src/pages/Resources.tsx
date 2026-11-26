// Resource lists and editors: Sites, Routes, Listeners, Upstreams,
// Certificates, Policies, Lookup tables. Editors are generated from the schema, with a Raw
// JSON tab.
import { useEffect, useState, type ReactNode } from "react";
import { Link, useNavigate } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { api, APIError, type FieldError } from "../api/client";
import { KINDS, TEMPLATES, type Group, type Items, type Kind, type Resource } from "../api/types";
import { useApp } from "../app/context";
import { Card, DeleteDialog, Empty, ErrorBanner, Field, Loading, PageHeader, Status, Tabs, timeAgo, toast, toastError } from "../components/ui";
import { SchemaForm, type Refs } from "../form/SchemaForm";

const ALL_KINDS = Object.keys(KINDS) as Kind[];

function q(cs: string): string {
  return cs ? `?changeset=${cs}` : "";
}

export function useList(kind: Kind, cs: string) {
  return useQuery({ queryKey: [kind, cs], queryFn: () => api.get<Items<Resource>>(`/${kind}${q(cs)}`) });
}

// useRefs loads every kind for reference pickers and summaries.
export function useRefs(cs: string) {
  return useQuery({
    queryKey: ["refs", cs],
    queryFn: async (): Promise<Refs> => {
      const lists = await Promise.all(ALL_KINDS.map((k) => api.get<Items<Resource>>(`/${k}${q(cs)}`)));
      return Object.fromEntries(ALL_KINDS.map((k, i) => [k, lists[i]!.items]));
    },
  });
}

export function useGroups() {
  return useQuery({ queryKey: ["groups"], queryFn: () => api.get<Items<Group>>("/groups") });
}

export function refName(refs: Refs | undefined, kind: Kind, id: string): string | undefined {
  return refs?.[kind]?.find((r) => r.id === id)?.name;
}

const PATH_SIGN: Record<string, string> = { exact: "=", prefix: "prefix", prefixPriority: "^~", regex: "~", regexCI: "~*" };

function certStatus(c: Resource): ReactNode {
  const st = c.spec.status ?? {};
  if (st.error) return <Status tone="danger">Error</Status>;
  if (!st.notAfter) return <Status tone="warning">Not issued</Status>;
  const left = new Date(st.notAfter).getTime() - Date.now();
  if (left < 0) return <Status tone="danger">Expired</Status>;
  if (left < 30 * 86400e3) return <Status tone="warning">Expires {timeAgo(st.notAfter)}</Status>;
  return <Status tone="success">Valid until {new Date(st.notAfter).toLocaleDateString()}</Status>;
}

function summary(kind: Kind, r: Resource, refs: Refs | undefined): ReactNode {
  const s = r.spec ?? {};
  switch (kind) {
    case "sites":
      return (s.hostnames ?? []).map((h: { value: string }) => h.value).join(", ") || <span className="muted">any host</span>;
    case "routes": {
      const m = s.match?.path;
      const up = s.action?.[s.action?.type]?.upstream;
      return (
        <>
          <span className="mono">{m ? `${PATH_SIGN[m.type] === "prefix" ? "" : PATH_SIGN[m.type] + " "}${m.value}` : ""}</span>{" "}
          <span className="muted">→ {s.action?.type}{up ? ` ${refName(refs, "upstreams", up) ?? up}` : ""}</span>
        </>
      );
    }
    case "listeners":
      return (
        <>
          <span className="mono">{s.address}</span>
          {s.tls && <> <span className="badge badge--info">TLS</span></>}
          {s.http2 && <> <span className="badge badge--outline">h2</span></>}
        </>
      );
    case "upstreams":
      return <span className="mono">{(s.targets ?? []).map((t: { address: string }) => t.address).join(", ")}</span>;
    case "certificates":
      return certStatus(r);
    case "policies":
      return s.type;
    case "streams":
      return (
        <span className="mono">
          {s.protocol === "udp" ? "udp" : "tcp"} {s.address}
          {s.sslPreread ? " · preread" : s.tls ? " · tls" : ""}
        </span>
      );
    case "lookups":
      return <span className="mono">${s.variable || r.name.replaceAll("-", "_")} ← {s.type === "geo" ? s.source || "$remote_addr" : s.source}</span>;
  }
}

export function ResourceList({ kind }: { kind: Kind }) {
  const app = useApp();
  const navigate = useNavigate();
  const list = useList(kind, app.changeset);
  const refs = useRefs(app.changeset);
  const [filter, setFilter] = useState("");
  const meta = KINDS[kind];
  const needle = filter.toLowerCase();
  const items = (list.data?.items ?? []).filter((r) => !needle || JSON.stringify(r).toLowerCase().includes(needle));
  return (
    <div className="stack">
      <PageHeader title={meta.label} sub={app.changeset ? <>Showing change set <span className="mono">{app.changeset}</span>.</> : "Showing the current configuration."}>
        {app.canAny("editor") && (
          <button className="btn btn--primary" onClick={() => app.withChangeSet(() => void navigate({ to: "/$kind/$id", params: { kind, id: "new" } }))}>
            Create {meta.one}
          </button>
        )}
      </PageHeader>
      <ErrorBanner error={list.error} />
      <div className="card list-card">
        <div className="table-toolbar">
          <input className="input grow" type="search" placeholder={`Search ${meta.label.toLowerCase()}`} aria-label="Search" value={filter} onChange={(e) => setFilter(e.target.value)} />
        </div>
        {list.isPending ? (
          <div className="card__body"><Loading /></div>
        ) : items.length === 0 ? (
          <Empty title={filter ? "No matches" : `No ${meta.label.toLowerCase()} yet`} text={filter ? "Try another search." : `Create a ${meta.one} to get started.`} />
        ) : (
          <div className="data-table-wrap">
            <table className="data-table">
              <thead><tr><th>Name</th><th>Summary</th><th>ID</th><th>Updated</th></tr></thead>
              <tbody>
                {items.map((r) => (
                  <tr key={r.id}>
                    <td>
                      <Link to="/$kind/$id" params={{ kind, id: r.id }}>{r.name}</Link>
                      {r.enabled === false && <> <span className="badge badge--outline">Disabled</span></>}
                    </td>
                    <td className="ellipsis">{summary(kind, r, refs.data)}</td>
                    <td className="mono muted small">{r.id}</td>
                    <td className="muted nowrap">{timeAgo(r.updatedAt)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}

type Draft = Partial<Resource>;

// editable drops fields the server owns.
function editable(r: Draft): Draft {
  const { id: _id, resourceVersion: _v, createdAt: _c, updatedAt: _u, ...rest } = r;
  if (rest.spec?.status) {
    const { status: _s, ...spec } = rest.spec;
    rest.spec = spec;
  }
  return rest;
}

function json(v: unknown): string {
  return JSON.stringify(v, null, 2);
}

export function ResourceEdit({ kind, id }: { kind: Kind; id: string }) {
  const app = useApp();
  const navigate = useNavigate();
  const isNew = id === "new";
  const meta = KINDS[kind];
  const loaded = useQuery({
    queryKey: [kind, app.changeset, id],
    queryFn: () => (isNew ? Promise.resolve(TEMPLATES[kind] as Resource) : api.get<Resource>(`/${kind}/${id}${q(app.changeset)}`)),
    staleTime: isNew ? Infinity : 0,
  });
  const refs = useRefs(app.changeset);
  const [doc, setDoc] = useState<Draft | null>(null);
  const [raw, setRaw] = useState("");
  const [view, setView] = useState<"form" | "raw">("form");
  const [errors, setErrors] = useState<FieldError[]>([]);
  const [banner, setBanner] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const groups = useGroups();
  // Editable when the principal is an editor where the resource is now
  // (new resources: anywhere); the server checks the target group too.
  const canEdit = isNew ? app.canAny("editor") : app.can("editor", loaded.data?.group);
  const writable = (groups.data?.items ?? []).filter((g) => app.can("editor", g.id));
  // Group-only members create inside a group they can write.
  const groupOf = (d: Draft) => d.group ?? (isNew && !app.can("editor") ? writable[0]?.id : undefined);

  useEffect(() => {
    if (!loaded.data) return;
    setDoc(loaded.data);
    setRaw(json(editable(loaded.data)));
    setErrors([]);
    setBanner(null);
  }, [loaded.data]);

  const fromRaw = (): Draft | null => {
    try {
      return { ...doc, ...(JSON.parse(raw) as Draft) };
    } catch (e) {
      setBanner(new Error("Raw JSON is invalid: " + (e as Error).message));
      return null;
    }
  };

  const switchView = (v: "form" | "raw") => {
    if (v === "form") {
      const d = fromRaw();
      if (!d) return;
      setDoc(d);
    } else if (doc) {
      setRaw(json(editable(doc)));
    }
    setBanner(null);
    setView(v);
  };

  const save = () =>
    app.withChangeSet(async (cs) => {
      const draft = view === "raw" ? fromRaw() : doc;
      if (!draft) return;
      const body = { ...draft, group: groupOf(draft) };
      setBusy(true);
      setErrors([]);
      setBanner(null);
      try {
        const res = isNew
          ? await api.post<Resource>(`/${kind}?changeset=${cs}`, editable(body))
          : await api.put<Resource>(`/${kind}/${id}?changeset=${cs}`, editable(body));
        toast(`${meta.one[0]!.toUpperCase()}${meta.one.slice(1)} saved`, `In change set ${cs}`);
        app.refresh();
        if (isNew) void navigate({ to: "/$kind/$id", params: { kind, id: res.id } });
      } catch (e) {
        setErrors(e instanceof APIError ? e.fields : []);
        setBanner(e);
      } finally {
        setBusy(false);
      }
    });

  const remove = () =>
    app.withChangeSet(async (cs) => {
      setBusy(true);
      try {
        await api.del(`/${kind}/${id}?changeset=${cs}`);
        toast(`${doc?.name} deleted`, `In change set ${cs}`);
        app.refresh();
        void navigate({ to: "/$kind", params: { kind } });
      } catch (e) {
        toastError(e);
      } finally {
        setBusy(false);
        setDeleting(false);
      }
    });

  const crumbs = [{ label: meta.label, to: `/${kind}` }];
  if (loaded.error) {
    return (
      <div className="stack">
        <PageHeader crumbs={crumbs} title={id} />
        <ErrorBanner error={loaded.error} />
      </div>
    );
  }
  if (!doc || !app.schema) return <Loading />;
  const def = app.schema["x-kinds"][kind];
  const nameErr = errors.find((e) => e.path === "name")?.message;

  return (
    <div className="stack">
      <PageHeader
        crumbs={[...crumbs, { label: isNew ? "New" : doc.name ?? id }]}
        title={isNew ? `New ${meta.one}` : doc.name}
        sub={isNew ? "Saved into the active change set; nothing is served until it is applied." : <><span className="mono">{doc.id}</span> · version {doc.resourceVersion}</>}
      >
        <Tabs tabs={[{ id: "form", label: "Form" }, { id: "raw", label: "Raw JSON" }]} value={view} onChange={switchView} />
      </PageHeader>
      <ErrorBanner error={banner} />
      {kind === "sites" && !isNew && <SiteRoutes site={doc} refs={refs.data} />}
      <Card title="General">
        <div className="grid grid--2">
          <Field id="res-name" label="Name" error={nameErr}>
            <input id="res-name" className={"input" + (nameErr ? " input--error" : "")} value={doc.name ?? ""} disabled={!canEdit} onChange={(e) => setDoc({ ...doc, name: e.target.value })} />
          </Field>
          <Field id="res-desc" label="Description">
            <input id="res-desc" className="input" value={doc.description ?? ""} disabled={!canEdit} onChange={(e) => setDoc({ ...doc, description: e.target.value || undefined })} />
          </Field>
          <Field id="res-group" label="Group" error={errors.find((e) => e.path === "group")?.message}
            hint="Members of the group and its parents get their group role on this resource.">
            <select id="res-group" className="input" value={groupOf(doc) ?? ""} disabled={!canEdit} onChange={(e) => setDoc({ ...doc, group: e.target.value || undefined })}>
              {(app.can("editor") || !groupOf(doc)) && <option value="">No group</option>}
              {(groups.data?.items ?? []).filter((g) => g.id === doc.group || writable.includes(g)).map((g) => <option key={g.id} value={g.id}>{g.name}</option>)}
            </select>
          </Field>
        </div>
        <div className="setting-row mt">
          <div className="setting-row__text">
            <div className="setting-row__title">Enabled</div>
            <div className="muted small">Disabled resources stay stored but are left out of the served configuration.</div>
          </div>
          <button type="button" className="toggle" role="switch" aria-label="Enabled" disabled={!canEdit} aria-checked={doc.enabled !== false}
            onClick={() => setDoc({ ...doc, enabled: doc.enabled === false ? undefined : false })} />
        </div>
      </Card>
      {kind === "lookups" && canEdit && view === "form" && <LookupImport spec={doc.spec ?? {}} onChange={(spec) => setDoc({ ...doc, spec })} />}
      <Card title="Specification">
        {view === "form" ? (
          <fieldset className="fieldset-plain" disabled={!canEdit}>
            {def && <SchemaForm root={app.schema} def={def} value={doc.spec ?? {}} refs={refs.data ?? {}} errors={errors} onChange={(spec) => setDoc({ ...doc, spec })} />}
          </fieldset>
        ) : (
          <>
            <textarea className="code" aria-label="Resource JSON" spellCheck={false} readOnly={!canEdit} value={raw} onChange={(e) => setRaw(e.target.value)} />
            {errors.length > 0 && (
              <ul className="stack mt">
                {errors.map((e) => <li key={e.path} className="field__error"><span className="mono">{e.path}</span>: {e.message}</li>)}
              </ul>
            )}
          </>
        )}
      </Card>
      {canEdit && (
        <div className="row row--between">
          {!isNew ? <button className="btn btn--danger-text" disabled={busy} onClick={() => setDeleting(true)}>Delete {meta.one}</button> : <span />}
          <div className="row">
            <Link className="btn" to="/$kind" params={{ kind }}>Cancel</Link>
            <button className="btn btn--primary" disabled={busy} onClick={save}>{isNew ? "Create" : "Save to change set"}</button>
          </div>
        </div>
      )}
      {deleting && <DeleteDialog what={meta.one} name={doc.name ?? ""} busy={busy} onConfirm={remove} onClose={() => setDeleting(false)} />}
    </div>
  );
}

interface RouteSpec {
  match?: { path: { type: string; value: string }; methods?: string[]; headers?: unknown[]; query?: unknown[]; expr?: string };
  action?: { type: string };
  children?: string[];
}

const MATCH_ORDER: Record<string, number> = { exact: 0, prefixPriority: 1, prefix: 1, regex: 2, regexCI: 2 };

function hasCond(m: RouteSpec["match"]): boolean {
  return !!m && (!!m.methods?.length || !!m.headers?.length || !!m.query?.length || !!m.expr);
}

// SiteRoutes shows a site's route tree with nginx match badges, in the
// order nginx checks them.
function SiteRoutes({ site, refs }: { site: Draft; refs: Refs | undefined }) {
  const byID = new Map((refs?.routes ?? []).map((r) => [r.id, r]));
  const order = (id: string) => MATCH_ORDER[(byID.get(id)?.spec as RouteSpec | undefined)?.match?.path.type ?? ""] ?? 3;
  const ids: string[] = [...(site.spec?.routes ?? [])].sort((a, b) => order(a) - order(b));
  const rows = (list: string[] | undefined, depth: number): ReactNode[] =>
    (list ?? []).flatMap((rid) => {
      const r = byID.get(rid);
      const spec = (r?.spec ?? {}) as RouteSpec;
      return [
        <tr key={`${rid}-${depth}`}>
          <td style={{ paddingLeft: 12 + depth * 20 }}>
            {r ? <Link to="/$kind/$id" params={{ kind: "routes", id: rid }}>{r.name}</Link> : <span className="danger-text">{rid} (missing)</span>}
          </td>
          <td>{spec.match && <span className="badge badge--outline mono">{PATH_SIGN[spec.match.path.type]}</span>}</td>
          <td className="mono">{spec.match?.path.value}</td>
          <td className="muted">{spec.action?.type}{hasCond(spec.match) ? " · conditional" : ""}</td>
        </tr>,
        ...rows(spec.children, depth + 1),
      ];
    });
  return (
    <Card title="Route tree" flush>
      {ids.length === 0 ? (
        <div className="card__body muted">No routes. Add route IDs under Routes in the specification below.</div>
      ) : (
        <div className="data-table-wrap">
          <table className="data-table">
            <thead><tr><th>Route</th><th>Match</th><th>Path</th><th>Action</th></tr></thead>
            <tbody>{rows(ids, 0)}</tbody>
          </table>
        </div>
      )}
    </Card>
  );
}

// Columns of each lookup table type, in CSV order.
const LOOKUP_COLUMNS: Record<string, { list: string; cols: string[] }> = {
  map: { list: "entries", cols: ["key", "value", "match"] },
  geo: { list: "entries", cols: ["network", "value"] },
  split: { list: "buckets", cols: ["percent", "value"] },
};

// parseCSV reads RFC 4180 CSV: quoted fields may hold commas, quotes ("")
// and line breaks.
export function parseCSV(text: string): string[][] {
  const rows: string[][] = [];
  let row: string[] = [];
  let f = "";
  let quoted = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i]!;
    if (quoted) {
      if (c === '"' && text[i + 1] === '"') { f += '"'; i++; }
      else if (c === '"') quoted = false;
      else f += c;
    } else if (c === '"' && f === "") quoted = true;
    else if (c === ",") { row.push(f); f = ""; }
    else if (c === "\n" || c === "\r") {
      if (c === "\r" && text[i + 1] === "\n") i++;
      row.push(f); f = "";
      if (row.some((x) => x !== "")) rows.push(row);
      row = [];
    } else f += c;
  }
  row.push(f);
  if (row.some((x) => x !== "")) rows.push(row);
  return rows;
}

// LookupImport replaces or extends a lookup table's rows from CSV. A first
// row naming the columns sets their order.
function LookupImport({ spec, onChange }: { spec: Record<string, any>; onChange: (spec: Record<string, any>) => void }) {
  const [text, setText] = useState("");
  const [append, setAppend] = useState(false);
  const t = LOOKUP_COLUMNS[spec.type as string];
  if (!t) return null;
  const run = () => {
    const rows = parseCSV(text);
    let cols = t.cols;
    if (rows[0] && rows[0].every((h) => t.cols.includes(h.trim()))) cols = rows.shift()!.map((h) => h.trim());
    const items = rows.map((r) => Object.fromEntries(cols.flatMap((c, i) => (r[i] ? [[c, r[i]]] : []))));
    const table = spec[spec.type] ?? {};
    onChange({ ...spec, [spec.type]: { ...table, [t.list]: [...(append ? table[t.list] ?? [] : []), ...items] } });
    toast(`Imported ${items.length} row${items.length === 1 ? "" : "s"}`);
    setText("");
  };
  return (
    <Card title="Import CSV">
      <div className="stack">
        <Field id="lookup-csv" label="Rows" hint={`Columns: ${t.cols.join(", ")}. A header row may name them in another order.`}>
          <textarea id="lookup-csv" className="input mono" rows={5} value={text} onChange={(e) => setText(e.target.value)} spellCheck={false} />
        </Field>
        <div className="row">
          <label className="row small">
            <input type="checkbox" checked={append} onChange={(e) => setAppend(e.target.checked)} /> Append to existing rows
          </label>
          <span className="grow" />
          <button type="button" className="btn btn--sm" disabled={!text.trim()} onClick={run}>Import</button>
        </div>
      </div>
    </Card>
  );
}
