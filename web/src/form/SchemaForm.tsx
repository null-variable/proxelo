// SchemaForm renders a resource spec from the JSON Schema.
// Values stay plain JSON; unset optional fields are omitted rather than sent
// as zero values. Server field errors ("spec.match.path.value") appear at
// their field.
import { useId } from "react";
import type { FieldError } from "../api/client";
import type { Kind, Resource } from "../api/types";
import { Toggle } from "../components/ui";
import { isEmpty, label, resolve, variants, type RootSchema, type Schema } from "./schema";

type JSONValue = unknown;
type Obj = Record<string, JSONValue>;
export type Refs = Partial<Record<Kind, Resource[]>>;

interface Ctx {
  root: RootSchema;
  refs: Refs;
  errors: FieldError[];
}

function errorAt(errors: FieldError[], path: string): string | undefined {
  return errors.find((e) => e.path === path)?.message;
}

export function SchemaForm({ root, def, value, onChange, refs, errors }: { root: RootSchema; def: string; value: Obj; onChange: (v: Obj) => void; refs: Refs; errors: FieldError[] }) {
  const s = root.$defs[def];
  if (!s) return <p className="danger-text">Unknown schema {def}</p>;
  return <ObjectFields ctx={{ root, refs, errors }} s={s} value={value ?? {}} onChange={onChange} path="spec" />;
}

function ObjectFields({ ctx, s, value, onChange, path }: { ctx: Ctx; s: Schema; value: Obj; onChange: (v: Obj) => void; path: string }) {
  if (!s.properties) return <MapField ctx={ctx} s={s} value={value} onChange={onChange} path={path} />;
  const props = s.properties;
  const vs = variants(s);
  const keys = (s["x-order"] ?? Object.keys(props)).filter((k) => !vs || k === "type" || k === value.type);
  const req = new Set(s.required ?? []);
  const set = (k: string, v: JSONValue) => {
    if (vs && k === "type") {
      // Switching variant drops the old variant's settings.
      const t = v as string;
      onChange(t ? { type: t, [t]: value[t] ?? {} } : {});
      return;
    }
    const out = { ...value };
    if (isEmpty(v) && !req.has(k)) delete out[k];
    else out[k] = v;
    onChange(out);
  };
  return (
    <div className="stack">
      {keys.map((k) => (
        <Prop key={k} ctx={ctx} name={k} s={props[k]!} value={value[k]} onChange={(v) => set(k, v)} path={`${path}.${k}`} required={req.has(k)} />
      ))}
    </div>
  );
}

function Prop({ ctx, name, s, value, onChange, path, required }: { ctx: Ctx; name: string; s: Schema; value: JSONValue; onChange: (v: JSONValue) => void; path: string; required: boolean }) {
  const id = useId();
  const r = resolve(ctx.root, s);
  const err = errorAt(ctx.errors, path);
  const desc = s.description ?? r.description;
  const title = label(name);

  if (r.readOnly) {
    if (isEmpty(value)) return null;
    return (
      <div className="field">
        <span className="field__label">{title}</span>
        <pre className="code code--sm">{JSON.stringify(value, null, 2)}</pre>
      </div>
    );
  }

  if (r.type === "object" && r.properties) {
    const nullable = !!s["x-nullable"];
    const on = value !== undefined && value !== null;
    return (
      <fieldset className="card">
        <div className="card__head">
          <h2 className="small">{title}</h2>
          {nullable && <Toggle checked={on} label={`Set ${title}`} onChange={(v) => onChange(v ? {} : undefined)} />}
        </div>
        {(on || !nullable) && (
          <div className="card__body">
            {desc && <p className="field__hint" style={{ marginBottom: 12 }}>{desc}</p>}
            <ObjectFields ctx={ctx} s={r} value={(value as Obj) ?? {}} onChange={onChange} path={path} />
          </div>
        )}
        {err && <div className="card__body"><span className="field__error" role="alert">{err}</span></div>}
      </fieldset>
    );
  }

  if (r.type === "object") {
    return (
      <div className="field">
        <span className="field__label">{title}</span>
        <MapField ctx={ctx} s={r} value={(value as Obj) ?? {}} onChange={onChange} path={path} />
        {desc && <span className="field__hint">{desc}</span>}
      </div>
    );
  }

  if (r.type === "array") {
    return <ArrayField ctx={ctx} title={title} desc={desc} s={r} value={(value as JSONValue[]) ?? []} onChange={onChange} path={path} err={err} />;
  }

  return (
    <div className="field">
      <label className="field__label" htmlFor={id}>
        {title}
        {!required && <span className="muted"> (optional)</span>}
      </label>
      <Scalar id={id} ctx={ctx} s={r} value={value} onChange={onChange} err={err} nullable={!!s["x-nullable"]} label={title} />
      {err ? <span className="field__error" role="alert">{err}</span> : desc && <span className="field__hint">{desc}</span>}
    </div>
  );
}

function Scalar({ id, ctx, s, value, onChange, err, nullable, label: name }: { id: string; ctx: Ctx; s: Schema; value: JSONValue; onChange: (v: JSONValue) => void; err?: string; nullable?: boolean; label: string }) {
  const cls = "input" + (err ? " input--error" : "");
  const kind = s["x-ref"];
  if (kind) {
    const v = (value as string) ?? "";
    const opts = (ctx.refs[kind] ?? []).map((r) => ({ v: r.id, l: `${r.name} (${r.id})` }));
    if (v && !opts.some((o) => o.v === v)) opts.push({ v, l: `${v} (missing)` });
    return (
      <select id={id} className={cls} value={v} onChange={(e) => onChange(e.target.value)} aria-invalid={!!err}>
        <option value="">None</option>
        {opts.map((o) => <option key={o.v} value={o.v}>{o.l}</option>)}
      </select>
    );
  }
  if (s.enum) {
    return (
      <select id={id} className={cls} value={(value as string) ?? ""} onChange={(e) => onChange(e.target.value)} aria-invalid={!!err}>
        {!s.enum.includes("") && <option value="">Default</option>}
        {s.enum.map((v) => <option key={v} value={v}>{v || "(none)"}</option>)}
      </select>
    );
  }
  if (s.type === "boolean") {
    if (nullable) {
      // Three states: unset, on, off.
      const v = value === true ? "true" : value === false ? "false" : "";
      return (
        <select id={id} className={cls} value={v} onChange={(e) => onChange(e.target.value === "" ? undefined : e.target.value === "true")}>
          <option value="">Default</option>
          <option value="true">On</option>
          <option value="false">Off</option>
        </select>
      );
    }
    return <div><Toggle checked={!!value} label={name} onChange={onChange} /></div>;
  }
  if (s.type === "integer") {
    return (
      <input id={id} className={cls} type="number" min={s.minimum} step={1} value={(value as number) ?? ""}
        onChange={(e) => onChange(e.target.value === "" ? undefined : Number(e.target.value))} aria-invalid={!!err} />
    );
  }
  return (
    <input id={id} className={cls} value={(value as string) ?? ""} onChange={(e) => onChange(e.target.value)}
      autoComplete="off" spellCheck={false} aria-invalid={!!err} />
  );
}

function ArrayField({ ctx, title, desc, s, value, onChange, path, err }: { ctx: Ctx; title: string; desc?: string; s: Schema; value: JSONValue[]; onChange: (v: JSONValue[]) => void; path: string; err?: string }) {
  const id = useId();
  const item = resolve(ctx.root, s.items ?? { type: "string" });
  const simple = item.type !== "object";
  const set = (i: number, v: JSONValue) => onChange(value.map((x, j) => (j === i ? v : x)));
  const move = (i: number, d: number) => {
    const n = value.slice();
    [n[i], n[i + d]] = [n[i + d], n[i]];
    onChange(n);
  };
  const blank = item.type === "object" ? {} : item.type === "integer" ? 0 : "";
  return (
    <div className="field">
      <span className="field__label" id={id}>{title}</span>
      <div className="stack" role="group" aria-labelledby={id}>
        {value.map((v, i) => {
          const sub = `${path}[${i}]`;
          const controls = (
            <div className="row">
              <button type="button" className="btn btn--ghost btn--sm" disabled={i === 0} onClick={() => move(i, -1)} aria-label="Move up">↑</button>
              <button type="button" className="btn btn--ghost btn--sm" disabled={i === value.length - 1} onClick={() => move(i, 1)} aria-label="Move down">↓</button>
              <button type="button" className="btn btn--danger-text btn--sm" onClick={() => onChange(value.filter((_, j) => j !== i))}>Remove</button>
            </div>
          );
          return simple ? (
            <div className="row" key={i}>
              <div className="grow">
                <Scalar id={`${id}-${i}`} ctx={ctx} s={item} value={v} onChange={(x) => set(i, x)} err={errorAt(ctx.errors, sub)} label={`${title} ${i + 1}`} />
              </div>
              {controls}
            </div>
          ) : (
            <div className="card" key={i}>
              <div className="card__body stack">
                <ObjectFields ctx={ctx} s={item} value={(v as Obj) ?? {}} onChange={(x) => set(i, x)} path={sub} />
                {controls}
              </div>
            </div>
          );
        })}
        <div>
          <button type="button" className="btn btn--sm" onClick={() => onChange([...value, blank])}>Add</button>
        </div>
      </div>
      {err ? <span className="field__error" role="alert">{err}</span> : desc && <span className="field__hint">{desc}</span>}
    </div>
  );
}

function MapField({ ctx, s, value, onChange, path }: { ctx: Ctx; s: Schema; value: Obj; onChange: (v: Obj) => void; path: string }) {
  const id = useId();
  const entries = Object.entries(value ?? {});
  const val = resolve(ctx.root, s.additionalProperties ?? { type: "string" });
  const update = (list: [string, JSONValue][]) => onChange(Object.fromEntries(list));
  return (
    <div className="stack">
      {entries.map(([k, v], i) => (
        <div className="row" key={i}>
          <input className="input grow" aria-label="Key" value={k} onChange={(e) => update(entries.map((x, j) => (j === i ? [e.target.value, x[1]] : x)))} />
          <div className="grow">
            <Scalar id={`${id}-${i}`} ctx={ctx} s={val} value={v} onChange={(x) => update(entries.map((y, j) => (j === i ? [y[0], x] : y)))} err={errorAt(ctx.errors, `${path}.${k}`)} label={`Value of ${k}`} />
          </div>
          <button type="button" className="btn btn--danger-text btn--sm" onClick={() => update(entries.filter((_, j) => j !== i))}>Remove</button>
        </div>
      ))}
      <div>
        <button type="button" className="btn btn--sm" onClick={() => update([...entries, ["", ""]])}>Add</button>
      </div>
    </div>
  );
}
