// Shared components built on the console style classes.
import { useEffect, useRef, useState, type ReactNode } from "react";
import { Link } from "@tanstack/react-router";
import { errorText } from "../api/client";
import type { RevisionStatus } from "../api/types";

export interface Crumb {
  label: string;
  to?: string;
}

export function PageHeader({ crumbs, title, sub, children }: { crumbs?: Crumb[]; title: ReactNode; sub?: ReactNode; children?: ReactNode }) {
  return (
    <div>
      {crumbs && (
        <nav className="breadcrumbs" aria-label="Breadcrumb">
          {crumbs.map((c, i) => (
            <span key={i} className="row" style={{ display: "contents" }}>
              {i > 0 && <span aria-hidden="true">/</span>}
              {c.to ? <Link to={c.to}>{c.label}</Link> : <span>{c.label}</span>}
            </span>
          ))}
        </nav>
      )}
      <div className="page-header">
        <div className="grow">
          <h1 className="page-title">{title}</h1>
          {sub && <p className="page-sub">{sub}</p>}
        </div>
        {children && <div className="page-actions">{children}</div>}
      </div>
    </div>
  );
}

export function Card({ title, actions, flush, children }: { title?: ReactNode; actions?: ReactNode; flush?: boolean; children: ReactNode }) {
  return (
    <section className="card">
      {title && (
        <div className="card__head">
          <h2>{title}</h2>
          {actions && <div className="row">{actions}</div>}
        </div>
      )}
      <div className={"card__body" + (flush ? " card__body--flush" : "")}>{children}</div>
    </section>
  );
}

export function Empty({ title, text, children }: { title: string; text?: string; children?: ReactNode }) {
  return (
    <div className="empty">
      <div className="empty__icon" aria-hidden="true" />
      <div className="empty__title">{title}</div>
      {text && <p className="empty__text">{text}</p>}
      {children}
    </div>
  );
}

export function Loading() {
  return (
    <div className="stack" aria-busy="true" aria-label="Loading">
      <span className="placeholder-bar" style={{ width: "40%" }} />
      <span className="placeholder-bar" style={{ width: "70%" }} />
      <span className="placeholder-bar" style={{ width: "55%" }} />
    </div>
  );
}

export function ErrorBanner({ error }: { error: unknown }) {
  if (!error) return null;
  return (
    <div className="banner banner--danger" role="alert">
      <div style={{ whiteSpace: "pre-wrap" }}>{errorText(error)}</div>
    </div>
  );
}

export type Tone = "success" | "warning" | "danger" | "info" | "";

// Badge with text; the dot repeats the state for scanning, never alone.
export function Status({ tone, children }: { tone: Tone; children: ReactNode }) {
  const dot = tone === "warning" ? " status-dot--warning" : tone === "danger" ? " status-dot--danger" : "";
  return (
    <span className={"badge" + (tone ? ` badge--${tone}` : "")}>
      {tone && tone !== "info" && <span className={"status-dot" + dot} aria-hidden="true" />}
      {children}
    </span>
  );
}

export function revisionTone(s: RevisionStatus): Tone {
  return s === "pending" ? "warning" : s === "confirmed" ? "success" : "danger";
}

export function Dialog({
  title, text, onClose, wide, children, actions,
}: { title: string; text?: ReactNode; onClose: () => void; wide?: boolean; children?: ReactNode; actions?: ReactNode }) {
  const ref = useRef<HTMLDivElement>(null);
  const close = useRef(onClose);
  close.current = onClose;
  useEffect(() => {
    const prev = document.activeElement as HTMLElement | null;
    ref.current?.querySelector<HTMLElement>("input,textarea,select,button")?.focus();
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && close.current();
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("keydown", onKey);
      prev?.focus();
    };
  }, []);
  return (
    <div className="overlay" onClick={(e) => e.target === e.currentTarget && onClose()}>
      <div className={"dialog" + (wide ? " dialog--wide" : "")} role="dialog" aria-modal="true" aria-label={title} ref={ref}>
        <h2 className="dialog__title">{title}</h2>
        {text && <p className="dialog__text">{text}</p>}
        {children}
        {actions && <div className="dialog__actions">{actions}</div>}
      </div>
    </div>
  );
}

// DeleteDialog asks for the resource name before a destructive action.
export function DeleteDialog({ what, name, busy, onConfirm, onClose }: { what: string; name: string; busy: boolean; onConfirm: () => void; onClose: () => void }) {
  const [typed, setTyped] = useState("");
  return (
    <Dialog
      title={`Delete ${what}`}
      text={<>This removes <b>{name}</b> in the change set. Type its name to continue.</>}
      onClose={onClose}
      actions={
        <>
          <button className="btn" onClick={onClose}>Cancel</button>
          <button className="btn btn--destructive" disabled={typed !== name || busy} onClick={onConfirm}>Delete</button>
        </>
      }
    >
      <Field id="del-name" label="Name">
        <input id="del-name" className="input" value={typed} onChange={(e) => setTyped(e.target.value)} autoComplete="off" />
      </Field>
    </Dialog>
  );
}

export function Field({ id, label, hint, error, children }: { id: string; label: ReactNode; hint?: ReactNode; error?: string; children: ReactNode }) {
  return (
    <div className="field">
      <label className="field__label" htmlFor={id}>{label}</label>
      {children}
      {error ? <span className="field__error" role="alert">{error}</span> : hint && <span className="field__hint">{hint}</span>}
    </div>
  );
}

export function Toggle({ checked, onChange, label, disabled }: { checked: boolean; onChange: (v: boolean) => void; label: string; disabled?: boolean }) {
  return (
    <button type="button" className="toggle" role="switch" aria-checked={checked} aria-label={label} disabled={disabled} onClick={() => onChange(!checked)} />
  );
}

export function Tabs<T extends string>({ tabs, value, onChange, underline }: { tabs: { id: T; label: string }[]; value: T; onChange: (v: T) => void; underline?: boolean }) {
  return (
    <div className={"tabs" + (underline ? " tabs--underline" : "")} role="tablist">
      {tabs.map((t) => (
        <button key={t.id} type="button" className="tab" role="tab" aria-selected={value === t.id} onClick={() => onChange(t.id)}>
          {t.label}
        </button>
      ))}
    </div>
  );
}

export function SettingRow({ title, text, children }: { title: ReactNode; text: ReactNode; children: ReactNode }) {
  return (
    <div className="setting-row">
      <div className="setting-row__text">
        <div className="setting-row__title">{title}</div>
        <div className="muted small">{text}</div>
      </div>
      {children}
    </div>
  );
}

// ---- Toasts ----

interface ToastItem {
  id: number;
  title: string;
  text?: string;
  danger?: boolean;
}

let push: (t: ToastItem) => void = () => {};
let seq = 0;

export function toast(title: string, text?: string, danger?: boolean): void {
  push({ id: ++seq, title, text, danger });
}

export function toastError(e: unknown): void {
  toast("Request failed", errorText(e), true);
}

export function Toasts() {
  const [items, setItems] = useState<ToastItem[]>([]);
  useEffect(() => {
    push = (t) => {
      setItems((xs) => [...xs, t]);
      setTimeout(() => setItems((xs) => xs.filter((x) => x.id !== t.id)), 5000);
    };
    return () => {
      push = () => {};
    };
  }, []);
  return (
    <div className="toasts" aria-live="polite">
      {items.map((t) => (
        <div key={t.id} className={"toast" + (t.danger ? " toast--danger" : "")} role="status">
          <div>
            <div className="toast__title">{t.title}</div>
            {t.text && <div className="toast__text">{t.text}</div>}
          </div>
        </div>
      ))}
    </div>
  );
}

// ---- Formatting ----

function dur(d: number): string {
  if (d < 60) return `${Math.round(d)}s`;
  if (d < 3600) return `${Math.round(d / 60)}m`;
  if (d < 86400) return `${Math.round(d / 3600)}h`;
  return `${Math.round(d / 86400)}d`;
}

export function timeAgo(s?: string): string {
  if (!s) return "";
  const d = (Date.now() - new Date(s).getTime()) / 1000;
  if (d < 0) return "in " + dur(-d);
  if (d < 60) return "just now";
  return dur(d) + " ago";
}

export function fmtTime(s?: string): string {
  return s ? new Date(s).toLocaleString() : "";
}

// Hashes arrive base64-encoded.
export function shortHash(h: string): string {
  try {
    return Array.from(atob(h).slice(0, 6), (c) => c.charCodeAt(0).toString(16).padStart(2, "0")).join("");
  } catch {
    return h.slice(0, 12);
  }
}
