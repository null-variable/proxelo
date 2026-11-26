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

// The Proxelo mark, drawn in the current text color.
export function Logo({ size = 20 }: { size?: number }) {
  return (
    <svg className="logo-mark" width={size} height={size} viewBox="0 0 2756 2756" fill="currentColor" aria-hidden="true">
      <path transform="translate(86 2756) scale(1 -1)" d="M1365 2716 c-50 -3 -102 -19 -148 -46 -6 -3 -30 -17 -54 -30 -24 -13 -44 -25 -44 -25 -1 0 -10 -5 -20 -11 -11 -6 -26 -14 -34 -19 -9 -5 -22 -12 -29 -16 -21 -11 -60 -33 -78 -43 -9 -5 -23 -13 -32 -18 -10 -5 -25 -13 -33 -19 -9 -5 -21 -11 -27 -15 -7 -3 -19 -10 -29 -15 -10 -6 -24 -14 -32 -18 -19 -10 -44 -25 -84 -47 -17 -9 -39 -21 -49 -27 -10 -6 -34 -19 -52 -29 -18 -11 -47 -27 -63 -36 -16 -9 -33 -19 -38 -21 -4 -2 -17 -9 -28 -16 -11 -6 -24 -13 -29 -16 -5 -3 -15 -9 -24 -13 -9 -5 -27 -15 -40 -23 -28 -15 -56 -31 -83 -46 -17 -10 -29 -18 -33 -24 -2 -3 -2 -3 -1 -5 2 -4 5 -5 16 -7 11 -2 599 -2 618 0 31 4 35 6 142 58 21 11 59 30 85 43 26 12 61 29 78 38 17 8 31 15 32 15 0 0 12 6 27 13 49 25 68 30 100 30 34 0 53 -5 94 -28 36 -21 67 -37 80 -44 7 -4 20 -11 29 -16 9 -6 30 -17 46 -26 15 -8 33 -18 40 -22 6 -3 24 -13 41 -22 16 -9 39 -22 50 -28 11 -6 31 -18 45 -25 13 -7 30 -17 39 -21 8 -5 19 -11 26 -14 6 -4 17 -10 26 -15 14 -8 42 -24 83 -46 11 -6 27 -15 36 -19 8 -5 19 -11 25 -14 5 -3 17 -10 27 -15 9 -5 25 -14 36 -20 37 -20 52 -33 65 -58 8 -15 8 -8 7 -156 l0 -131 -3 -2 -2 -2 -228 0 c-126 0 -234 0 -240 1 -44 3 -84 13 -130 34 -46 19 -116 65 -168 110 -4 3 -10 8 -13 11 -4 3 -14 11 -22 17 -8 7 -17 14 -20 17 -2 2 -11 9 -20 16 -19 15 -52 39 -73 54 -92 60 -194 88 -306 85 -11 -1 -163 -1 -339 -2 -304 -1 -321 -1 -328 -2 -22 -6 -31 -11 -45 -28 -5 -6 -14 -16 -20 -22 -5 -6 -16 -19 -25 -28 -8 -10 -18 -22 -23 -27 -6 -6 -14 -15 -20 -22 -25 -28 -62 -68 -81 -88 -17 -17 -18 -17 -16 -20 1 -1 15 -6 25 -9 6 -1 42 -1 432 -2 309 0 430 -1 441 -2 56 -4 82 -9 125 -22 65 -20 87 -31 231 -117 85 -51 145 -77 208 -93 43 -11 69 -15 114 -17 31 -2 880 -3 892 -1 14 2 22 8 26 19 l3 6 0 230 c0 254 0 239 -7 271 -14 70 -56 137 -112 180 -12 9 -32 21 -71 44 -17 9 -38 22 -47 27 -9 5 -26 15 -37 22 -11 6 -28 16 -36 21 -9 5 -26 15 -37 21 -12 7 -32 19 -45 27 -13 7 -30 17 -38 22 -8 5 -25 15 -38 23 -14 7 -37 21 -51 30 -15 8 -37 21 -49 28 -13 8 -28 17 -35 21 -8 4 -22 12 -32 19 -32 18 -66 38 -79 46 -8 4 -23 13 -35 20 -36 22 -47 28 -69 41 -11 6 -26 15 -33 19 -7 4 -19 11 -26 15 -8 5 -30 18 -50 29 -73 44 -86 51 -111 62 -44 19 -101 29 -146 26z M904 1528 c-11 0 -153 -1 -315 -1 -289 0 -295 0 -306 -2 -26 -4 -32 -9 -70 -54 -5 -6 -11 -14 -15 -17 -4 -4 -12 -14 -18 -21 -24 -27 -33 -37 -45 -49 -6 -8 -14 -16 -16 -18 -6 -7 -35 -39 -56 -61 -20 -20 -20 -21 -18 -23 4 -2 31 -2 485 -2 l458 0 16 2 c40 5 84 20 145 50 20 9 50 24 68 31 24 12 82 33 103 38 16 4 16 5 -8 12 -33 10 -81 28 -117 45 -29 14 -30 14 -49 23 -63 29 -96 39 -138 45 -18 2 -69 3 -104 2z M1647 1365 c-47 -2 -89 -8 -139 -20 -51 -13 -118 -43 -176 -77 -12 -7 -26 -15 -32 -18 -6 -4 -18 -11 -28 -17 -120 -72 -186 -100 -262 -112 -28 -4 -36 -5 -67 -7 -32 -2 -42 -2 -361 -3 -251 0 -329 0 -331 -1 l-2 -2 -1 -200 c0 -110 0 -201 0 -202 1 -3 5 -3 25 5 10 3 25 9 35 13 10 3 23 8 29 10 6 2 21 8 32 13 11 4 27 11 35 14 22 9 32 14 76 36 53 27 81 37 121 47 70 18 118 22 255 20 146 -1 164 0 212 9 84 17 158 51 236 110 23 18 61 48 71 57 3 3 12 9 18 15 7 5 17 13 23 18 35 28 47 38 75 56 69 45 126 67 195 75 17 2 18 2 251 3 l233 0 1 -2 c2 -2 2 -8 2 -86 0 -48 0 -88 -1 -93 -4 -32 -24 -66 -51 -86 -8 -6 -13 -9 -45 -26 -13 -6 -35 -18 -50 -26 -16 -8 -42 -22 -58 -31 -17 -8 -40 -21 -52 -27 -12 -6 -27 -14 -33 -17 -6 -4 -21 -11 -32 -18 -12 -6 -25 -13 -30 -16 -5 -2 -22 -11 -37 -19 -15 -9 -31 -17 -34 -19 -9 -4 -31 -16 -54 -28 -35 -19 -57 -31 -73 -39 -16 -8 -27 -15 -83 -45 -10 -5 -29 -15 -42 -22 -13 -7 -24 -13 -25 -14 -2 0 -14 -7 -29 -15 -71 -37 -78 -41 -96 -61 -23 -24 -37 -51 -45 -85 l-2 -9 -1 -191 c0 -175 0 -190 2 -191 2 -2 2 -2 17 6 6 4 19 11 29 16 9 5 21 12 27 16 12 7 42 24 68 38 10 6 23 13 29 17 6 4 22 12 35 19 12 8 28 16 34 20 6 4 19 11 27 15 9 5 23 13 33 19 17 10 44 25 69 39 7 4 19 11 27 16 8 4 23 13 34 19 11 6 28 16 38 21 9 6 23 14 31 18 8 5 21 12 29 17 16 9 62 35 75 42 4 3 21 13 37 21 16 9 36 21 46 27 10 5 31 17 48 27 17 10 36 20 42 24 15 8 52 29 68 38 29 18 35 21 46 27 6 3 16 9 23 13 7 4 23 13 35 20 12 7 28 16 36 20 7 4 22 13 34 20 41 23 55 31 63 35 4 3 13 8 19 11 47 27 87 70 114 124 17 34 26 63 31 105 2 15 2 18 3 230 0 235 0 221 -6 231 -3 5 -11 10 -19 12 -4 1 -854 2 -877 1z" />
    </svg>
  );
}
