// Login and first-owner setup.
import { useState, type FormEvent, type ReactNode } from "react";
import { api, APIError, setCSRF } from "../api/client";
import { ErrorBanner, Field, Logo, Toasts } from "../components/ui";

function AuthCard({ title, sub, children }: { title: string; sub?: string; children: ReactNode }) {
  return (
    <div className="auth">
      <div className="auth__brand"><Logo size={24} />Proxelo</div>
      <div className="auth__card">
        <h1 className="auth__title">{title}</h1>
        {sub && <p className="muted">{sub}</p>}
        {children}
      </div>
      <Toasts />
    </div>
  );
}

async function login(name: string, password: string, code?: string): Promise<void> {
  const out = await api.post<{ csrfToken: string }>("/auth/login", { name, password, code: code || undefined }, { quiet: true });
  setCSRF(out.csrfToken);
}

export function Login({ onDone }: { onDone: () => void }) {
  const [f, setF] = useState({ name: "", password: "", code: "" });
  const [needCode, setNeedCode] = useState(false);
  const [err, setErr] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setErr(null);
    try {
      await login(f.name, f.password, f.code);
      onDone();
    } catch (e2) {
      if (e2 instanceof APIError && e2.code === "totp_required") setNeedCode(true);
      else setErr(e2);
      setBusy(false);
    }
  };
  return (
    <AuthCard title="Log in">
      <form className="stack" onSubmit={submit}>
        <ErrorBanner error={err} />
        <Field id="li-n" label="User name">
          <input id="li-n" className="input" autoComplete="username" value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} required />
        </Field>
        <Field id="li-p" label="Password">
          <input id="li-p" className="input" type="password" autoComplete="current-password" value={f.password} onChange={(e) => setF({ ...f, password: e.target.value })} required />
        </Field>
        {needCode && (
          <Field id="li-c" label="Authentication code" hint="From your authenticator app.">
            <input id="li-c" className="input mono" inputMode="numeric" autoComplete="one-time-code" pattern="[0-9]{6}" value={f.code} onChange={(e) => setF({ ...f, code: e.target.value })} required />
          </Field>
        )}
        <button className="btn btn--primary btn--block" disabled={busy}>Log in</button>
        <p className="muted small">Locked out? Run <span className="mono">proxelo admin reset-password</span> on the control host.</p>
      </form>
    </AuthCard>
  );
}

export function Setup({ onDone }: { onDone: () => void }) {
  const [f, setF] = useState({ token: "", name: "", password: "" });
  const [err, setErr] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setErr(null);
    try {
      await api.post("/auth/setup", f, { quiet: true });
      await login(f.name, f.password);
      onDone();
    } catch (e2) {
      setErr(e2);
      setBusy(false);
    }
  };
  return (
    <AuthCard title="Create the owner account" sub="Use the one-time setup token printed when proxelo first started.">
      <form className="stack" onSubmit={submit}>
        <ErrorBanner error={err} />
        <Field id="su-t" label="Setup token">
          <input id="su-t" className="input mono" autoComplete="off" value={f.token} onChange={(e) => setF({ ...f, token: e.target.value })} required />
        </Field>
        <Field id="su-n" label="User name">
          <input id="su-n" className="input" autoComplete="username" value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} required />
        </Field>
        <Field id="su-p" label="Password" hint="At least 12 characters.">
          <input id="su-p" className="input" type="password" autoComplete="new-password" minLength={12} value={f.password} onChange={(e) => setF({ ...f, password: e.target.value })} required />
        </Field>
        <button className="btn btn--primary btn--block" disabled={busy}>Create account</button>
      </form>
    </AuthCard>
  );
}
