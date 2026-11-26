// Client for /api/v1. Sessions use the HttpOnly cookie; writes carry the
// session's CSRF token.

let csrf = "";

export function setCSRF(token: string | undefined): void {
  csrf = token ?? "";
}

export interface FieldError {
  path: string;
  message: string;
}

interface ErrorBody {
  error?: string;
  code?: string;
  fields?: FieldError[];
}

export class APIError extends Error {
  readonly status: number;
  readonly code: string | undefined;
  readonly fields: FieldError[];

  constructor(status: number, body: ErrorBody | null) {
    super(body?.error ?? `HTTP ${status}`);
    this.status = status;
    this.code = body?.code;
    this.fields = body?.fields ?? [];
  }
}

let onUnauthorized: () => void = () => {};

// The app returns to the login page on 401.
export function setUnauthorizedHandler(fn: () => void): void {
  onUnauthorized = fn;
}

interface Options {
  // Do not treat 401 as a lost session (login, probing /auth/me).
  quiet?: boolean;
  contentType?: string;
}

async function send(method: string, path: string, body: unknown, opts: Options): Promise<Response> {
  const headers: Record<string, string> = {};
  if (method !== "GET" && csrf) headers["X-CSRF-Token"] = csrf;
  let payload: string | Blob | undefined;
  if (body instanceof Blob) {
    payload = body;
    headers["Content-Type"] = opts.contentType ?? "application/octet-stream";
  } else if (typeof body === "string") {
    payload = body;
    headers["Content-Type"] = opts.contentType ?? "application/yaml";
  } else if (body !== undefined) {
    payload = JSON.stringify(body);
    headers["Content-Type"] = "application/json";
  }
  return fetch("/api/v1" + path, { method, headers, body: payload, credentials: "same-origin" });
}

export async function request<T>(method: string, path: string, body?: unknown, opts: Options = {}): Promise<T> {
  const res = await send(method, path, body, opts);
  const text = await res.text();
  let data: unknown = null;
  if (text) {
    try {
      data = JSON.parse(text);
    } catch {
      data = { error: text };
    }
  }
  if (!res.ok) {
    if (res.status === 401 && !opts.quiet) onUnauthorized();
    throw new APIError(res.status, data as ErrorBody | null);
  }
  return data as T;
}

export async function requestText(path: string): Promise<string> {
  const res = await send("GET", path, undefined, {});
  if (!res.ok) throw new APIError(res.status, null);
  return res.text();
}

export const api = {
  get: <T>(path: string, opts?: Options) => request<T>("GET", path, undefined, opts),
  post: <T>(path: string, body: unknown = {}, opts?: Options) => request<T>("POST", path, body, opts),
  put: <T>(path: string, body: unknown) => request<T>("PUT", path, body),
  patch: <T>(path: string, body: unknown) => request<T>("PATCH", path, body),
  del: (path: string) => request<null>("DELETE", path),
};

export function errorText(e: unknown): string {
  if (e instanceof APIError && e.fields.length) return e.fields.map((f) => `${f.path}: ${f.message}`).join("\n");
  if (e instanceof Error) return e.message;
  return String(e);
}
