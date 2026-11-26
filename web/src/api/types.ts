// Shapes of the control plane API (internal/api, internal/store).
import type { FieldError } from "./client";

export type Role = "viewer" | "editor" | "operator" | "admin" | "owner";

export const ROLE_RANK: Record<Role, number> = { viewer: 0, editor: 1, operator: 2, admin: 3, owner: 4 };
export const ROLES = Object.keys(ROLE_RANK) as Role[];

export interface User {
  id: string;
  name: string;
  role: Role;
  totpEnabled: boolean;
  createdAt: string;
}

export interface Me {
  user: User;
  role: Role;
  via: "session" | "token";
  csrfToken?: string;
}

export interface Token {
  id: string;
  user: string;
  name: string;
  role: Role;
  cidrs?: string[];
  expiresAt: string;
  createdAt: string;
  lastUsed?: string;
}

export interface AuditEntry {
  seq: number;
  at: string;
  actor: string;
  action: string;
  target: string;
}

// A resource as the API returns it; spec depends on the kind.
export interface Resource {
  id: string;
  name: string;
  description?: string;
  labels?: Record<string, string>;
  enabled?: boolean;
  resourceVersion: number;
  createdAt: string;
  updatedAt: string;
  spec: any;
}

export type Kind = "sites" | "routes" | "listeners" | "upstreams" | "certificates" | "policies";

export const KINDS: Record<Kind, { label: string; one: string }> = {
  sites: { label: "Sites", one: "site" },
  routes: { label: "Routes", one: "route" },
  listeners: { label: "Listeners", one: "listener" },
  upstreams: { label: "Upstreams", one: "upstream" },
  certificates: { label: "Certificates", one: "certificate" },
  policies: { label: "Policies", one: "policy" },
};

export function isKind(s: string): s is Kind {
  return s in KINDS;
}

// Starter bodies for new resources.
export const TEMPLATES: Record<Kind, Partial<Resource>> = {
  listeners: { name: "http", spec: { address: "0.0.0.0:80" } },
  sites: { name: "example", spec: { listeners: [], hostnames: [{ type: "exact", value: "example.com" }], routes: [] } },
  routes: {
    name: "root",
    spec: { match: { path: { type: "prefix", value: "/" } }, action: { type: "return", return: { status: 200, text: "ok" } } },
  },
  upstreams: { name: "backend", spec: { targets: [{ address: "192.0.2.10:8080" }], keepalive: {} } },
  certificates: { name: "example-com", spec: { source: "acme", domains: ["example.com"] } },
  policies: {
    name: "security-headers",
    spec: { type: "headers", headers: { response: { set: { "Strict-Transport-Security": "max-age=31536000" } } } },
  },
};

export type ItemOp = "create" | "update" | "delete";

export interface ChangeSet {
  id: string;
  author: string;
  message: string;
  baseRevision: number;
  createdAt: string;
  updatedAt: string;
  items: { kind: string; id: string; op: ItemOp }[];
}

export interface Change {
  path: string;
  old?: unknown;
  new?: unknown;
}

export interface ResourceDiff {
  kind: Kind;
  id: string;
  name: string;
  op: ItemOp;
  drifted?: boolean;
  changes?: Change[];
}

export interface EffectiveDiff {
  kind: string;
  id: string;
  op: "added" | "removed" | "changed";
  changes?: Change[];
}

export interface DiffResult {
  resources: ResourceDiff[];
  effective?: EffectiveDiff[];
  errors?: FieldError[];
}

export interface Finding {
  path: string;
  message: string;
  level: "warning" | "safety";
}

export interface Validation {
  valid: boolean;
  errors?: FieldError[];
  warnings?: Finding[];
}

export type RevisionStatus = "pending" | "confirmed" | "reverted";

export interface Revision {
  revision: number;
  createdAt: string;
  author: string;
  message: string;
  hash: string;
  status: RevisionStatus;
  confirmBy?: string;
  tag?: string;
  guard?: string;
}

export interface NodeStatus {
  nodeId: string;
  proxyVersion: string;
  connectedAt: string;
  activeRevision: number;
  sentRevision: number;
  failedRevision?: number;
  error?: string;
}

export interface Traffic {
  requests: number;
  serverErrors: number;
  upstreamAttempts: number;
  upstreamFailures: number;
}

export interface Header {
  name: string;
  value: string;
}

export interface SimResult {
  kind?: string;
  status?: number;
  site?: string;
  route?: string;
  uri?: string;
  location?: string;
  body?: string;
  file?: string;
  upstream?: string;
  targets?: string[];
  trace?: string[];
  responseHeaders?: Header[];
  requestHeaders?: Header[];
}

export interface SimRun {
  revision?: number;
  changeset?: string;
  error?: string;
  results: SimResult[];
}

export interface Items<T> {
  items: T[];
}
