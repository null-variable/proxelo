// The resource JSON Schema served at /api/v1/schema, generated from
// internal/model by schemagen.go.
import type { Kind } from "../api/types";

export interface Schema {
  type?: "object" | "array" | "string" | "integer" | "boolean";
  $ref?: string;
  description?: string;
  format?: string;
  enum?: string[];
  minimum?: number;
  properties?: Record<string, Schema>;
  "x-order"?: string[];
  required?: string[];
  items?: Schema;
  additionalProperties?: Schema;
  "x-nullable"?: boolean;
  "x-ref"?: Kind;
  readOnly?: boolean;
}

export interface RootSchema {
  $defs: Record<string, Schema>;
  "x-kinds": Record<Kind, string>;
}

// resolve follows $ref, keeping the referring property's own keywords.
export function resolve(root: RootSchema, s: Schema): Schema {
  let out = s;
  while (out.$ref) {
    const { $ref, ...rest } = out;
    const target = root.$defs[$ref.slice("#/$defs/".length)];
    if (!target) throw new Error(`schema: unknown ${$ref}`);
    out = { ...target, ...rest };
  }
  return out;
}

// Variant objects (Action, PolicySpec) have a "type" enum with one object
// property per value; only the selected one is shown and kept.
export function variants(s: Schema): string[] | null {
  const t = s.properties?.type;
  if (!t?.enum) return null;
  const opts = t.enum.filter((v) => s.properties?.[v]);
  return opts.length === t.enum.length ? opts : null;
}

// Words the generated labels spell in capitals.
const ACRONYMS: Record<string, string> = {
  tls: "TLS", http2: "HTTP/2", http: "HTTP", https: "HTTPS", uri: "URI", url: "URL", pem: "PEM", acme: "ACME", cidrs: "CIDRs", dns: "DNS", json: "JSON", ip: "IP", id: "ID",
};

export function label(name: string): string {
  return name
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .split(" ")
    .map((w, i) => ACRONYMS[w.toLowerCase()] ?? (i === 0 ? w[0]!.toUpperCase() + w.slice(1) : w.toLowerCase()))
    .join(" ");
}

export function isEmpty(v: unknown): boolean {
  if (v === undefined || v === null || v === "") return true;
  if (Array.isArray(v)) return v.length === 0;
  return typeof v === "object" && Object.keys(v as object).length === 0;
}
