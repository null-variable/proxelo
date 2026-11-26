// Topology: the configuration as a request-flow diagram (listener → site →
// route → upstream → target). Members connect nodes by dragging one onto
// another or from the side panel; every edit lands in the active
// change set like a form save. The diagram exports as SVG, PNG, Mermaid,
// Graphviz DOT or JSON. With traffic on, edges thicken with recent requests
// and turn amber or red with the share of 5xx answers.
import { useEffect, useMemo, useRef, useState, type PointerEvent as ReactPointerEvent } from "react";
import { Link } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { api, requestText } from "../api/client";
import { KINDS, TEMPLATES, type Graph, type GraphNode, type Group, type Items, type Kind, type Resource, type TrafficCount } from "../api/types";
import { useApp } from "../app/context";
import { Card, Dialog, Empty, ErrorBanner, Field, Loading, PageHeader, toast, toastError } from "../components/ui";
import type { Refs } from "../form/SchemaForm";
import { useRefs } from "./Resources";

// Lookup tables are global variables and streams bypass the HTTP flow.
type Col = Exclude<Kind, "lookups" | "streams"> | "targets";
const COLS: Col[] = ["listeners", "sites", "routes", "upstreams", "targets"];
const COL_TITLE: Record<Col, string> = { listeners: "Listeners", sites: "Sites", routes: "Routes", upstreams: "Upstreams", targets: "Targets", certificates: "Certificates", policies: "Policies" };

const NODE_W = 184;
const NODE_H = 52;
const COL_GAP = 64;
const ROW_GAP = 14;
const PAD = 20;
const HEAD = 36;

function q(cs: string): string {
  return cs ? `?changeset=${cs}` : "";
}

// trafficClass maps a count to a width step (1–4, by order of magnitude
// relative to the busiest edge) and an error level.
function trafficClass(t: TrafficCount | undefined, max: number): string {
  if (!t || !t.requests || !max) return "";
  const step = Math.max(1, Math.min(4, 4 - Math.floor(Math.log10(max / t.requests))));
  const level = errorLevel(t);
  return ` topo__edge--w${step}` + (level ? ` topo__edge--${level}` : "");
}

function errorLevel(t: TrafficCount): "" | "warn" | "bad" {
  const share = t.requests ? t.errors / t.requests : 0;
  return share >= 0.05 ? "bad" : share >= 0.01 ? "warn" : "";
}

function compact(n: number): string {
  return n >= 1e6 ? (n / 1e6).toFixed(1) + "M" : n >= 1e3 ? (n / 1e3).toFixed(1) + "k" : String(n);
}

function trafficText(t: TrafficCount | undefined): string {
  if (!t?.requests) return "";
  const share = (t.errors / t.requests) * 100;
  return compact(t.requests) + (t.errors ? ` · ${share < 1 ? share.toFixed(1) : Math.round(share)}% err` : "");
}

function clip(s: string, n: number): string {
  return s.length > n ? s.slice(0, n - 1) + "…" : s;
}

// Display edges run in request order; a site stores its listeners, so that
// edge is turned around.
interface FlowEdge {
  from: string;
  to: string;
  field: string;
  traffic?: TrafficCount;
}

function flowEdges(g: Graph): FlowEdge[] {
  return g.edges.map((e) => (e.field === "spec.listeners" ? { ...e, from: e.to, to: e.from } : e));
}

interface Box {
  node: GraphNode;
  x: number;
  y: number;
}

// layout places each column's nodes in the order of their predecessors'
// rows (one barycenter pass), which keeps most edges from crossing.
function layout(nodes: GraphNode[], edges: FlowEdge[]): { boxes: Map<string, Box>; width: number; height: number } {
  const row = new Map<string, number>();
  const preds = new Map<string, string[]>();
  for (const e of edges) preds.set(e.to, [...(preds.get(e.to) ?? []), e.from]);
  const boxes = new Map<string, Box>();
  let rows = 0;
  COLS.forEach((col, ci) => {
    const ns = nodes.filter((n) => n.kind === col);
    const key = (n: GraphNode) => {
      const ps = (preds.get(n.id) ?? []).map((p) => row.get(p)).filter((r): r is number => r !== undefined);
      return ps.length ? ps.reduce((a, b) => a + b, 0) / ps.length : Infinity;
    };
    const keyed = ns.map((n, i) => ({ n, k: key(n), i }));
    keyed.sort((a, b) => a.k - b.k || a.i - b.i);
    keyed.forEach(({ n }, i) => {
      row.set(n.id, i);
      boxes.set(n.id, { node: n, x: PAD + ci * (NODE_W + COL_GAP), y: PAD + HEAD + i * (NODE_H + ROW_GAP) });
    });
    rows = Math.max(rows, ns.length);
  });
  return {
    boxes,
    width: PAD * 2 + COLS.length * NODE_W + (COLS.length - 1) * COL_GAP + 48,
    height: PAD * 2 + HEAD + Math.max(rows, 1) * (NODE_H + ROW_GAP),
  };
}

function edgePath(a: Box, b: Box): string {
  const y1 = a.y + NODE_H / 2;
  const y2 = b.y + NODE_H / 2;
  if (a.x === b.x) {
    // Child routes: loop on the right side of the column.
    const x = a.x + NODE_W;
    const bulge = 28 + Math.min(Math.abs(y2 - y1) / 6, 30);
    return `M${x},${y1} C${x + bulge},${y1} ${x + bulge},${y2} ${x},${y2}`;
  }
  const x1 = a.x + NODE_W;
  const x2 = b.x;
  const mid = (x1 + x2) / 2;
  return `M${x1},${y1} C${mid},${y1} ${mid},${y2} ${x2},${y2}`;
}

// ---- Edits ----

// A connection the diagram can make, and the resource it changes.
interface Link_ {
  from: GraphNode;
  to: GraphNode;
}

function linkable(from: GraphNode, to: GraphNode): boolean {
  if (from.id === to.id) return false;
  return (
    (from.kind === "listeners" && to.kind === "sites") ||
    (from.kind === "sites" && to.kind === "routes") ||
    (from.kind === "routes" && (to.kind === "routes" || to.kind === "upstreams"))
  );
}

// owner is the resource whose spec holds the reference.
function owner(l: Link_): GraphNode {
  return l.from.kind === "listeners" ? l.to : l.from;
}

function find(refs: Refs | undefined, n: GraphNode): Resource | undefined {
  return n.kind === "targets" ? undefined : refs?.[n.kind]?.find((r) => r.id === n.id);
}

function addID(list: string[] | undefined, id: string): string[] {
  return list?.includes(id) ? list : [...(list ?? []), id];
}

// isActionEdge: the route's action names this upstream; the form changes it.
function isActionEdge(field: string): boolean {
  return /^spec\.action\.(proxy|gateway|memcached|grpc)\.upstream$/.test(field);
}

// connectPatch is the merge patch that makes l.
function connectPatch(l: Link_, res: Resource): object {
  const s = res.spec ?? {};
  switch (`${l.from.kind}>${l.to.kind}`) {
    case "listeners>sites":
      return { spec: { listeners: addID(s.listeners, l.from.id) } };
    case "sites>routes":
      return { spec: { routes: addID(s.routes, l.to.id) } };
    case "routes>routes":
      return { spec: { children: addID(s.children, l.to.id) } };
    case "routes>upstreams": {
      // Keep a gateway, memcached or grpc action; anything else becomes proxy.
      const t = s.action?.type;
      const kind = t === "gateway" || t === "memcached" || t === "grpc" ? t : "proxy";
      return { spec: { action: { type: kind, static: null, return: null, [kind]: { ...(s.action?.[kind] ?? {}), upstream: l.to.id } } } };
    }
  }
  throw new Error("these nodes do not connect");
}

// disconnectPatch removes edge e, or explains why the form must do it.
function disconnectPatch(e: FlowEdge, res: Resource): object | string {
  const s = res.spec ?? {};
  const drop = (list: string[] | undefined, id: string) => (list ?? []).filter((x) => x !== id);
  switch (e.field) {
    case "spec.listeners":
      return drop(s.listeners, e.from).length ? { spec: { listeners: drop(s.listeners, e.from) } } : "A site needs at least one listener; connect another first.";
    case "spec.routes":
      return { spec: { routes: drop(s.routes, e.to) } };
    case "spec.children":
      return { spec: { children: drop(s.children, e.to) } };
    case "spec.action.proxy.upstream":
    case "spec.action.gateway.upstream":
    case "spec.action.memcached.upstream":
    case "spec.action.grpc.upstream":
      return "A proxy route needs an upstream; connect another upstream or change the action in the route's form.";
    case "spec.targets":
      return { spec: { targets: (s.targets ?? []).filter((_: unknown, i: number) => `${res.id}/${i}` !== e.to) } };
  }
  return "Edit this reference in the form.";
}

// The resource holding a displayed edge.
function edgeOwner(e: FlowEdge): string {
  return e.field === "spec.listeners" ? e.to : e.from;
}

// ---- Export ----

function download(name: string, type: string, data: BlobPart) {
  const url = URL.createObjectURL(new Blob([data], { type }));
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

const STYLE_PROPS = ["fill", "fill-opacity", "stroke", "stroke-width", "stroke-dasharray", "opacity", "font-family", "font-size", "font-weight"];

// standalone copies the diagram with computed styles written as SVG
// presentation attributes (the console's CSP forbids style attributes),
// without the editing handles, so it renders the same outside the console.
function standalone(svg: SVGSVGElement): string {
  const copy = svg.cloneNode(true) as SVGSVGElement;
  const live = svg.querySelectorAll<SVGElement>("*");
  copy.querySelectorAll<SVGElement>("*").forEach((el, i) => {
    const cs = getComputedStyle(live[i]!);
    for (const p of STYLE_PROPS) {
      const v = cs.getPropertyValue(p);
      if (v) el.setAttribute(p, v);
    }
    el.removeAttribute("class");
  });
  copy.querySelectorAll("[data-export=skip]").forEach((el) => el.remove());
  const bg = document.createElementNS("http://www.w3.org/2000/svg", "rect");
  bg.setAttribute("width", "100%");
  bg.setAttribute("height", "100%");
  bg.setAttribute("fill", getComputedStyle(svg).getPropertyValue("--px-canvas").trim() || "#fff");
  copy.insertBefore(bg, copy.firstChild);
  copy.setAttribute("xmlns", "http://www.w3.org/2000/svg");
  copy.removeAttribute("class");
  return new XMLSerializer().serializeToString(copy);
}

function png(svg: SVGSVGElement): Promise<Blob> {
  const src = standalone(svg);
  const w = svg.width.baseVal.value;
  const h = svg.height.baseVal.value;
  return new Promise((resolve, reject) => {
    const img = new Image();
    img.onload = () => {
      const c = document.createElement("canvas");
      c.width = w * 2;
      c.height = h * 2;
      const ctx = c.getContext("2d")!;
      ctx.scale(2, 2);
      ctx.drawImage(img, 0, 0);
      c.toBlob((b) => (b ? resolve(b) : reject(new Error("PNG export failed"))), "image/png");
    };
    img.onerror = () => reject(new Error("PNG export failed"));
    img.src = "data:image/svg+xml;charset=utf-8," + encodeURIComponent(src);
  });
}

// ---- Page ----

type Sel = { node: string } | { edge: number } | null;

export function Topology() {
  const app = useApp();
  const cs = app.changeset;
  // Traffic covers the running configuration, so it is off while a change
  // set is shown.
  const [traffic, setTraffic] = useState("");
  const win = cs ? "" : traffic;
  const graph = useQuery({
    queryKey: ["topology", cs, win],
    queryFn: () => api.get<Graph>(`/topology${q(cs)}${win ? (cs ? "&" : "?") + "traffic=" + win : ""}`),
    refetchInterval: win ? 10_000 : false,
  });
  const groups = useQuery({ queryKey: ["groups"], queryFn: () => api.get<Items<Group>>("/groups") });
  const refs = useRefs(cs);
  const [group, setGroup] = useState("*");
  const [sel, setSel] = useState<Sel>(null);
  const [adding, setAdding] = useState<Kind | null>(null);
  const [busy, setBusy] = useState(false);
  // A press on a node: a click selects it, a drag from a node that can
  // connect draws a line to drop on another node.
  const [drag, setDrag] = useState<{ from: string; x: number; y: number; sx: number; sy: number; moved: boolean } | null>(null);
  const svgRef = useRef<SVGSVGElement>(null);

  const view = useMemo(() => {
    const g = graph.data ?? { nodes: [], edges: [] };
    const nodes = g.nodes.filter((n) => (COLS as string[]).includes(n.kind) && (group === "*" || (n.group ?? "") === group));
    const ids = new Set(nodes.map((n) => n.id));
    const edges = flowEdges(g).filter((e) => ids.has(e.from) && ids.has(e.to));
    const max = Math.max(0, ...edges.map((e) => e.traffic?.requests ?? 0));
    return { nodes, edges, max, ...layout(nodes, edges) };
  }, [graph.data, group]);

  const groupName = (id?: string) => (id ? groups.data?.items.find((g) => g.id === id)?.name ?? id : "");
  const editable = (n: GraphNode) => n.kind !== "targets" && app.can("editor", n.group);

  // mutate sends a merge patch for node n into the active change set.
  const mutate = (n: GraphNode, patch: (res: Resource) => object | string, done: string) =>
    app.withChangeSet(async (id) => {
      const res = find(refs.data, n);
      if (!res) return;
      const p = patch(res);
      if (typeof p === "string") {
        toast("Not changed", p, true);
        return;
      }
      setBusy(true);
      try {
        await api.patch(`/${n.kind}/${n.id}?changeset=${id}`, p);
        toast(done, `In change set ${id}`);
        app.refresh();
      } catch (e) {
        toastError(e);
      } finally {
        setBusy(false);
      }
    });

  const connect = (from: GraphNode, to: GraphNode) => {
    const l = { from, to };
    if (!linkable(from, to)) return;
    const o = owner(l);
    if (!editable(o)) {
      toast("Not allowed", `You cannot edit ${o.name}.`, true);
      return;
    }
    if (view.edges.some((e) => e.from === from.id && e.to === to.id)) return;
    mutate(o, (res) => connectPatch(l, res), `Connected ${from.name} → ${to.name}`);
  };

  const disconnect = (e: FlowEdge) => {
    const o = view.boxes.get(edgeOwner(e))?.node;
    if (!o) return;
    mutate(o, (res) => disconnectPatch(e, res), "Connection removed");
    setSel(null);
  };

  const point = (ev: ReactPointerEvent) => {
    const svg = svgRef.current!;
    const m = svg.getScreenCTM()!.inverse();
    const p = new DOMPoint(ev.clientX, ev.clientY).matrixTransform(m);
    return { x: p.x, y: p.y };
  };
  const hit = (x: number, y: number) => [...view.boxes.values()].find((b) => x >= b.x && x <= b.x + NODE_W && y >= b.y && y <= b.y + NODE_H);

  const exportAs = async (format: "svg" | "png" | "mermaid" | "dot" | "json") => {
    try {
      const base = `proxelo-topology${cs ? "-" + cs : ""}`;
      if (format === "svg") download(base + ".svg", "image/svg+xml", standalone(svgRef.current!));
      else if (format === "png") download(base + ".png", "image/png", await png(svgRef.current!));
      else if (format === "json") download(base + ".json", "application/json", JSON.stringify(graph.data, null, 2));
      else download(base + (format === "dot" ? ".dot" : ".mmd"), "text/plain", await requestText(`/topology?format=${format}${cs ? "&changeset=" + cs : ""}`));
    } catch (e) {
      toastError(e);
    }
  };

  const selNode = sel && "node" in sel ? view.boxes.get(sel.node)?.node : undefined;
  const selEdge = sel && "edge" in sel ? view.edges[sel.edge] : undefined;
  const near = (id: string) => id === selNode?.id;
  const ownerEditable = (e: FlowEdge) => {
    const o = view.boxes.get(edgeOwner(e))?.node;
    return !!o && editable(o);
  };
  const lit = (e: FlowEdge) => !!selNode && (e.from === selNode.id || e.to === selNode.id);
  const dragFrom = drag?.moved ? view.boxes.get(drag.from)?.node : undefined;
  const dropOn = dragFrom ? hit(drag!.x, drag!.y) : undefined;
  const dropOK = !!dragFrom && !!dropOn && linkable(dragFrom, dropOn.node);
  // canStart: nodes with an outgoing kind of connection.
  const canStart = (n: GraphNode) => app.canAny("editor") && (n.kind === "listeners" || n.kind === "sites" || n.kind === "routes");
  useEffect(() => {
    if (!drag) return;
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && setDrag(null);
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [drag !== null]);
  const press = (n: GraphNode, ev: ReactPointerEvent) => {
    if (ev.button !== 0) return;
    ev.stopPropagation();
    svgRef.current?.setPointerCapture(ev.pointerId);
    const p = point(ev);
    setDrag({ from: n.id, ...p, sx: p.x, sy: p.y, moved: false });
  };

  return (
    <div className="stack">
      <PageHeader title="Topology" sub={cs ? <>Showing change set <span className="mono">{cs}</span>; edits go into it.</> : "The current configuration. Edits open a change set."}>
        <select className="input input--sm" aria-label="Group" value={group} onChange={(e) => { setGroup(e.target.value); setSel(null); }}>
          <option value="*">All groups</option>
          <option value="">Ungrouped</option>
          {(groups.data?.items ?? []).map((g) => <option key={g.id} value={g.id}>{g.name}</option>)}
        </select>
        {!cs && (
          <select className="input input--sm" aria-label="Traffic" value={traffic} onChange={(e) => setTraffic(e.target.value)}>
            <option value="">No traffic</option>
            <option value="1m">Traffic 1m</option>
            <option value="5m">Traffic 5m</option>
            <option value="15m">Traffic 15m</option>
          </select>
        )}
        <select className="input input--sm" aria-label="Export" value="" onChange={(e) => { void exportAs(e.target.value as "svg"); e.target.value = ""; }}>
          <option value="" disabled>Export…</option>
          <option value="svg">SVG image</option>
          <option value="png">PNG image</option>
          <option value="mermaid">Mermaid</option>
          <option value="dot">Graphviz DOT</option>
          <option value="json">JSON graph</option>
        </select>
      </PageHeader>
      <ErrorBanner error={graph.error} />
      {graph.isPending ? <Loading /> : view.nodes.length === 0 && group === "*" ? (
        <Empty title="Nothing configured yet" text="Add a listener to start.">
          {app.canAny("editor") && <button className="btn btn--primary" onClick={() => setAdding("listeners")}>Add listener</button>}
        </Empty>
      ) : (
        <div className="topo">
          <div className="card topo__canvas">
            <svg
              ref={svgRef}
              className="topo__svg"
              width={view.width}
              height={view.height}
              viewBox={`0 0 ${view.width} ${view.height}`}
              role="img"
              aria-label="Configuration topology"
              onPointerDown={(ev) => ev.target === ev.currentTarget && setSel(null)}
              onPointerMove={(ev) => {
                if (!drag) return;
                const p = point(ev);
                const from = view.boxes.get(drag.from)?.node;
                const moved = drag.moved || (!!from && canStart(from) && Math.hypot(p.x - drag.sx, p.y - drag.sy) > 5);
                setDrag({ ...drag, ...p, moved });
              }}
              onPointerUp={(ev) => {
                if (!drag) return;
                const p = point(ev);
                const from = view.boxes.get(drag.from)?.node;
                setDrag(null);
                if (!drag.moved) {
                  setSel({ node: drag.from });
                  return;
                }
                const to = hit(p.x, p.y)?.node;
                if (from && to && to.id !== from.id) {
                  if (linkable(from, to)) connect(from, to);
                  else toast("Not connected", `A ${KINDS[from.kind as Kind]?.one ?? from.kind} cannot connect to a ${KINDS[to.kind as Kind]?.one ?? to.kind}.`, true);
                }
              }}
              onPointerCancel={() => setDrag(null)}
            >
              <defs>
                <marker id="topo-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="8" markerHeight="8" markerUnits="userSpaceOnUse" orient="auto-start-reverse">
                  <path d="M0,0 L10,5 L0,10 z" className="topo__arrow" />
                </marker>
              </defs>
              {COLS.map((c, i) => {
                const x = PAD + i * (NODE_W + COL_GAP);
                const addable = c !== "targets" && app.canAny("editor");
                return (
                  <g key={c}>
                    <text className="topo__col" x={x} y={PAD + 14}>{COL_TITLE[c]}</text>
                    {addable && (
                      <g data-export="skip" className="topo__add" role="button" tabIndex={0} aria-label={`Add ${KINDS[c as Kind].one}`}
                        onClick={() => setAdding(c as Kind)} onKeyDown={(e) => e.key === "Enter" && setAdding(c as Kind)}>
                        <rect x={x + NODE_W - 24} y={PAD} width={24} height={20} rx={5} />
                        <text x={x + NODE_W - 12} y={PAD + 14} textAnchor="middle">+</text>
                      </g>
                    )}
                  </g>
                );
              })}
              {view.edges.map((e, i) => {
                const a = view.boxes.get(e.from)!;
                const b = view.boxes.get(e.to)!;
                const d = edgePath(a, b);
                const on = (sel && "edge" in sel && sel.edge === i) || lit(e);
                return (
                  <g key={`${e.from}-${e.to}-${e.field}`} onClick={() => setSel({ edge: i })}>
                    <path d={d} className="topo__hit" data-export="skip" />
                    <path d={d} className={"topo__edge" + trafficClass(e.traffic, view.max) + (on ? " topo__edge--on" : "")} markerEnd="url(#topo-arrow)">
                      {e.traffic && <title>{trafficText(e.traffic) || "no requests"}</title>}
                    </path>
                  </g>
                );
              })}
              {[...view.boxes.values()].map(({ node: n, x, y }) => (
                <g
                  key={n.id}
                  className={`topo__node topo__node--${n.kind}` + (near(n.id) ? " topo__node--sel" : "") + (n.disabled ? " topo__node--off" : "") + (n.down ? " topo__node--down" : "") +
                    (canStart(n) ? " topo__node--grab" : "") +
                    (dragFrom ? (linkable(dragFrom, n) ? " topo__node--target" : n.id === dragFrom.id ? "" : " topo__node--dim") : "") +
                    (dropOK && dropOn!.node.id === n.id ? " topo__node--drop" : "")}
                  transform={`translate(${x},${y})`}
                  role="button"
                  tabIndex={0}
                  aria-label={`${n.kind} ${n.name}`}
                  onPointerDown={(ev) => press(n, ev)}
                  onKeyDown={(e) => e.key === "Enter" && setSel({ node: n.id })}
                >
                  <title>{`${n.name}${n.detail ? "\n" + n.detail : ""}${n.group ? "\ngroup " + groupName(n.group) : ""}${n.health ? "\ndown: " + n.health : ""}`}</title>
                  <rect className="topo__box" width={NODE_W} height={NODE_H} rx={8} />
                  <rect className="topo__accent" width={4} height={NODE_H - 16} x={0} y={8} rx={2} />
                  <text className="topo__name" x={14} y={21}>{clip(n.name, 24)}</text>
                  <text className="topo__detail" x={14} y={39}>{clip(n.detail ?? "", n.traffic ? 16 : 30)}</text>
                  {n.traffic && <text className={"topo__traffic" + (errorLevel(n.traffic) ? ` topo__traffic--${errorLevel(n.traffic)}` : "")} x={NODE_W - 8} y={39} textAnchor="end">{trafficText(n.traffic)}</text>}
                  {n.group && group === "*" && <text className="topo__group" x={NODE_W - 8} y={21} textAnchor="end">{clip(groupName(n.group), 10)}</text>}
                  {canStart(n) && <circle data-export="skip" className="topo__handle" cx={NODE_W} cy={NODE_H / 2} r={7} aria-hidden="true" />}
                </g>
              ))}
              {dragFrom && (() => {
                const a = view.boxes.get(dragFrom.id)!;
                // Snap onto a valid target's input side.
                const d = dropOK ? edgePath(a, dropOn!) : `M${a.x + NODE_W},${a.y + NODE_H / 2} L${drag!.x},${drag!.y}`;
                return <path data-export="skip" className={"topo__edge topo__edge--drag" + (dropOK ? " topo__edge--ok" : "")} d={d} markerEnd={dropOK ? "url(#topo-arrow)" : undefined} />;
              })()}
            </svg>
          </div>
          <aside className="topo__panel">
            {selNode ? (
              <NodePanel node={selNode} view={view} refs={refs.data} groupName={groupName} editable={editable(selNode)} ownerEditable={ownerEditable} busy={busy}
                onConnect={connect} onDisconnect={disconnect} onAddTarget={(addr) => mutate(selNode, (res) => ({ spec: { targets: [...(res.spec?.targets ?? []), { address: addr }] } }), `Target ${addr} added`)}
                onPatch={(p, done) => mutate(selNode, p, done)} />
            ) : selEdge ? (
              <EdgePanel edge={selEdge} view={view} editable={ownerEditable(selEdge)} busy={busy} onDisconnect={disconnect} />
            ) : (
              <Card title="Diagram">
                <p className="muted small">Click a node or connection to select it. Drag a node onto another to connect them: listener → site, site → route, route → child route or upstream. Certificates and policies are attached from a site's or route's panel. Valid targets light up while dragging; Esc cancels.</p>
                <p className="muted small mt">Dashed nodes are disabled; red targets are down. Details are edited in each resource's form.</p>
                {win && <p className="muted small mt">Line width follows requests in the last {win}; amber lines answer 1% or more 5xx, red 5% or more.</p>}
              </Card>
            )}
          </aside>
        </div>
      )}
      {adding && <AddDialog kind={adding} groups={groups.data?.items ?? []} refs={refs.data} onClose={() => setAdding(null)} />}
    </div>
  );
}

interface View {
  nodes: GraphNode[];
  edges: FlowEdge[];
  max: number;
  boxes: Map<string, Box>;
}

function NodePanel({ node, view, refs, groupName, editable, ownerEditable, busy, onConnect, onDisconnect, onAddTarget, onPatch }: {
  node: GraphNode;
  view: View;
  refs: Refs | undefined;
  groupName: (id?: string) => string;
  editable: boolean;
  ownerEditable: (e: FlowEdge) => boolean;
  busy: boolean;
  onConnect: (from: GraphNode, to: GraphNode) => void;
  onDisconnect: (e: FlowEdge) => void;
  onAddTarget: (address: string) => void;
  onPatch: (patch: (res: Resource) => object | string, done: string) => void;
}) {
  const [target, setTarget] = useState("");
  const [addr, setAddr] = useState("");
  const out = view.edges.filter((e) => e.from === node.id);
  const inc = view.edges.filter((e) => e.to === node.id);
  const options = view.nodes.filter((n) => linkable(node, n) && !out.some((e) => e.to === n.id));
  const name = (id: string) => view.boxes.get(id)?.node.name ?? id;
  const res = find(refs, node);
  const upstreamID = node.kind === "targets" ? node.id.slice(0, node.id.lastIndexOf("/")) : "";
  // Certificates (sites) and policies (sites, routes) are attached here;
  // they sit outside the request flow, so the canvas leaves them out.
  const [attach, setAttach] = useState("");
  const slots: ("certificates" | "policies")[] = node.kind === "sites" ? ["certificates", "policies"] : node.kind === "routes" ? ["policies"] : [];
  const attached = slots.flatMap((k) => ((res?.spec?.[k] ?? []) as string[]).map((id) => ({ k, id, name: refs?.[k]?.find((r) => r.id === id)?.name ?? id })));
  const attachable = slots.flatMap((k) => (refs?.[k] ?? []).filter((r) => !attached.some((a) => a.id === r.id)).map((r) => ({ k, r })));
  const setList = (k: "certificates" | "policies", ids: string[], done: string) => onPatch(() => ({ spec: { [k]: ids } }), done);
  return (
    <Card title={node.name} actions={node.kind !== "targets"
      ? <Link className="btn btn--sm" to="/$kind/$id" params={{ kind: node.kind, id: node.id }}>Open form</Link>
      : <Link className="btn btn--sm" to="/$kind/$id" params={{ kind: "upstreams", id: upstreamID }}>Open upstream</Link>}>
      <div className="stack">
        <div className="muted small">{KINDS[node.kind as Kind]?.one ?? "target"}{node.group ? ` · group ${groupName(node.group)}` : ""}{node.disabled ? " · disabled" : ""}{node.down ? " · down" : ""}</div>
        {node.health && <div className="banner banner--danger small">{node.health}</div>}
        {node.detail && <div className="mono small">{node.detail}</div>}
        {attached.length > 0 && (
          <ul className="topo__links">
            {attached.map((a) => (
              <li key={a.id}>
                <span className="grow">{KINDS[a.k].one} {a.name}</span>
                {editable && <button className="btn btn--ghost btn--sm" disabled={busy}
                  onClick={() => setList(a.k, ((res?.spec?.[a.k] ?? []) as string[]).filter((x) => x !== a.id), `${KINDS[a.k].one} ${a.name} detached`)}>Detach</button>}
              </li>
            ))}
          </ul>
        )}
        {editable && attachable.length > 0 && (
          <div className="row">
            <select className="input input--sm grow" aria-label="Attach" value={attach} onChange={(e) => setAttach(e.target.value)}>
              <option value="">Attach…</option>
              {attachable.map(({ k, r }) => <option key={r.id} value={r.id}>{KINDS[k].one} {r.name}</option>)}
            </select>
            <button className="btn btn--sm" disabled={!attach || busy} onClick={() => {
              const a = attachable.find((x) => x.r.id === attach);
              if (a) setList(a.k, [...((res?.spec?.[a.k] ?? []) as string[]), a.r.id], `${KINDS[a.k].one} ${a.r.name} attached`);
              setAttach("");
            }}>Attach</button>
          </div>
        )}
        {inc.length + out.length > 0 && (
          <ul className="topo__links">
            {[...inc, ...out].map((e) => (
              <li key={`${e.from}-${e.to}-${e.field}`}>
                <span className="grow">{e.from === node.id ? `→ ${name(e.to)}` : `← ${name(e.from)}`}</span>
                {!isActionEdge(e.field) && ownerEditable(e) && <button className="btn btn--ghost btn--sm" disabled={busy} onClick={() => onDisconnect(e)}>Remove</button>}
              </li>
            ))}
          </ul>
        )}
        {editable && options.length > 0 && (
          <div className="row">
            <select className="input input--sm grow" aria-label="Connect to" value={target} onChange={(e) => setTarget(e.target.value)}>
              <option value="">Connect to…</option>
              {options.map((n) => <option key={n.id} value={n.id}>{KINDS[n.kind as Kind].one} {n.name}</option>)}
            </select>
            <button className="btn btn--sm" disabled={!target || busy} onClick={() => { const to = view.boxes.get(target)?.node; if (to) onConnect(node, to); setTarget(""); }}>Connect</button>
          </div>
        )}
        {editable && node.kind === "upstreams" && (
          <form className="row" onSubmit={(e) => { e.preventDefault(); if (addr) onAddTarget(addr); setAddr(""); }}>
            <input className="input input--sm grow mono" aria-label="Target address" placeholder="10.0.0.5:8080" value={addr} onChange={(e) => setAddr(e.target.value)} />
            <button className="btn btn--sm" disabled={!addr || busy}>Add target</button>
          </form>
        )}
      </div>
    </Card>
  );
}

function EdgePanel({ edge, view, editable, busy, onDisconnect }: { edge: FlowEdge; view: View; editable: boolean; busy: boolean; onDisconnect: (e: FlowEdge) => void }) {
  const a = view.boxes.get(edge.from)!.node;
  const b = view.boxes.get(edge.to)!.node;
  return (
    <Card title="Connection">
      <div className="stack">
        <div>{a.name} → {b.name}</div>
        <div className="muted small mono">{edge.field}</div>
        {editable && !isActionEdge(edge.field) && (
          <div><button className="btn btn--danger-text btn--sm" disabled={busy} onClick={() => onDisconnect(edge)}>Remove connection</button></div>
        )}
        {isActionEdge(edge.field) && <p className="muted small">Connect the route to another upstream to replace this one, or change its action in the form.</p>}
      </div>
    </Card>
  );
}

// AddDialog creates a resource with the one field the diagram needs.
function AddDialog({ kind, groups, refs, onClose }: { kind: Kind; groups: Group[]; refs: Refs | undefined; onClose: () => void }) {
  const app = useApp();
  const writable = groups.filter((g) => app.can("editor", g.id));
  const [name, setName] = useState("");
  const [value, setValue] = useState("");
  const [group, setGroup] = useState(app.can("editor") ? "" : writable[0]?.id ?? "");
  const [listener, setListener] = useState(refs?.listeners?.[0]?.id ?? "");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<unknown>(null);
  const field: Partial<Record<Kind, { label: string; placeholder: string }>> = {
    listeners: { label: "Address", placeholder: "0.0.0.0:80" },
    sites: { label: "Hostname", placeholder: "example.com" },
    routes: { label: "Path prefix", placeholder: "/" },
    upstreams: { label: "Target address", placeholder: "10.0.0.5:8080" },
  };
  const f = field[kind];

  const body = (): Partial<Resource> => {
    const t = structuredClone(TEMPLATES[kind]);
    const spec = t.spec ?? {};
    switch (kind) {
      case "listeners": spec.address = value; break;
      case "sites": spec.hostnames = value ? [{ type: "exact", value }] : []; spec.listeners = listener ? [listener] : []; break;
      case "routes": spec.match = { path: { type: "prefix", value: value || "/" } }; break;
      case "upstreams": spec.targets = [{ address: value }]; break;
    }
    return { ...t, name, ...(group ? { group } : {}), spec };
  };

  const submit = () =>
    app.withChangeSet(async (cs) => {
      setBusy(true);
      setErr(null);
      try {
        await api.post(`/${kind}?changeset=${cs}`, body());
        toast(`${KINDS[kind].one} ${name} added`, `In change set ${cs}`);
        app.refresh();
        onClose();
      } catch (e) {
        setErr(e);
      } finally {
        setBusy(false);
      }
    });

  return (
    <Dialog title={`Add ${KINDS[kind].one}`} onClose={onClose}>
      <form className="stack" onSubmit={(e) => { e.preventDefault(); submit(); }}>
        <ErrorBanner error={err} />
        <Field id="add-name" label="Name">
          <input id="add-name" className="input" value={name} onChange={(e) => setName(e.target.value)} required />
        </Field>
        {f && (
          <Field id="add-value" label={f.label}>
            <input id="add-value" className="input mono" placeholder={f.placeholder} value={value} onChange={(e) => setValue(e.target.value)} required={kind !== "routes"} />
          </Field>
        )}
        {kind === "sites" && (
          <Field id="add-lst" label="Listener">
            <select id="add-lst" className="input" value={listener} onChange={(e) => setListener(e.target.value)}>
              {(refs?.listeners ?? []).map((l) => <option key={l.id} value={l.id}>{l.name} ({l.spec?.address})</option>)}
            </select>
          </Field>
        )}
        {(writable.length > 0) && (
          <Field id="add-group" label="Group">
            <select id="add-group" className="input" value={group} onChange={(e) => setGroup(e.target.value)}>
              {app.can("editor") && <option value="">No group</option>}
              {writable.map((g) => <option key={g.id} value={g.id}>{g.name}</option>)}
            </select>
          </Field>
        )}
        <div className="dialog__actions">
          <button type="button" className="btn" onClick={onClose}>Cancel</button>
          <button className="btn btn--primary" disabled={busy}>Add</button>
        </div>
      </form>
    </Dialog>
  );
}
