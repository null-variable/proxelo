import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../api/client";
import type { Items } from "../api/types";
import { useApp } from "../app/context";
import { DeleteDialog, Empty, ErrorBanner, Loading, PageHeader, fmtTime, toast, toastError } from "../components/ui";

interface WasmModule {
  sha256: string;
  name: string;
  size: number;
  createdAt: string;
}

function size(n: number): string {
  if (n >= 1 << 20) return `${(n / (1 << 20)).toFixed(1)} MiB`;
  if (n >= 1 << 10) return `${(n / (1 << 10)).toFixed(1)} KiB`;
  return `${n} B`;
}

export function Wasm() {
  const app = useApp();
  const qc = useQueryClient();
  const list = useQuery({ queryKey: ["wasm"], queryFn: () => api.get<Items<WasmModule>>("/wasm") });
  const [removing, setRemoving] = useState<WasmModule | null>(null);
  const upload = useMutation({
    mutationFn: (f: File) => api.post<WasmModule>(`/wasm?name=${encodeURIComponent(f.name)}`, f, { contentType: "application/wasm" }),
    onSuccess: (m) => {
      toast("Module uploaded", m.sha256);
      void qc.invalidateQueries({ queryKey: ["wasm"] });
    },
    onError: toastError,
  });
  const remove = useMutation({
    mutationFn: (m: WasmModule) => api.del(`/wasm/${m.sha256}`),
    onSuccess: () => {
      setRemoving(null);
      void qc.invalidateQueries({ queryKey: ["wasm"] });
    },
    onError: toastError,
  });
  const editor = app.can("editor");
  const items = list.data?.items ?? [];
  return (
    <div className="stack">
      <PageHeader title="WASM modules" sub="proxy-wasm plugins, such as the Coraza WAF. wasm and waf policies refer to a module by its SHA-256.">
        {editor && (
          <label className="btn btn--primary">
            {upload.isPending ? "Uploading…" : "Upload module"}
            <input type="file" accept=".wasm" className="sr-only" aria-label="WebAssembly module" disabled={upload.isPending} onChange={(e) => {
              const f = e.target.files?.[0];
              e.target.value = "";
              if (f) upload.mutate(f);
            }} />
          </label>
        )}
      </PageHeader>
      <ErrorBanner error={list.error} />
      {list.isPending ? <Loading /> : items.length === 0 ? <Empty title="No module uploaded" /> : (
        <div className="data-table-wrap">
          <table className="data-table">
            <thead><tr><th>Name</th><th>SHA-256</th><th>Size</th><th>Uploaded</th>{editor && <th />}</tr></thead>
            <tbody>
              {items.map((m) => (
                <tr key={m.sha256}>
                  <td>{m.name}</td>
                  <td className="mono small">{m.sha256}</td>
                  <td className="nowrap">{size(m.size)}</td>
                  <td className="muted nowrap">{fmtTime(m.createdAt)}</td>
                  {editor && <td><button className="btn btn--danger-text btn--sm" onClick={() => setRemoving(m)}>Delete</button></td>}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {removing && <DeleteDialog what="module" name={removing.name} busy={remove.isPending} onConfirm={() => remove.mutate(removing)} onClose={() => setRemoving(null)} />}
    </div>
  );
}
