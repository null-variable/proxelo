// Console state shared by every page: the session, the resource schema, the
// active change set (edits always go to a draft) and the
// revision waiting for confirmation.
import { createContext, useContext, useState, type ReactNode } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../api/client";
import { ROLE_RANK, type ChangeSet, type Items, type Me, type Revision, type Role } from "../api/types";
import type { RootSchema } from "../form/schema";

const CS_KEY = "proxelo.changeset";

export interface AppState {
  me: Me;
  schema: RootSchema | undefined;
  changeset: string;
  changesets: ChangeSet[];
  pending: Revision | undefined;
  setChangeSet: (id: string) => void;
  can: (role: Role) => boolean;
  // Runs fn with the active change set, asking to open one first.
  withChangeSet: (fn: (cs: string) => void) => void;
  // Invalidates every query after a write.
  refresh: () => void;
  logout: () => void;
}

const Ctx = createContext<AppState | null>(null);

export function useApp(): AppState {
  const a = useContext(Ctx);
  if (!a) throw new Error("useApp outside AppProvider");
  return a;
}

export function AppProvider({ me, onLogout, askChangeSet, children }: { me: Me; onLogout: () => void; askChangeSet: (then: (cs: string) => void) => void; children: ReactNode }) {
  const qc = useQueryClient();
  const [changeset, setCS] = useState(() => localStorage.getItem(CS_KEY) ?? "");
  const schema = useQuery({ queryKey: ["schema"], queryFn: () => api.get<RootSchema>("/schema"), staleTime: Infinity });
  const css = useQuery({ queryKey: ["changesets"], queryFn: () => api.get<Items<ChangeSet>>("/changesets") });
  const revs = useQuery({
    queryKey: ["revisions"],
    queryFn: () => api.get<Items<Revision>>("/revisions"),
    // A pending revision has a deadline; keep its banner current.
    refetchInterval: (q) => (q.state.data?.items.some((r) => r.status === "pending") ? 5000 : false),
  });

  const setChangeSet = (id: string) => {
    setCS(id);
    if (id) localStorage.setItem(CS_KEY, id);
    else localStorage.removeItem(CS_KEY);
  };
  const list = css.data?.items ?? [];
  // The stored change set may have been applied or discarded elsewhere.
  const active = css.data && changeset && !list.some((c) => c.id === changeset) ? "" : changeset;

  const state: AppState = {
    me,
    schema: schema.data,
    changeset: active,
    changesets: list,
    pending: revs.data?.items.find((r) => r.status === "pending"),
    setChangeSet,
    can: (role) => ROLE_RANK[me.role] >= ROLE_RANK[role],
    withChangeSet: (fn) => (active ? fn(active) : askChangeSet((id) => {
      setChangeSet(id);
      void qc.invalidateQueries();
      fn(id);
    })),
    refresh: () => void qc.invalidateQueries(),
    logout: onLogout,
  };
  return <Ctx.Provider value={state}>{children}</Ctx.Provider>;
}
