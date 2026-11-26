// Console entry: resolves the session, then mounts the router inside the
// app state. Logged out, it shows setup (first start) or login.
import { StrictMode, useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import { QueryClient, QueryClientProvider, useQuery, useQueryClient } from "@tanstack/react-query";
import { RouterProvider } from "@tanstack/react-router";
import { api, setCSRF, setUnauthorizedHandler } from "./api/client";
import type { Me } from "./api/types";
import { AppProvider } from "./app/context";
import { router } from "./app/router";
import { Loading } from "./components/ui";
import { Login, Setup, type AuthStatus } from "./pages/Auth";
import { NewChangeSet } from "./pages/Changes";
import "./styles/main.scss";

const queryClient = new QueryClient({
  defaultOptions: { queries: { retry: false, refetchOnWindowFocus: true, staleTime: 2000 } },
});

function Root() {
  const qc = useQueryClient();
  const me = useQuery({
    queryKey: ["me"],
    queryFn: async () => {
      try {
        const m = await api.get<Me>("/auth/me", { quiet: true });
        setCSRF(m.csrfToken);
        return m;
      } catch {
        return null;
      }
    },
    staleTime: Infinity,
  });
  const status = useQuery({
    queryKey: ["auth-status"],
    queryFn: () => api.get<AuthStatus>("/auth/status"),
    enabled: me.data === null,
  });
  const [ask, setAsk] = useState<((cs: string) => void) | null>(null);

  useEffect(() => {
    setUnauthorizedHandler(() => {
      setCSRF("");
      qc.setQueryData(["me"], null);
    });
  }, [qc]);

  const signedIn = () => {
    // Drop data cached for the previous user, then load the new session.
    qc.removeQueries({ predicate: (q) => q.queryKey[0] !== "me" && q.queryKey[0] !== "auth-status" });
    void qc.refetchQueries({ queryKey: ["me"] });
  };
  const logout = async () => {
    try {
      await api.post("/auth/logout");
    } finally {
      setCSRF("");
      qc.removeQueries({ predicate: (q) => q.queryKey[0] !== "me" });
      qc.setQueryData(["me"], null);
      void router.navigate({ to: "/" });
    }
  };

  if (me.isPending) return <div className="auth"><Loading /></div>;
  if (!me.data) {
    if (status.isPending) return <div className="auth"><Loading /></div>;
    return status.data?.setupRequired ? <Setup onDone={signedIn} /> : <Login onDone={signedIn} sso={status.data?.sso} />;
  }
  return (
    <AppProvider me={me.data} onLogout={logout} askChangeSet={(then) => setAsk(() => then)}>
      <RouterProvider router={router} />
      {ask && (
        <NewChangeSet
          onClose={() => setAsk(null)}
          onCreated={(c) => {
            const then = ask;
            setAsk(null);
            then(c.id);
          }}
        />
      )}
    </AppProvider>
  );
}

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <Root />
    </QueryClientProvider>
  </StrictMode>,
);
