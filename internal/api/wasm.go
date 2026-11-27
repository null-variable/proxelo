package api

import (
	"bytes"
	"errors"
	"io"
	"net/http"

	"github.com/null-variable/proxelo/internal/model"
)

// maxWasm bounds a module upload; the Coraza WAF build is about 18 MiB.
const maxWasm = 64 << 20

// wasmMagic starts every WebAssembly binary module: "\0asm" and version 1.
var wasmMagic = []byte{0, 'a', 's', 'm', 1, 0, 0, 0}

func (a *api) wasmModules(w http.ResponseWriter, r *http.Request) {
	ms, err := a.st.WasmModules(r.Context())
	if err != nil {
		a.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": ms})
}

// uploadWasm stores the module in the body under ?name= and returns it with
// its SHA-256, which wasm and waf policies refer to.
func (a *api) uploadWasm(w http.ResponseWriter, r *http.Request) {
	b, err := io.ReadAll(http.MaxBytesReader(nil, r.Body, maxWasm))
	if err != nil {
		var mb *http.MaxBytesError
		if errors.As(err, &mb) {
			a.fail(w, httpError{status: http.StatusRequestEntityTooLarge, msg: "module is larger than 64 MiB"})
			return
		}
		a.fail(w, badRequest("reading body: %v", err))
		return
	}
	if !bytes.HasPrefix(b, wasmMagic) {
		a.fail(w, badRequest("not a WebAssembly binary module"))
		return
	}
	name := r.URL.Query().Get("name")
	if name == "" {
		a.fail(w, badRequest("name is required"))
		return
	}
	m, err := a.st.PutWasm(r.Context(), name, b)
	if err != nil {
		a.fail(w, err)
		return
	}
	a.audit(r, "wasm.upload", m.SHA256, map[string]any{"name": m.Name, "size": m.Size})
	writeJSON(w, http.StatusCreated, m)
}

// deleteWasm removes a module no head policy uses.
func (a *api) deleteWasm(w http.ResponseWriter, r *http.Request) {
	sha := r.PathValue("sha")
	cfg, err := a.st.Head(r.Context())
	if err != nil {
		a.fail(w, err)
		return
	}
	for _, p := range cfg.Policies {
		if usesModule(p, sha) {
			a.fail(w, httpError{status: http.StatusConflict, msg: "policy " + p.Name + " uses the module"})
			return
		}
	}
	if err := a.st.DeleteWasm(r.Context(), sha); err != nil {
		a.fail(w, err)
		return
	}
	a.audit(r, "wasm.delete", sha, nil)
	w.WriteHeader(http.StatusNoContent)
}

func usesModule(p *model.Policy, sha string) bool {
	switch {
	case p.Spec.Wasm != nil:
		return p.Spec.Wasm.Module == sha
	case p.Spec.WAF != nil:
		return p.Spec.WAF.Module == sha
	}
	return false
}
