// Package api serves the control plane REST API under /api/v1.
package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	simv1 "github.com/null-variable/proxelo-api/gen/go/proxelo/sim/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"github.com/null-variable/proxelo/internal/compile"
	"github.com/null-variable/proxelo/internal/distrib"
	"github.com/null-variable/proxelo/internal/model"
	"github.com/null-variable/proxelo/internal/store"
)

const maxBody = 1 << 20

// Distributor delivers applied snapshots to proxies.
type Distributor interface {
	Publish(snapshot []byte) error
	Nodes() []distrib.NodeStatus
}

// Simulator loads snapshots and runs requests with the proxy engine.
type Simulator interface {
	Run(snapshot []byte, requests []*simv1.HttpRequest) (*simv1.SimResponse, error)
	// DryLoad rejects a snapshot the engine cannot load with
	// model.FieldErrors.
	DryLoad(snapshot []byte) error
}

// Handler returns the API handler. sim may be nil: apply then skips the
// engine dry-load and /simulate answers 503. certsChanged, when set, is
// called after a certificate is created or changed, to issue ACME ones.
func Handler(st *store.Store, d Distributor, sim Simulator, certsChanged func(), log *slog.Logger) http.Handler {
	a := &api{st: st, d: d, sim: sim, certsChanged: certsChanged, log: log}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/{kind}", a.list)
	mux.HandleFunc("POST /api/v1/{kind}", a.create)
	mux.HandleFunc("GET /api/v1/{kind}/{id}", a.get)
	mux.HandleFunc("PATCH /api/v1/{kind}/{id}", a.patch)
	mux.HandleFunc("DELETE /api/v1/{kind}/{id}", a.delete)
	mux.HandleFunc("POST /api/v1/apply", a.apply)
	mux.HandleFunc("GET /api/v1/revisions", a.revisions)
	mux.HandleFunc("GET /api/v1/revisions/{rev}", a.revision)
	mux.HandleFunc("GET /api/v1/revisions/{rev}/snapshot", a.snapshot)
	mux.HandleFunc("GET /api/v1/nodes", a.nodes)
	mux.HandleFunc("POST /api/v1/simulate", a.simulate)
	return mux
}

type api struct {
	st           *store.Store
	d            Distributor
	sim          Simulator
	certsChanged func()
	log          *slog.Logger
}

func (a *api) changed(k model.Kind) {
	if k.Plural == model.CertificateKind.Plural && a.certsChanged != nil {
		a.certsChanged()
	}
}

// errorBody is the JSON body of every error response.
type errorBody struct {
	Error  string             `json:"error"`
	Fields []model.FieldError `json:"fields,omitempty"`
}

func (a *api) fail(w http.ResponseWriter, err error) {
	var fe model.FieldErrors
	switch {
	case errors.As(err, &fe):
		writeJSON(w, http.StatusUnprocessableEntity, errorBody{Error: "validation failed", Fields: fe})
	case errors.Is(err, store.ErrNotFound):
		writeJSON(w, http.StatusNotFound, errorBody{Error: err.Error()})
	case errors.Is(err, store.ErrConflict):
		writeJSON(w, http.StatusPreconditionFailed, errorBody{Error: err.Error()})
	case errors.Is(err, store.ErrNameTaken):
		writeJSON(w, http.StatusConflict, errorBody{Error: err.Error(), Fields: []model.FieldError{{Path: "name", Message: err.Error()}}})
	default:
		var he httpError
		if errors.As(err, &he) {
			writeJSON(w, he.status, errorBody{Error: he.msg})
			return
		}
		a.log.Error("api", "err", err)
		writeJSON(w, http.StatusInternalServerError, errorBody{Error: "internal error"})
	}
}

type httpError struct {
	status int
	msg    string
}

func (e httpError) Error() string { return e.msg }

func badRequest(format string, args ...any) error {
	return httpError{http.StatusBadRequest, fmt.Sprintf(format, args...)}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(v)
}

func kindOf(r *http.Request) (model.Kind, error) {
	k, ok := model.KindByPlural(r.PathValue("kind"))
	if !ok {
		return k, httpError{http.StatusNotFound, fmt.Sprintf("unknown resource kind %q", r.PathValue("kind"))}
	}
	return k, nil
}

// ifMatch returns the resource version in If-Match, or 0 when absent.
func ifMatch(r *http.Request) (int64, error) {
	v := r.Header.Get("If-Match")
	if v == "" {
		return 0, nil
	}
	n, err := strconv.ParseInt(strings.Trim(v, `"`), 10, 64)
	if err != nil || n <= 0 {
		return 0, badRequest("If-Match must be a resource version")
	}
	return n, nil
}

func etag(r model.Resource) string {
	return `"` + strconv.FormatInt(r.Common().ResourceVersion, 10) + `"`
}

func readBody(r *http.Request) ([]byte, error) {
	b, err := io.ReadAll(http.MaxBytesReader(nil, r.Body, maxBody))
	if err != nil {
		return nil, badRequest("reading body: %v", err)
	}
	return b, nil
}

// decodeStrict decodes exactly one JSON value and rejects unknown fields.
// Server-managed resource fields (id, resourceVersion, timestamps) in a body
// are accepted and then overwritten by the store.
func decodeStrict(b []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return badRequest("invalid JSON: %v", err)
	}
	if dec.More() {
		return badRequest("invalid JSON: trailing data")
	}
	return nil
}

func (a *api) list(w http.ResponseWriter, r *http.Request) {
	k, err := kindOf(r)
	if err != nil {
		a.fail(w, err)
		return
	}
	items, err := a.st.List(r.Context(), k)
	if err != nil {
		a.fail(w, err)
		return
	}
	out := make([]model.Resource, len(items))
	for i, it := range items {
		out[i] = model.Redacted(it)
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": out})
}

func (a *api) get(w http.ResponseWriter, r *http.Request) {
	k, err := kindOf(r)
	if err != nil {
		a.fail(w, err)
		return
	}
	res, err := a.st.Get(r.Context(), k, r.PathValue("id"))
	if err != nil {
		a.fail(w, err)
		return
	}
	w.Header().Set("ETag", etag(res))
	writeJSON(w, http.StatusOK, model.Redacted(res))
}

func (a *api) create(w http.ResponseWriter, r *http.Request) {
	k, err := kindOf(r)
	if err != nil {
		a.fail(w, err)
		return
	}
	b, err := readBody(r)
	if err != nil {
		a.fail(w, err)
		return
	}
	res := k.New()
	if err := decodeStrict(b, res); err != nil {
		a.fail(w, err)
		return
	}
	if err := model.Validate(res).Err(); err != nil {
		a.fail(w, err)
		return
	}
	model.Prepare(res)
	if err := a.st.Create(r.Context(), k, res); err != nil {
		a.fail(w, err)
		return
	}
	a.changed(k)
	w.Header().Set("Location", "/api/v1/"+k.Plural+"/"+res.Common().ID)
	w.Header().Set("ETag", etag(res))
	writeJSON(w, http.StatusCreated, model.Redacted(res))
}

// patch applies a JSON merge patch (RFC 7396) to the stored resource.
func (a *api) patch(w http.ResponseWriter, r *http.Request) {
	k, err := kindOf(r)
	if err != nil {
		a.fail(w, err)
		return
	}
	version, err := ifMatch(r)
	if err != nil {
		a.fail(w, err)
		return
	}
	b, err := readBody(r)
	if err != nil {
		a.fail(w, err)
		return
	}
	var patch any
	if err := json.Unmarshal(b, &patch); err != nil {
		a.fail(w, badRequest("invalid JSON: %v", err))
		return
	}
	id := r.PathValue("id")
	cur, err := a.st.Get(r.Context(), k, id)
	if err != nil {
		a.fail(w, err)
		return
	}
	if version == 0 {
		version = cur.Common().ResourceVersion
	}
	curJSON, err := json.Marshal(cur)
	if err != nil {
		a.fail(w, err)
		return
	}
	var doc any
	if err := json.Unmarshal(curJSON, &doc); err != nil {
		a.fail(w, err)
		return
	}
	merged, err := json.Marshal(mergePatch(doc, patch))
	if err != nil {
		a.fail(w, err)
		return
	}
	res := k.New()
	if err := decodeStrict(merged, res); err != nil {
		a.fail(w, err)
		return
	}
	if err := model.Validate(res).Err(); err != nil {
		a.fail(w, err)
		return
	}
	model.Prepare(res)
	if err := a.st.Update(r.Context(), k, id, version, res); err != nil {
		a.fail(w, err)
		return
	}
	a.changed(k)
	w.Header().Set("ETag", etag(res))
	writeJSON(w, http.StatusOK, model.Redacted(res))
}

// mergePatch implements RFC 7396.
func mergePatch(target, patch any) any {
	p, ok := patch.(map[string]any)
	if !ok {
		return patch
	}
	t, ok := target.(map[string]any)
	if !ok {
		t = map[string]any{}
	}
	for k, v := range p {
		if v == nil {
			delete(t, k)
		} else {
			t[k] = mergePatch(t[k], v)
		}
	}
	return t
}

func (a *api) delete(w http.ResponseWriter, r *http.Request) {
	k, err := kindOf(r)
	if err != nil {
		a.fail(w, err)
		return
	}
	version, err := ifMatch(r)
	if err != nil {
		a.fail(w, err)
		return
	}
	if err := a.st.Delete(r.Context(), k, r.PathValue("id"), version); err != nil {
		a.fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *api) apply(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Message string `json:"message"`
	}
	b, err := readBody(r)
	if err != nil {
		a.fail(w, err)
		return
	}
	if len(b) > 0 {
		if err := decodeStrict(b, &req); err != nil {
			a.fail(w, err)
			return
		}
	}
	rev, err := a.st.Apply(r.Context(), req.Message, a.dryLoad)
	if err != nil {
		a.fail(w, err)
		return
	}
	a.log.Info("applied", "revision", rev.Revision, "hash", fmt.Sprintf("%x", rev.Hash))
	// The revision is stored; proxies that miss this push get it when they
	// reconnect, so a publish failure is logged rather than undoing the apply.
	if err := a.d.Publish(rev.Snapshot); err != nil {
		a.log.Error("publishing snapshot", "revision", rev.Revision, "err", err)
	}
	writeJSON(w, http.StatusCreated, rev)
}

func (a *api) nodes(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"items": a.d.Nodes()})
}

func (a *api) revisions(w http.ResponseWriter, r *http.Request) {
	revs, err := a.st.Revisions(r.Context())
	if err != nil {
		a.fail(w, err)
		return
	}
	if revs == nil {
		revs = []*store.Revision{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": revs})
}

func (a *api) loadRevision(r *http.Request) (*store.Revision, error) {
	n, err := strconv.ParseUint(r.PathValue("rev"), 10, 64)
	if err != nil {
		return nil, badRequest("revision must be a number")
	}
	return a.st.Revision(r.Context(), n)
}

func (a *api) revision(w http.ResponseWriter, r *http.Request) {
	rev, err := a.loadRevision(r)
	if err != nil {
		a.fail(w, err)
		return
	}
	cfg := rev.Config
	cfg.Certificates = nil
	for _, c := range rev.Config.Certificates {
		cfg.Certificates = append(cfg.Certificates, model.Redacted(c).(*model.Certificate))
	}
	writeJSON(w, http.StatusOK, struct {
		*store.Revision
		Config model.Config `json:"config"`
	}{rev, cfg})
}

func (a *api) snapshot(w http.ResponseWriter, r *http.Request) {
	rev, err := a.loadRevision(r)
	if err != nil {
		a.fail(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/x-protobuf")
	w.Write(rev.Snapshot)
}

// dryLoad rejects a snapshot the proxy engine cannot load.
func (a *api) dryLoad(snapshot []byte) error {
	if a.sim == nil {
		return nil
	}
	err := a.sim.DryLoad(snapshot)
	var fe model.FieldErrors
	if err != nil && !errors.As(err, &fe) {
		return httpError{http.StatusServiceUnavailable, err.Error()}
	}
	return err
}

// simulateRequest is the body of POST /api/v1/simulate. Requests run against
// an applied revision, the current draft, or both to compare them.
type simulateRequest struct {
	// Applied revision; 0 means the latest.
	Revision uint64 `json:"revision"`
	// Also run against the resources as they are now, applied or not.
	Draft    bool              `json:"draft"`
	Requests []json.RawMessage `json:"requests"`
}

type simulateResult struct {
	Revision uint64            `json:"revision,omitempty"`
	Draft    bool              `json:"draft,omitempty"`
	Error    string            `json:"error,omitempty"`
	Results  []json.RawMessage `json:"results"`
}

func (a *api) simulate(w http.ResponseWriter, r *http.Request) {
	if a.sim == nil {
		a.fail(w, httpError{http.StatusServiceUnavailable, "simulator unavailable"})
		return
	}
	b, err := readBody(r)
	if err != nil {
		a.fail(w, err)
		return
	}
	var req simulateRequest
	if err := decodeStrict(b, &req); err != nil {
		a.fail(w, err)
		return
	}
	if len(req.Requests) == 0 {
		a.fail(w, badRequest("requests: at least one is required"))
		return
	}
	reqs := make([]*simv1.HttpRequest, len(req.Requests))
	for i, raw := range req.Requests {
		reqs[i] = &simv1.HttpRequest{}
		if err := (protojson.UnmarshalOptions{}).Unmarshal(raw, reqs[i]); err != nil {
			a.fail(w, badRequest("requests[%d]: %v", i, err))
			return
		}
	}

	var out []simulateResult
	rev, err := a.st.Latest(r.Context())
	if req.Revision != 0 {
		rev, err = a.st.Revision(r.Context(), req.Revision)
	}
	switch {
	case errors.Is(err, store.ErrNotFound) && req.Revision == 0 && req.Draft:
		// Nothing applied yet: only the draft.
	case err != nil:
		a.fail(w, err)
		return
	default:
		res, err := a.runSim(rev.Snapshot, reqs)
		if err != nil {
			a.fail(w, err)
			return
		}
		res.Revision = rev.Revision
		out = append(out, res)
	}
	if req.Draft {
		cfg, err := a.st.Draft(r.Context())
		if err != nil {
			a.fail(w, err)
			return
		}
		snap, err := compile.Compile(cfg, 0)
		if err != nil {
			a.fail(w, err)
			return
		}
		sb, err := proto.MarshalOptions{Deterministic: true}.Marshal(snap)
		if err != nil {
			a.fail(w, err)
			return
		}
		res, err := a.runSim(sb, reqs)
		if err != nil {
			a.fail(w, err)
			return
		}
		res.Draft = true
		out = append(out, res)
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": out})
}

func (a *api) runSim(snapshot []byte, reqs []*simv1.HttpRequest) (simulateResult, error) {
	resp, err := a.sim.Run(snapshot, reqs)
	if err != nil {
		return simulateResult{}, httpError{http.StatusServiceUnavailable, err.Error()}
	}
	res := simulateResult{Error: resp.Error, Results: []json.RawMessage{}}
	for _, x := range resp.Results {
		j, err := protojson.MarshalOptions{UseEnumNumbers: false}.Marshal(x)
		if err != nil {
			return res, err
		}
		res.Results = append(res.Results, j)
	}
	return res, nil
}
