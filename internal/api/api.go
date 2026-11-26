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
	"time"

	simv1 "github.com/null-variable/proxelo-api/gen/go/proxelo/sim/v1"
	snapshotv1 "github.com/null-variable/proxelo-api/gen/go/proxelo/snapshot/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"github.com/null-variable/proxelo/internal/auth"
	"github.com/null-variable/proxelo/internal/compile"
	"github.com/null-variable/proxelo/internal/deploy"
	"github.com/null-variable/proxelo/internal/distrib"
	"github.com/null-variable/proxelo/internal/model"
	"github.com/null-variable/proxelo/internal/store"
)

const maxBody = 1 << 20

// Distributor delivers applied snapshots to proxies.
type Distributor interface {
	Publish(snapshot []byte) error
	Nodes() []distrib.NodeStatus
	Traffic(from, to time.Time, revision uint64) distrib.Traffic
	ResourceTraffic(from, to time.Time) map[distrib.ResourceKey]distrib.Count
}

// Simulator loads snapshots and runs requests with the proxy engine.
type Simulator interface {
	Run(snapshot []byte, requests []*simv1.HttpRequest) (*simv1.SimResponse, error)
	// DryLoad rejects a snapshot the engine cannot load with
	// model.FieldErrors.
	DryLoad(snapshot []byte) error
}

// Options configure the handler.
type Options struct {
	// Called after a certificate is created or changed, to issue ACME ones.
	CertsChanged func()
	// Admin API address, for the admin-access safety check.
	AdminAddr string
	// Mark session cookies Secure even on plain HTTP, for a TLS-terminating
	// front such as an SSH tunnel.
	SecureCookies bool
}

// Handler returns the API handler. sim may be nil: applies then skip the
// engine dry-load and /simulate answers 503.
func Handler(st *store.Store, d Distributor, dep *deploy.Manager, sim Simulator, opts Options, log *slog.Logger) http.Handler {
	a := &api{st: st, d: d, dep: dep, sim: sim, certsChanged: opts.CertsChanged, adminAddr: opts.AdminAddr, secureCookies: opts.SecureCookies, log: log}
	mux := http.NewServeMux()
	v, ed, op, adm := auth.Viewer, auth.Editor, auth.Operator, auth.Admin
	g := auth.Guest

	mux.HandleFunc("GET /api/v1/auth/status", a.authStatus)
	mux.HandleFunc("POST /api/v1/auth/setup", a.setup)
	mux.HandleFunc("POST /api/v1/auth/login", a.login)
	mux.HandleFunc("POST /api/v1/auth/logout", a.require(g, a.logout))
	mux.HandleFunc("GET /api/v1/auth/oidc/start", a.oidcStart)
	mux.HandleFunc("GET /api/v1/auth/oidc/callback", a.oidcCallback)
	mux.HandleFunc("GET /api/v1/settings/oidc", a.require(adm, a.getOIDC))
	mux.HandleFunc("PUT /api/v1/settings/oidc", a.require(auth.Owner, a.putOIDC))
	mux.HandleFunc("GET /api/v1/auth/me", a.requireAny(g, a.me))
	mux.HandleFunc("POST /api/v1/auth/password", a.require(g, a.changePassword))
	mux.HandleFunc("POST /api/v1/auth/totp/setup", a.require(g, a.totpSetup))
	mux.HandleFunc("POST /api/v1/auth/totp/enable", a.require(g, a.totpEnable))
	mux.HandleFunc("POST /api/v1/auth/totp/disable", a.require(g, a.totpDisable))
	mux.HandleFunc("GET /api/v1/auth/tokens", a.require(g, a.tokens))
	mux.HandleFunc("POST /api/v1/auth/tokens", a.requireAny(g, a.createToken))
	mux.HandleFunc("DELETE /api/v1/auth/tokens/{id}", a.require(g, a.deleteToken))
	mux.HandleFunc("GET /api/v1/users", a.require(adm, a.users))
	mux.HandleFunc("POST /api/v1/users", a.require(adm, a.createUser))
	mux.HandleFunc("PATCH /api/v1/users/{id}", a.require(adm, a.updateUser))
	mux.HandleFunc("DELETE /api/v1/users/{id}", a.require(adm, a.deleteUser))
	mux.HandleFunc("GET /api/v1/audit", a.require(adm, a.auditLog))
	mux.HandleFunc("GET /api/v1/audit/verify", a.require(adm, a.auditVerify))

	mux.HandleFunc("GET /api/v1/groups", a.requireAny(g, a.groups))
	mux.HandleFunc("POST /api/v1/groups", a.requireAny(adm, a.createGroup))
	mux.HandleFunc("PATCH /api/v1/groups/{id}", a.requireAny(adm, a.updateGroup))
	mux.HandleFunc("DELETE /api/v1/groups/{id}", a.requireAny(adm, a.deleteGroup))
	mux.HandleFunc("PUT /api/v1/groups/{id}/members", a.requireAny(adm, a.setMember))
	mux.HandleFunc("DELETE /api/v1/groups/{id}/members/{user}", a.requireAny(g, a.removeMember))
	mux.HandleFunc("GET /api/v1/directory", a.requireAny(adm, a.directory))
	mux.HandleFunc("GET /api/v1/topology", a.requireAny(v, a.topology))

	mux.HandleFunc("GET /api/v1/changesets", a.requireAny(v, a.changesets))
	mux.HandleFunc("POST /api/v1/changesets", a.requireAny(ed, a.createChangeSet))
	mux.HandleFunc("GET /api/v1/changesets/{id}", a.requireAny(v, a.changeset))
	mux.HandleFunc("DELETE /api/v1/changesets/{id}", a.requireAny(ed, a.deleteChangeSet))
	mux.HandleFunc("GET /api/v1/changesets/{id}/diff", a.requireAny(v, a.diff))
	mux.HandleFunc("POST /api/v1/changesets/{id}/validate", a.requireAny(v, a.validate))
	mux.HandleFunc("POST /api/v1/changesets/{id}/apply", a.requireAny(op, a.apply))
	mux.HandleFunc("POST /api/v1/changesets/{id}/import", a.require(ed, a.importBundle))
	mux.HandleFunc("GET /api/v1/export", a.require(v, a.export))
	mux.HandleFunc("POST /api/v1/import/nginx", a.require(ed, a.importNginx))

	mux.HandleFunc("GET /api/v1/revisions", a.requireAny(v, a.revisions))
	mux.HandleFunc("GET /api/v1/revisions/{rev}", a.requireAny(v, a.revision))
	mux.HandleFunc("GET /api/v1/revisions/{rev}/snapshot", a.require(adm, a.snapshot))
	mux.HandleFunc("POST /api/v1/revisions/{rev}/confirm", a.requireAny(op, a.confirm))
	mux.HandleFunc("POST /api/v1/revisions/{rev}/rollback", a.require(op, a.rollback))
	mux.HandleFunc("PUT /api/v1/revisions/{rev}/tag", a.require(op, a.tag))
	mux.HandleFunc("GET /api/v1/nodes", a.require(v, a.nodes))
	mux.HandleFunc("GET /api/v1/traffic", a.require(v, a.traffic))
	mux.HandleFunc("GET /api/v1/tap", a.requireAny(v, a.tap))
	mux.HandleFunc("GET /api/v1/schema", a.requireAny(v, func(w http.ResponseWriter, r *http.Request, _ *access) {
		w.Header().Set("Content-Type", "application/schema+json")
		w.Write(model.SchemaJSON)
	}))
	mux.HandleFunc("POST /api/v1/simulate", a.require(v, a.simulate))

	mux.HandleFunc("GET /api/v1/{kind}", a.requireAny(v, a.list))
	mux.HandleFunc("POST /api/v1/{kind}", a.requireAny(ed, a.create))
	mux.HandleFunc("GET /api/v1/{kind}/{id}", a.requireAny(v, a.get))
	mux.HandleFunc("PATCH /api/v1/{kind}/{id}", a.requireAny(ed, a.patch))
	mux.HandleFunc("PUT /api/v1/{kind}/{id}", a.requireAny(ed, a.put))
	mux.HandleFunc("DELETE /api/v1/{kind}/{id}", a.requireAny(ed, a.delete))
	return mux
}

type api struct {
	st            *store.Store
	d             Distributor
	dep           *deploy.Manager
	sim           Simulator
	certsChanged  func()
	adminAddr     string
	secureCookies bool
	log           *slog.Logger
	oidc          oidcClient
}

// changed kicks ACME after a certificate reaches the head.
func (a *api) changed(touched []store.ItemState) {
	for _, it := range touched {
		if it.Kind == model.CertificateKind.Plural && a.certsChanged != nil {
			a.certsChanged()
			return
		}
	}
}

// errorBody is the JSON body of every error response.
type errorBody struct {
	Error string `json:"error"`
	// Machine-readable reason, for example "totp_required".
	Code   string             `json:"code,omitempty"`
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
	case errors.Is(err, store.ErrPending), errors.Is(err, store.ErrNotPending):
		writeJSON(w, http.StatusConflict, errorBody{Error: err.Error()})
	case errors.Is(err, store.ErrNameTaken):
		writeJSON(w, http.StatusConflict, errorBody{Error: err.Error(), Fields: []model.FieldError{{Path: "name", Message: err.Error()}}})
	default:
		var he httpError
		if errors.As(err, &he) {
			writeJSON(w, he.status, errorBody{Error: he.msg, Code: he.code})
			return
		}
		a.log.Error("api", "err", err)
		writeJSON(w, http.StatusInternalServerError, errorBody{Error: "internal error"})
	}
}

type httpError struct {
	status int
	msg    string
	code   string
}

func (e httpError) Error() string { return e.msg }

func badRequest(format string, args ...any) error {
	return httpError{status: http.StatusBadRequest, msg: fmt.Sprintf(format, args...)}
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
		return k, httpError{status: http.StatusNotFound, msg: fmt.Sprintf("unknown resource kind %q", r.PathValue("kind"))}
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

// decode reads a JSON body into v; an empty body leaves v as is.
func (a *api) decode(r *http.Request, v any) error {
	b, err := readBody(r)
	if err != nil || len(b) == 0 {
		return err
	}
	return decodeStrict(b, v)
}

func uintParam(r *http.Request, name string) (uint64, error) {
	v := r.URL.Query().Get(name)
	if v == "" {
		return 0, nil
	}
	n, err := strconv.ParseUint(v, 10, 64)
	if err != nil {
		return 0, badRequest("%s must be a number", name)
	}
	return n, nil
}

func itoa(i int) string { return strconv.Itoa(i) }

// dryLoad rejects a snapshot the proxy engine cannot load.
func (a *api) dryLoad(snapshot []byte) error {
	if a.sim == nil {
		return nil
	}
	err := a.sim.DryLoad(snapshot)
	var fe model.FieldErrors
	if err != nil && !errors.As(err, &fe) {
		return httpError{status: http.StatusServiceUnavailable, msg: err.Error()}
	}
	return err
}

// simulateRequest is the body of POST /api/v1/simulate. Requests run
// against an applied revision, a change set as it would apply, or both to
// compare them.
type simulateRequest struct {
	// Applied revision; 0 means the latest.
	Revision uint64 `json:"revision"`
	// Also run against this change set merged into the head.
	ChangeSet string            `json:"changeset"`
	Requests  []json.RawMessage `json:"requests"`
}

type simulateResult struct {
	Revision  uint64            `json:"revision,omitempty"`
	ChangeSet string            `json:"changeset,omitempty"`
	Error     string            `json:"error,omitempty"`
	Results   []json.RawMessage `json:"results"`
}

func (a *api) simulate(w http.ResponseWriter, r *http.Request) {
	if a.sim == nil {
		a.fail(w, httpError{status: http.StatusServiceUnavailable, msg: "simulator unavailable"})
		return
	}
	var req simulateRequest
	if err := a.decode(r, &req); err != nil {
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

	out := []simulateResult{}
	rev, err := a.st.Latest(r.Context())
	if req.Revision != 0 {
		rev, err = a.st.Revision(r.Context(), req.Revision)
	}
	switch {
	case errors.Is(err, store.ErrNotFound) && req.Revision == 0 && req.ChangeSet != "":
		// Nothing applied yet: only the change set.
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
	if req.ChangeSet != "" {
		cfg, err := a.st.Preview(r.Context(), req.ChangeSet)
		if err != nil {
			a.fail(w, err)
			return
		}
		sb, _, err := compileBytes(cfg)
		if err != nil {
			a.fail(w, err)
			return
		}
		res, err := a.runSim(sb, reqs)
		if err != nil {
			a.fail(w, err)
			return
		}
		res.ChangeSet = req.ChangeSet
		out = append(out, res)
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": out})
}

// compileBytes compiles cfg as a preview, revision 0.
func compileBytes(cfg model.Config) ([]byte, *snapshotv1.Snapshot, error) {
	snap, err := compile.Compile(cfg, 0)
	if err != nil {
		return nil, nil, err
	}
	b, err := proto.MarshalOptions{Deterministic: true}.Marshal(snap)
	return b, snap, err
}

func (a *api) runSim(snapshot []byte, reqs []*simv1.HttpRequest) (simulateResult, error) {
	resp, err := a.sim.Run(snapshot, reqs)
	if err != nil {
		return simulateResult{}, httpError{status: http.StatusServiceUnavailable, msg: err.Error()}
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
