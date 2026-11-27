package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	snapshotv1 "github.com/null-variable/proxelo-api/gen/go/proxelo/snapshot/v1"
	"go.yaml.in/yaml/v3"
	"google.golang.org/protobuf/proto"

	"github.com/null-variable/proxelo/internal/auth"
	"github.com/null-variable/proxelo/internal/deploy"
	"github.com/null-variable/proxelo/internal/diff"
	"github.com/null-variable/proxelo/internal/lint"
	"github.com/null-variable/proxelo/internal/model"
	"github.com/null-variable/proxelo/internal/store"
)

func uintParamValue(s string) (uint64, error) { return strconv.ParseUint(s, 10, 64) }

func (a *api) changesets(w http.ResponseWriter, r *http.Request, ac *access) {
	css, err := a.st.ChangeSets(r.Context())
	if err != nil {
		a.fail(w, err)
		return
	}
	out := []*store.ChangeSet{}
	for _, cs := range css {
		ok, err := a.seesChangeSet(r, ac, cs)
		if err != nil {
			a.fail(w, err)
			return
		}
		if ok {
			out = append(out, cs)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": out})
}

// seesChangeSet: instance viewers see every change set; group members
// those they opened and those touching only resources they can read.
func (a *api) seesChangeSet(r *http.Request, ac *access, cs *store.ChangeSet) (bool, error) {
	if ac.seesAll() || cs.Author == ac.p.user.Name {
		return true, nil
	}
	if len(cs.Items) == 0 {
		return false, nil
	}
	return a.requireItems(r, ac, cs.ID, auth.Viewer) == nil, nil
}

func (a *api) createChangeSet(w http.ResponseWriter, r *http.Request, _ *access) {
	var req struct {
		Message string `json:"message"`
	}
	if err := a.decode(r, &req); err != nil {
		a.fail(w, err)
		return
	}
	cs, err := a.st.CreateChangeSet(r.Context(), who(r).name(), req.Message)
	if err != nil {
		a.fail(w, err)
		return
	}
	w.Header().Set("Location", "/api/v1/changesets/"+cs.ID)
	writeJSON(w, http.StatusCreated, cs)
}

func (a *api) changeset(w http.ResponseWriter, r *http.Request, ac *access) {
	cs, err := a.st.ChangeSet(r.Context(), r.PathValue("id"))
	if err == nil {
		var ok bool
		if ok, err = a.seesChangeSet(r, ac, cs); err == nil && !ok {
			err = store.ErrNotFound
		}
	}
	if err != nil {
		a.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, cs)
}

func (a *api) deleteChangeSet(w http.ResponseWriter, r *http.Request, ac *access) {
	if err := a.requireItems(r, ac, r.PathValue("id"), auth.Editor); err != nil {
		a.fail(w, err)
		return
	}
	if err := a.st.DeleteChangeSet(r.Context(), r.PathValue("id")); err != nil {
		a.fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// resourceDiff is the field-level change of one resource.
type resourceDiff struct {
	Kind string   `json:"kind"`
	ID   string   `json:"id"`
	Name string   `json:"name"`
	Op   store.Op `json:"op"`
	// The current revision changed the resource since the change set
	// touched it; applying merges both.
	Drifted bool          `json:"drifted,omitempty"`
	Changes []diff.Change `json:"changes,omitempty"`
}

// metaNoise are fields every edit changes.
var metaNoise = map[string]bool{"resourceVersion": true, "updatedAt": true, "createdAt": true}

func resourceDoc(r model.Resource) any {
	if r == nil {
		return nil
	}
	return diff.Doc(r)
}

func (a *api) resourceDiffs(r *http.Request, cs string) ([]resourceDiff, error) {
	items, err := a.st.Items(r.Context(), cs)
	if err != nil {
		return nil, err
	}
	out := []resourceDiff{}
	for _, it := range items {
		k, _ := model.KindByPlural(it.Kind)
		head, err := a.st.Get(r.Context(), "", k, it.ID)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return nil, err
		}
		d := resourceDiff{Kind: it.Kind, ID: it.ID, Op: it.Op, Drifted: it.Drifted}
		if it.New != nil {
			d.Name = it.New.Common().Name
		} else if head != nil {
			d.Name = head.Common().Name
		}
		for _, c := range diff.Compare(resourceDoc(head), resourceDoc(it.New)) {
			if !metaNoise[c.Path] {
				d.Changes = append(d.Changes, c)
			}
		}
		d.Changes = diff.Redact(d.Changes, model.SecretFields...)
		out = append(out, d)
	}
	return out, nil
}

// latestSnapshot is the snapshot of the newest revision, nil before the
// first.
func (a *api) latestSnapshot(r *http.Request) (*snapshotv1.Snapshot, error) {
	rev, err := a.st.Latest(r.Context())
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	snap := &snapshotv1.Snapshot{}
	return snap, proto.Unmarshal(rev.Snapshot, snap)
}

func redactEffective(es []diff.Effective) []diff.Effective {
	for i := range es {
		es[i].Changes = diff.Redact(es[i].Changes, model.SecretFields...)
	}
	return es
}

// diff returns the resource diff and, when the change set compiles, the
// effective diff of compiled behavior against the latest revision.
func (a *api) diff(w http.ResponseWriter, r *http.Request, ac *access) {
	cs := r.PathValue("id")
	if err := a.requireItems(r, ac, cs, auth.Viewer); err != nil {
		a.fail(w, err)
		return
	}
	res, err := a.resourceDiffs(r, cs)
	if err != nil {
		a.fail(w, err)
		return
	}
	out := map[string]any{"resources": res}
	cfg, err := a.st.Preview(r.Context(), cs)
	var fe model.FieldErrors
	switch {
	case errors.As(err, &fe):
		out["errors"] = fe
	case err != nil:
		a.fail(w, err)
		return
	default:
		_, next, err := compileBytes(cfg)
		if errors.As(err, &fe) {
			out["errors"] = fe
			break
		}
		if err != nil {
			a.fail(w, err)
			return
		}
		cur, err := a.latestSnapshot(r)
		if err != nil {
			a.fail(w, err)
			return
		}
		out["effective"] = redactEffective(diff.EffectiveDiff(cur, next))
	}
	writeJSON(w, http.StatusOK, out)
}

type validation struct {
	Valid    bool               `json:"valid"`
	Errors   []model.FieldError `json:"errors,omitempty"`
	Warnings []lint.Finding     `json:"warnings,omitempty"`
}

// check runs every validation stage (compile, proxy dry-load, lint) on change set cs.
func (a *api) check(r *http.Request, cs string) (validation, error) {
	v := validation{}
	cfg, err := a.st.Preview(r.Context(), cs)
	var fe model.FieldErrors
	if errors.As(err, &fe) {
		v.Errors = fe
		return v, nil
	}
	if err != nil {
		return v, err
	}
	sb, _, err := compileBytes(cfg)
	if errors.As(err, &fe) {
		v.Errors = fe
		return v, nil
	}
	if err != nil {
		return v, err
	}
	if err := a.dryLoad(sb); errors.As(err, &fe) {
		v.Errors = fe
		return v, nil
	} else if err != nil {
		return v, err
	}
	v.Valid = true
	v.Warnings = lint.Check(cfg, a.adminAddr)
	return v, nil
}

func (a *api) validate(w http.ResponseWriter, r *http.Request, ac *access) {
	if err := a.requireItems(r, ac, r.PathValue("id"), auth.Viewer); err != nil {
		a.fail(w, err)
		return
	}
	v, err := a.check(r, r.PathValue("id"))
	if err != nil {
		a.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

// applyMode is the body of an apply or rollback.
type applyMode struct {
	// "confirm" (default) or "direct".
	Mode string `json:"mode"`
	// Seconds; 0 means the default window.
	ConfirmTimeout uint32 `json:"confirmTimeout"`
}

// timeout returns the commit-confirm window, 0 for direct. def is used when
// no mode is given.
func (m applyMode) timeout(def time.Duration) (time.Duration, error) {
	switch m.Mode {
	case "":
		if def == 0 {
			return 0, nil
		}
	case "direct":
		return 0, nil
	case "confirm":
	default:
		return 0, httpError{status: http.StatusUnprocessableEntity, msg: `mode: must be "confirm" or "direct"`}
	}
	d := deploy.DefaultConfirmTimeout
	if m.ConfirmTimeout != 0 {
		d = time.Duration(m.ConfirmTimeout) * time.Second
	}
	if d > deploy.MaxConfirmTimeout {
		return 0, httpError{status: http.StatusUnprocessableEntity, msg: fmt.Sprintf("confirmTimeout: at most %d", int(deploy.MaxConfirmTimeout/time.Second))}
	}
	return d, nil
}

func (a *api) apply(w http.ResponseWriter, r *http.Request, ac *access) {
	cs := r.PathValue("id")
	if err := a.requireItems(r, ac, cs, auth.Operator); err != nil {
		a.fail(w, err)
		return
	}
	var req applyMode
	if err := a.decode(r, &req); err != nil {
		a.fail(w, err)
		return
	}
	confirm, err := req.timeout(deploy.DefaultConfirmTimeout)
	if err != nil {
		a.fail(w, err)
		return
	}
	v, err := a.check(r, cs)
	if err != nil {
		a.fail(w, err)
		return
	}
	if !v.Valid {
		writeJSON(w, http.StatusUnprocessableEntity, errorBody{Error: "validation failed", Fields: v.Errors})
		return
	}
	// Changes that may cut off admin access always need a confirmation.
	forced := false
	for _, f := range v.Warnings {
		if f.Level == "safety" && confirm == 0 {
			confirm, forced = deploy.DefaultConfirmTimeout, true
		}
	}
	items, err := a.st.Items(r.Context(), cs)
	if err != nil {
		a.fail(w, err)
		return
	}
	res, err := a.resourceDiffs(r, cs)
	if err != nil {
		a.fail(w, err)
		return
	}
	rev, err := a.dep.Apply(r.Context(), cs, who(r).name(), confirm)
	if err != nil {
		a.fail(w, err)
		return
	}
	a.audit(r, "changeset.apply", cs, map[string]any{"revision": rev.Revision, "status": rev.Status, "resources": res})
	a.changed(items)
	writeJSON(w, http.StatusCreated, map[string]any{"revision": rev, "warnings": v.Warnings, "confirmForced": forced})
}

// bundle is the export format.
type bundle struct {
	APIVersion string       `json:"apiVersion"`
	Revision   uint64       `json:"revision,omitempty"`
	Resources  model.Config `json:"resources"`
}

const bundleVersion = "proxelo/v1"

// export writes the head as a YAML bundle, or JSON with ?format=json.
// Private keys are left out; importing keeps the stored ones.
func (a *api) export(w http.ResponseWriter, r *http.Request) {
	cfg, err := a.st.Head(r.Context())
	if err != nil {
		a.fail(w, err)
		return
	}
	b := bundle{APIVersion: bundleVersion, Resources: redactConfig(cfg)}
	if rev, err := a.st.Latest(r.Context()); err == nil {
		b.Revision = rev.Revision
	}
	if r.URL.Query().Get("format") == "json" {
		writeJSON(w, http.StatusOK, b)
		return
	}
	out, err := yaml.Marshal(diff.Doc(b))
	if err != nil {
		a.fail(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/yaml")
	w.Write(out)
}

// importBundle makes change set {id} hold exactly the resources of a YAML
// or JSON bundle.
func (a *api) importBundle(w http.ResponseWriter, r *http.Request) {
	raw, err := readBody(r)
	if err != nil {
		a.fail(w, err)
		return
	}
	var doc any
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		a.fail(w, badRequest("invalid bundle: %v", err))
		return
	}
	j, err := json.Marshal(doc)
	if err != nil {
		a.fail(w, badRequest("invalid bundle: %v", err))
		return
	}
	var b bundle
	if err := decodeStrict(j, &b); err != nil {
		a.fail(w, err)
		return
	}
	if b.APIVersion != bundleVersion {
		a.fail(w, httpError{status: http.StatusUnprocessableEntity, msg: "apiVersion: must be " + bundleVersion})
		return
	}
	cs := r.PathValue("id")
	if err := a.importConfig(r.Context(), cs, b.Resources); err != nil {
		a.fail(w, err)
		return
	}
	css, err := a.st.ChangeSet(r.Context(), cs)
	if err != nil {
		a.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, css)
}

// importConfig validates cfg and makes change set cs hold exactly it.
// Resources without an ID get one.
func (a *api) importConfig(ctx context.Context, cs string, cfg model.Config) error {
	var es model.FieldErrors
	for _, k := range model.Kinds {
		for _, res := range cfg.Of(k) {
			m := res.Common()
			p := fmt.Sprintf("%s[%s]", k.Plural, m.ID)
			if m.ID == "" {
				m.ID = k.NewID()
			} else if len(m.ID) <= len(k.IDPrefix)+1 || m.ID[:len(k.IDPrefix)+1] != k.IDPrefix+"_" {
				es = append(es, model.FieldError{Path: p + ".id", Message: "must start with " + k.IDPrefix + "_"})
			}
			if c, ok := res.(*model.Certificate); ok && c.Spec.Source != model.CertACME && c.Spec.KeyPEM == "" {
				// Validated after the stored key is restored.
				continue
			}
			for _, e := range model.Validate(res) {
				es = append(es, model.FieldError{Path: p + "." + e.Path, Message: e.Message})
			}
			model.Prepare(res)
		}
	}
	if err := es.Err(); err != nil {
		return err
	}
	if err := a.st.Import(ctx, cs, cfg); err != nil {
		return err
	}
	// Certificates whose key came from the store are checked now.
	for _, c := range cfg.Certificates {
		got, err := a.st.Get(ctx, cs, model.CertificateKind, c.ID)
		if err != nil {
			return err
		}
		if fe := model.Validate(got); len(fe) > 0 {
			return prefix(fe, "certificates["+c.ID+"]")
		}
	}
	return nil
}

func prefix(es model.FieldErrors, p string) model.FieldErrors {
	out := make(model.FieldErrors, len(es))
	for i, e := range es {
		out[i] = model.FieldError{Path: p + "." + e.Path, Message: e.Message}
	}
	return out
}
