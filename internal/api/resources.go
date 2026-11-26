package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/null-variable/proxelo/internal/auth"
	"github.com/null-variable/proxelo/internal/model"
	"github.com/null-variable/proxelo/internal/store"
)

// changeSetParam is the change set of a request: reads without one see the
// head, writes without one fail.
func changeSetParam(r *http.Request) string { return r.URL.Query().Get("changeset") }

func writeChangeSet(r *http.Request) (string, error) {
	cs := changeSetParam(r)
	if cs == "" {
		return "", badRequest("writes need ?changeset=<id>; create one with POST /api/v1/changesets")
	}
	return cs, nil
}

func (a *api) list(w http.ResponseWriter, r *http.Request, ac *access) {
	k, err := kindOf(r)
	if err != nil {
		a.fail(w, err)
		return
	}
	items, err := a.st.List(r.Context(), changeSetParam(r), k)
	if err != nil {
		a.fail(w, err)
		return
	}
	out := make([]model.Resource, 0, len(items))
	for _, it := range items {
		if ac.canRead(k.Plural, it) {
			out = append(out, model.Redacted(it))
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": out})
}

func (a *api) get(w http.ResponseWriter, r *http.Request, ac *access) {
	k, err := kindOf(r)
	if err != nil {
		a.fail(w, err)
		return
	}
	res, err := a.st.Get(r.Context(), changeSetParam(r), k, r.PathValue("id"))
	if err == nil && !ac.canRead(k.Plural, res) {
		err = store.ErrNotFound
	}
	if err != nil {
		a.fail(w, err)
		return
	}
	w.Header().Set("ETag", etag(res))
	writeJSON(w, http.StatusOK, model.Redacted(res))
}

func (a *api) create(w http.ResponseWriter, r *http.Request, ac *access) {
	k, err := kindOf(r)
	if err != nil {
		a.fail(w, err)
		return
	}
	cs, err := writeChangeSet(r)
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
	if err := a.mayWrite(r, ac, cs, nil, res); err != nil {
		a.fail(w, err)
		return
	}
	model.Prepare(res)
	if err := a.st.Create(r.Context(), cs, k, res); err != nil {
		a.fail(w, err)
		return
	}
	w.Header().Set("Location", "/api/v1/"+k.Plural+"/"+res.Common().ID+"?changeset="+cs)
	w.Header().Set("ETag", etag(res))
	writeJSON(w, http.StatusCreated, model.Redacted(res))
}

// patch applies a JSON merge patch (RFC 7396) to the resource as the change
// set sees it.
func (a *api) patch(w http.ResponseWriter, r *http.Request, ac *access) {
	a.update(w, r, ac, true)
}

// put replaces the resource. An uploaded certificate without keyPem keeps
// the stored key, which reads never return.
func (a *api) put(w http.ResponseWriter, r *http.Request, ac *access) {
	a.update(w, r, ac, false)
}

func (a *api) update(w http.ResponseWriter, r *http.Request, ac *access, merge bool) {
	k, err := kindOf(r)
	if err != nil {
		a.fail(w, err)
		return
	}
	cs, err := writeChangeSet(r)
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
	id := r.PathValue("id")
	cur, err := a.st.Get(r.Context(), cs, k, id)
	if err == nil && !ac.canRead(k.Plural, cur) {
		err = store.ErrNotFound
	}
	if err != nil {
		a.fail(w, err)
		return
	}
	if version == 0 {
		version = cur.Common().ResourceVersion
	}
	body := b
	if merge {
		var patch any
		if err := json.Unmarshal(b, &patch); err != nil {
			a.fail(w, badRequest("invalid JSON: %v", err))
			return
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
		if body, err = json.Marshal(mergePatch(doc, patch)); err != nil {
			a.fail(w, err)
			return
		}
	}
	res := k.New()
	if err := decodeStrict(body, res); err != nil {
		a.fail(w, err)
		return
	}
	if c, ok := res.(*model.Certificate); ok && !merge && c.Spec.KeyPEM == "" {
		c.Spec.KeyPEM = cur.(*model.Certificate).Spec.KeyPEM
	}
	if err := model.Validate(res).Err(); err != nil {
		a.fail(w, err)
		return
	}
	if err := a.mayWrite(r, ac, cs, cur, res); err != nil {
		a.fail(w, err)
		return
	}
	model.Prepare(res)
	if err := a.st.Update(r.Context(), cs, k, id, version, res); err != nil {
		a.fail(w, err)
		return
	}
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

func (a *api) delete(w http.ResponseWriter, r *http.Request, ac *access) {
	k, err := kindOf(r)
	if err != nil {
		a.fail(w, err)
		return
	}
	cs, err := writeChangeSet(r)
	if err != nil {
		a.fail(w, err)
		return
	}
	cur, err := a.st.Get(r.Context(), cs, k, r.PathValue("id"))
	if err == nil && !ac.canRead(k.Plural, cur) {
		err = store.ErrNotFound
	}
	if err == nil {
		err = a.mayWrite(r, ac, cs, cur, nil)
	}
	if err != nil {
		a.fail(w, err)
		return
	}
	version, err := ifMatch(r)
	if err != nil {
		a.fail(w, err)
		return
	}
	if err := a.st.Delete(r.Context(), cs, k, r.PathValue("id"), version); err != nil {
		a.fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// traffic sums what proxies handled over ?window (a duration, default 5m,
// at most 15m), for every revision.
func (a *api) traffic(w http.ResponseWriter, r *http.Request) {
	window := 5 * time.Minute
	if v := r.URL.Query().Get("window"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d <= 0 || d > 15*time.Minute {
			a.fail(w, badRequest("window must be a duration up to 15m"))
			return
		}
		window = d
	}
	now := time.Now()
	writeJSON(w, http.StatusOK, map[string]any{"window": window.String(), "traffic": a.d.Traffic(now.Add(-window), now, 0)})
}

func (a *api) nodes(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"items": a.d.Nodes()})
}

func (a *api) loadRevision(r *http.Request) (*store.Revision, error) {
	n, err := parseRevision(r)
	if err != nil {
		return nil, err
	}
	return a.st.Revision(r.Context(), n)
}

func parseRevision(r *http.Request) (uint64, error) {
	n, err := uintParamValue(r.PathValue("rev"))
	if err != nil {
		return 0, badRequest("revision must be a number")
	}
	return n, nil
}

func (a *api) revisions(w http.ResponseWriter, r *http.Request, ac *access) {
	revs, err := a.st.Revisions(r.Context())
	if err != nil {
		a.fail(w, err)
		return
	}
	out := []*store.Revision{}
	for _, rev := range revs {
		// Group members see the revisions that touched their groups.
		if ac.seesAll() || ac.seesGroups(rev.Groups) {
			out = append(out, rev)
		}
	}
	revs = out
	writeJSON(w, http.StatusOK, map[string]any{"items": revs})
}

func redactConfig(cfg model.Config) model.Config {
	out := cfg
	out.Certificates = nil
	for _, c := range cfg.Certificates {
		out.Certificates = append(out.Certificates, model.Redacted(c).(*model.Certificate))
	}
	return out
}

// revision returns one revision with the resources the caller can read.
func (a *api) revision(w http.ResponseWriter, r *http.Request, ac *access) {
	rev, err := a.loadRevision(r)
	if err == nil && !ac.seesAll() && !ac.seesGroups(rev.Groups) {
		err = store.ErrNotFound
	}
	if err != nil {
		a.fail(w, err)
		return
	}
	var cfg model.Config
	for _, k := range model.Kinds {
		for _, res := range rev.Config.Of(k) {
			if ac.canRead(k.Plural, res) {
				cfg.Add(res)
			}
		}
	}
	writeJSON(w, http.StatusOK, struct {
		*store.Revision
		Config model.Config `json:"config"`
	}{rev, redactConfig(cfg)})
}

// snapshot returns the compiled snapshot, private keys included; it needs
// the admin role.
func (a *api) snapshot(w http.ResponseWriter, r *http.Request) {
	rev, err := a.loadRevision(r)
	if err != nil {
		a.fail(w, err)
		return
	}
	a.audit(r, "revision.snapshot.read", r.PathValue("rev"), nil)
	w.Header().Set("Content-Type", "application/x-protobuf")
	w.Write(rev.Snapshot)
}

// confirm keeps a pending revision. Instance operators confirm any; group
// operators the ones they applied.
func (a *api) confirm(w http.ResponseWriter, r *http.Request, ac *access) {
	n, err := parseRevision(r)
	if err != nil {
		a.fail(w, err)
		return
	}
	if !ac.in("").Allows(auth.Operator) {
		rev, err := a.st.Revision(r.Context(), n)
		if err != nil {
			a.fail(w, err)
			return
		}
		if rev.Author != ac.p.user.Name {
			a.fail(w, httpError{status: http.StatusForbidden, msg: "group operators confirm only the revisions they applied"})
			return
		}
	}
	rev, err := a.dep.Confirm(r.Context(), n, who(r).name())
	if err != nil {
		a.fail(w, err)
		return
	}
	a.audit(r, "revision.confirm", r.PathValue("rev"), nil)
	writeJSON(w, http.StatusOK, rev)
}

// rollback makes revision {rev} (0: the empty configuration) the next one.
func (a *api) rollback(w http.ResponseWriter, r *http.Request) {
	n, err := parseRevision(r)
	if err != nil {
		a.fail(w, err)
		return
	}
	var req struct {
		Message string `json:"message"`
		applyMode
	}
	if err := a.decode(r, &req); err != nil {
		a.fail(w, err)
		return
	}
	confirm, err := req.timeout(0)
	if err != nil {
		a.fail(w, err)
		return
	}
	rev, err := a.dep.Rollback(r.Context(), n, who(r).name(), req.Message, confirm)
	if err != nil {
		a.fail(w, err)
		return
	}
	a.audit(r, "revision.rollback", r.PathValue("rev"), map[string]any{"revision": rev.Revision, "status": rev.Status})
	writeJSON(w, http.StatusCreated, rev)
}

func (a *api) tag(w http.ResponseWriter, r *http.Request) {
	n, err := parseRevision(r)
	if err != nil {
		a.fail(w, err)
		return
	}
	var req struct {
		Tag string `json:"tag"`
	}
	if err := a.decode(r, &req); err != nil {
		a.fail(w, err)
		return
	}
	if req.Tag != "" && !nameOK(req.Tag) {
		a.fail(w, httpError{status: http.StatusUnprocessableEntity, msg: "tag: must be 1-64 lowercase letters, digits, '.', '_' or '-'"})
		return
	}
	if err := a.st.SetTag(r.Context(), n, req.Tag); err != nil {
		if errors.Is(err, store.ErrNameTaken) {
			err = httpError{status: http.StatusConflict, msg: "tag is on another revision"}
		}
		a.fail(w, err)
		return
	}
	a.audit(r, "revision.tag", r.PathValue("rev"), map[string]any{"tag": req.Tag})
	rev, err := a.st.Revision(r.Context(), n)
	if err != nil {
		a.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, rev)
}
