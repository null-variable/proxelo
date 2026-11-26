package api

import (
	"errors"
	"net/http"

	"github.com/null-variable/proxelo/internal/auth"
	"github.com/null-variable/proxelo/internal/model"
	"github.com/null-variable/proxelo/internal/store"
	"github.com/null-variable/proxelo/internal/topology"
)

// groups lists the groups the caller can see and the caller's effective
// role in each.
func (a *api) groups(w http.ResponseWriter, r *http.Request, ac *access) {
	writeJSON(w, http.StatusOK, map[string]any{"items": ac.visibleGroups(), "roles": ac.groupRoles()})
}

type groupBody struct {
	Name        string    `json:"name"`
	Parent      string    `json:"parent"`
	Description string    `json:"description"`
	Domains     *[]string `json:"domains"`
}

// checkDomains validates domain names and keeps them inside the bound the
// parent group sets.
func (ac *access) checkDomains(parent string, ds []string) error {
	var es model.FieldErrors
	bound := ac.domains(parent)
	for i, d := range ds {
		p := "domains[" + itoa(i) + "]"
		switch {
		case !model.IsHostname(d):
			es = append(es, model.FieldError{Path: p, Message: "must be a lowercase hostname"})
		case bound != nil && !within(d, bound):
			es = append(es, model.FieldError{Path: p, Message: "must be inside the parent group's domains"})
		}
	}
	return es.Err()
}

// manageParent fails unless the caller may create, move bounds of, or
// delete a child of parent: an admin of parent, or an instance admin for
// top-level groups.
func (ac *access) manageParent(parent string) error {
	return ac.requireIn(parent, auth.Admin)
}

func (a *api) createGroup(w http.ResponseWriter, r *http.Request, ac *access) {
	var req groupBody
	if err := a.decode(r, &req); err != nil {
		a.fail(w, err)
		return
	}
	if !nameOK(req.Name) {
		a.fail(w, model.FieldErrors{{Path: "name", Message: "must be 1-64 lowercase letters, digits, '.', '_' or '-'"}})
		return
	}
	if req.Parent != "" && ac.groups[req.Parent] == nil {
		a.fail(w, model.FieldErrors{{Path: "parent", Message: "no such group"}})
		return
	}
	if err := ac.manageParent(req.Parent); err != nil {
		a.fail(w, err)
		return
	}
	g := &store.Group{Name: req.Name, Parent: req.Parent, Description: req.Description}
	if req.Domains != nil {
		g.Domains = *req.Domains
	}
	if err := ac.checkDomains(g.Parent, g.Domains); err != nil {
		a.fail(w, err)
		return
	}
	if err := a.st.CreateGroup(r.Context(), g); err != nil {
		a.fail(w, err)
		return
	}
	a.audit(r, "group.create", g.ID, map[string]any{"name": g.Name, "parent": g.Parent, "domains": g.Domains})
	writeJSON(w, http.StatusCreated, g)
}

func (a *api) loadGroup(w http.ResponseWriter, r *http.Request, ac *access) (*store.Group, bool) {
	g := ac.groups[r.PathValue("id")]
	if g == nil || !ac.in(g.ID).Allows(auth.Viewer) {
		a.fail(w, store.ErrNotFound)
		return nil, false
	}
	return g, true
}

// updateGroup renames a group or changes its description (group admins)
// or its domains (admins of the parent, so a group cannot widen its own
// bound).
func (a *api) updateGroup(w http.ResponseWriter, r *http.Request, ac *access) {
	var req groupBody
	if err := a.decode(r, &req); err != nil {
		a.fail(w, err)
		return
	}
	g, ok := a.loadGroup(w, r, ac)
	if !ok {
		return
	}
	if req.Parent != "" && req.Parent != g.Parent {
		a.fail(w, model.FieldErrors{{Path: "parent", Message: "groups cannot move"}})
		return
	}
	if err := ac.requireIn(g.ID, auth.Admin); err != nil {
		a.fail(w, err)
		return
	}
	next := *g
	if req.Name != "" {
		if !nameOK(req.Name) {
			a.fail(w, model.FieldErrors{{Path: "name", Message: "must be 1-64 lowercase letters, digits, '.', '_' or '-'"}})
			return
		}
		next.Name = req.Name
	}
	next.Description = req.Description
	if req.Domains != nil {
		if err := ac.manageParent(g.Parent); err != nil {
			a.fail(w, err)
			return
		}
		if err := ac.checkDomains(g.Parent, *req.Domains); err != nil {
			a.fail(w, err)
			return
		}
		next.Domains = *req.Domains
	}
	if err := a.st.UpdateGroup(r.Context(), &next); err != nil {
		a.fail(w, err)
		return
	}
	a.audit(r, "group.update", g.ID, map[string]any{"name": next.Name, "domains": next.Domains})
	writeJSON(w, http.StatusOK, next)
}

func (a *api) deleteGroup(w http.ResponseWriter, r *http.Request, ac *access) {
	g, ok := a.loadGroup(w, r, ac)
	if !ok {
		return
	}
	if err := ac.manageParent(g.Parent); err != nil {
		a.fail(w, err)
		return
	}
	if err := a.st.DeleteGroup(r.Context(), g.ID); err != nil {
		if errors.Is(err, store.ErrGroupInUse) {
			err = httpError{status: http.StatusConflict, msg: err.Error()}
		}
		a.fail(w, err)
		return
	}
	a.audit(r, "group.delete", g.ID, map[string]any{"name": g.Name})
	w.WriteHeader(http.StatusNoContent)
}

// setMember adds a user by name to a group or changes their role there.
// Group admins manage members; nobody grants more than they hold.
func (a *api) setMember(w http.ResponseWriter, r *http.Request, ac *access) {
	var req struct {
		User string `json:"user"`
		Role string `json:"role"`
	}
	if err := a.decode(r, &req); err != nil {
		a.fail(w, err)
		return
	}
	g, ok := a.loadGroup(w, r, ac)
	if !ok {
		return
	}
	if err := ac.requireIn(g.ID, auth.Admin); err != nil {
		a.fail(w, err)
		return
	}
	role, err := auth.ParseGroupRole(req.Role)
	if err != nil {
		a.fail(w, model.FieldErrors{{Path: "role", Message: err.Error()}})
		return
	}
	if !ac.in(g.ID).Allows(role) {
		a.fail(w, httpError{status: http.StatusForbidden, msg: "cannot grant a role above your own"})
		return
	}
	u, err := a.st.UserByName(r.Context(), req.User)
	if errors.Is(err, store.ErrNotFound) {
		a.fail(w, model.FieldErrors{{Path: "user", Message: "no such user"}})
		return
	}
	if err != nil {
		a.fail(w, err)
		return
	}
	if err := a.st.SetMember(r.Context(), g.ID, u.ID, string(role)); err != nil {
		a.fail(w, err)
		return
	}
	a.audit(r, "group.member", g.ID, map[string]any{"user": u.ID, "name": u.Name, "role": role})
	writeJSON(w, http.StatusOK, store.Member{User: u.ID, Role: string(role)})
}

func (a *api) removeMember(w http.ResponseWriter, r *http.Request, ac *access) {
	g, ok := a.loadGroup(w, r, ac)
	if !ok {
		return
	}
	user := r.PathValue("user")
	if user != ac.p.user.ID {
		if err := ac.requireIn(g.ID, auth.Admin); err != nil {
			a.fail(w, err)
			return
		}
	}
	if err := a.st.RemoveMember(r.Context(), g.ID, user); err != nil {
		a.fail(w, err)
		return
	}
	a.audit(r, "group.member.remove", g.ID, map[string]any{"user": user})
	w.WriteHeader(http.StatusNoContent)
}

// directory lists account names and IDs, for picking group members.
func (a *api) directory(w http.ResponseWriter, r *http.Request, ac *access) {
	us, err := a.st.Users(r.Context())
	if err != nil {
		a.fail(w, err)
		return
	}
	type entry struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	out := make([]entry, len(us))
	for i, u := range us {
		out[i] = entry{u.ID, u.Name}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": out})
}

// topology returns the request-flow graph of the head, or of change set
// ?changeset as it would apply, with the resources the caller can read.
// ?format=mermaid or dot returns a diagram source instead of JSON.
func (a *api) topology(w http.ResponseWriter, r *http.Request, ac *access) {
	cfg, err := a.st.View(r.Context(), changeSetParam(r))
	if err != nil {
		a.fail(w, err)
		return
	}
	g := topology.Build(cfg, ac.canRead)
	switch f := r.URL.Query().Get("format"); f {
	case "", "json":
		writeJSON(w, http.StatusOK, g)
	case "mermaid":
		w.Header().Set("Content-Type", "text/vnd.mermaid; charset=utf-8")
		w.Write([]byte(topology.Mermaid(g)))
	case "dot":
		w.Header().Set("Content-Type", "text/vnd.graphviz; charset=utf-8")
		w.Write([]byte(topology.DOT(g)))
	default:
		a.fail(w, badRequest("format must be json, mermaid or dot"))
	}
}
