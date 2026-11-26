package api

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"

	"github.com/null-variable/proxelo/internal/auth"
	"github.com/null-variable/proxelo/internal/model"
	"github.com/null-variable/proxelo/internal/store"
)

// access answers what the request's principal may do with resources. A
// resource without a group falls under the instance role; a grouped one
// under the higher of the instance role and the member roles the principal
// holds in its group and the group's ancestors. API tokens cap both.
type access struct {
	p      *principal
	groups map[string]*store.Group
	// Effective group roles, inheritance applied.
	roles map[string]auth.Role
}

func (a *api) access(ctx context.Context, p *principal) (*access, error) {
	gs, err := a.st.Groups(ctx)
	if err != nil {
		return nil, err
	}
	ac := &access{p: p, groups: make(map[string]*store.Group, len(gs)), roles: map[string]auth.Role{}}
	for _, g := range gs {
		ac.groups[g.ID] = g
	}
	for _, g := range gs {
		var best auth.Role
		for cur := g; cur != nil; cur = ac.groups[cur.Parent] {
			for _, m := range cur.Members {
				if m.User == p.user.ID {
					best = best.Higher(auth.Role(m.Role))
				}
			}
		}
		if best != "" {
			ac.roles[g.ID] = best.Lower(p.cap)
		}
	}
	return ac, nil
}

// in is the principal's role on resources of group ("" for ungrouped).
func (ac *access) in(group string) auth.Role {
	if group == "" {
		return ac.p.role
	}
	return ac.p.role.Higher(ac.roles[group])
}

// highest is the principal's best role anywhere.
func (ac *access) highest() auth.Role {
	best := ac.p.role
	for _, r := range ac.roles {
		best = best.Higher(r)
	}
	return best
}

// shared kinds are infrastructure that group members attach their sites
// to; they read the ungrouped ones too.
var shared = map[string]bool{model.ListenerKind.Plural: true, model.CertificateKind.Plural: true}

func (ac *access) canRead(kind string, r model.Resource) bool {
	g := r.Common().Group
	if g == "" && shared[kind] && ac.highest().Allows(auth.Viewer) {
		return true
	}
	return ac.in(g).Allows(auth.Viewer)
}

// requireIn fails unless the principal has min on resources of group.
func (ac *access) requireIn(group string, min auth.Role) error {
	if ac.in(group).Allows(min) {
		return nil
	}
	where := "ungrouped resources"
	if g := ac.groups[group]; g != nil {
		where = "group " + g.Name
	}
	return httpError{status: http.StatusForbidden, msg: "requires role " + string(min) + " or higher on " + where}
}

// domains is the hostname bound of group: its own domains, else its
// nearest ancestor's. Nil means unbounded.
func (ac *access) domains(group string) []string {
	for g := ac.groups[group]; g != nil; g = ac.groups[g.Parent] {
		if len(g.Domains) > 0 {
			return g.Domains
		}
	}
	return nil
}

// within reports whether name is one of domains or under one.
func within(name string, domains []string) bool {
	for _, d := range domains {
		if name == d || strings.HasSuffix(name, "."+d) {
			return true
		}
	}
	return false
}

// checkResource checks the group of r exists and, for sites, that every
// hostname stays inside the group's domains.
func (ac *access) checkResource(r model.Resource) error {
	g := r.Common().Group
	if g == "" {
		return nil
	}
	if ac.groups[g] == nil {
		return model.FieldErrors{{Path: "group", Message: "no such group"}}
	}
	site, ok := r.(*model.Site)
	ds := ac.domains(g)
	if !ok || ds == nil {
		return nil
	}
	var es model.FieldErrors
	for i, h := range site.Spec.Hostnames {
		var ok bool
		switch {
		case h.Type == model.HostExact:
			ok = within(h.Value, ds)
		case h.Type == model.HostWildcard && strings.HasPrefix(h.Value, "*."):
			ok = within(h.Value[2:], ds)
		case h.Type == model.HostWildcard && strings.HasPrefix(h.Value, "."):
			ok = within(h.Value[1:], ds)
		}
		if !ok {
			es = append(es, model.FieldError{Path: "spec.hostnames[" + itoa(i) + "].value", Message: "must be inside the group's domains: " + strings.Join(ds, ", ")})
		}
	}
	if len(site.Spec.Hostnames) == 0 {
		es = append(es, model.FieldError{Path: "spec.hostnames", Message: "a site of a group with domains needs hostnames"})
	}
	return es.Err()
}

// groupRoles lists the principal's effective group roles for the UI.
func (ac *access) groupRoles() map[string]auth.Role {
	out := make(map[string]auth.Role, len(ac.roles))
	for id, r := range ac.roles {
		out[id] = r
	}
	return out
}

// visibleGroups are the groups the principal holds a role in, plus their
// ancestors for context; instance admins see every group.
func (ac *access) visibleGroups() []*store.Group {
	all := ac.p.role.Allows(auth.Admin)
	seen := map[string]bool{}
	for id := range ac.roles {
		for g := ac.groups[id]; g != nil && !seen[g.ID]; g = ac.groups[g.Parent] {
			seen[g.ID] = true
		}
	}
	out := []*store.Group{}
	for _, g := range ac.groups {
		if all || seen[g.ID] {
			out = append(out, g)
		}
	}
	slices.SortFunc(out, func(x, y *store.Group) int { return strings.Compare(x.Name, y.Name) })
	return out
}

// seesAll reports whether the principal reads ungrouped resources, and so
// every revision and change set.
func (ac *access) seesAll() bool { return ac.p.role.Allows(auth.Viewer) }

// seesGroups reports whether the principal reads one of groups.
func (ac *access) seesGroups(groups []string) bool {
	for _, g := range groups {
		if ac.in(g).Allows(auth.Viewer) {
			return true
		}
	}
	return false
}

// requireAny wraps h for principals whose best role, instance or group, is
// at least min. Handlers then check each resource with access.
func (a *api) requireAny(min auth.Role, h func(http.ResponseWriter, *http.Request, *access)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, err := a.authenticate(r)
		if err != nil {
			a.fail(w, err)
			return
		}
		ac, err := a.access(r.Context(), p)
		if err != nil {
			a.fail(w, err)
			return
		}
		if !ac.highest().Allows(min) {
			a.fail(w, httpError{status: http.StatusForbidden, msg: "requires role " + string(min) + " or higher"})
			return
		}
		h(w, r.WithContext(context.WithValue(r.Context(), principalKey{}, p)), ac)
	}
}

// mayWrite checks an edit that turns cur into next in change set cs; nil
// cur is a create, nil next a delete. The principal needs editor on the
// resource's group before and after, the group must admit it, and every
// reference it makes must point at a resource the principal can read.
func (a *api) mayWrite(r *http.Request, ac *access, cs string, cur, next model.Resource) error {
	if cur != nil {
		if err := ac.requireIn(cur.Common().Group, auth.Editor); err != nil {
			return err
		}
	}
	if next == nil {
		return nil
	}
	if err := ac.requireIn(next.Common().Group, auth.Editor); err != nil {
		return err
	}
	if err := ac.checkResource(next); err != nil {
		return err
	}
	if ac.in("").Allows(auth.Viewer) {
		return nil
	}
	var es model.FieldErrors
	for _, ref := range model.Refs(next) {
		k, _ := model.KindByPlural(ref.Kind)
		res, err := a.st.Get(r.Context(), cs, k, ref.ID)
		if errors.Is(err, store.ErrNotFound) {
			continue // compile reports missing references
		}
		if err != nil {
			return err
		}
		if !ac.canRead(ref.Kind, res) {
			es = append(es, model.FieldError{Path: ref.Field, Message: ref.ID + " is outside your groups"})
		}
	}
	return es.Err()
}

// requireItems fails unless the principal has min on the group of every
// resource change set cs touches, before and after.
func (a *api) requireItems(r *http.Request, ac *access, cs string, min auth.Role) error {
	items, err := a.st.Items(r.Context(), cs)
	if err != nil {
		return err
	}
	for _, it := range items {
		for _, res := range []model.Resource{it.Base, it.New} {
			if res == nil {
				continue
			}
			if err := ac.requireIn(res.Common().Group, min); err != nil {
				return err
			}
		}
	}
	return nil
}
