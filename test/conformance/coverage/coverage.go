// Package coverage reads and summarizes directives.yaml: every nginx
// directive and the Proxelo field that implements it. Which conformance
// cases exercise a directive is declared by the cases themselves.
package coverage

import (
	"bytes"
	"cmp"
	"fmt"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"
)

// Status is how far Proxelo implements a directive.
type Status string

const (
	// Implemented: every parameter and context of the directive has an
	// equivalent.
	Implemented Status = "implemented"
	// Partial: the common form works; Note says what is missing.
	Partial Status = "partial"
	// Fixed: Proxelo behaves as nginx with its default value, which cannot be
	// changed yet. Counts as missing in the coverage percentage.
	Fixed   Status = "fixed"
	Missing Status = "missing"
)

// Directive is one nginx directive.
type Directive struct {
	Name     string   `yaml:"name"`
	Module   string   `yaml:"module"`
	Contexts []string `yaml:"contexts,flow,omitempty"`
	Status   Status   `yaml:"status"`
	// Field is the resource field or proxy option that implements it, such as
	// "Route.spec.rewrite".
	Field string `yaml:"field,omitempty"`
	Note  string `yaml:"note,omitempty"`
}

// Key identifies a directive: the same name can exist in several modules
// (listen in http and stream).
func (d Directive) Key() string { return d.Module + "/" + d.Name }

// List is the content of directives.yaml.
type List struct {
	// Nginx is the version the list was extracted from.
	Nginx      string      `yaml:"nginx"`
	Directives []Directive `yaml:"directives"`
}

// Parse reads directives.yaml and checks its statuses.
func Parse(raw []byte) (List, error) {
	var l List
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&l); err != nil {
		return List{}, fmt.Errorf("directives.yaml: %w", err)
	}
	seen := map[string]bool{}
	for _, d := range l.Directives {
		switch d.Status {
		case Implemented, Partial, Fixed, Missing:
		default:
			return List{}, fmt.Errorf("directives.yaml: %s: unknown status %q", d.Key(), d.Status)
		}
		if (d.Status == Implemented || d.Status == Partial) && d.Field == "" {
			return List{}, fmt.Errorf("directives.yaml: %s is %s but names no field", d.Key(), d.Status)
		}
		if seen[d.Key()] {
			return List{}, fmt.Errorf("directives.yaml: %s listed twice", d.Key())
		}
		seen[d.Key()] = true
	}
	return l, nil
}

// Marshal writes the list in a stable order.
func (l List) Marshal() ([]byte, error) {
	var b bytes.Buffer
	b.WriteString("# nginx directives and their Proxelo equivalents. Regenerate the list\n")
	b.WriteString("# from an nginx checkout with `go run ./test/conformance/directives -src <dir>`;\n")
	b.WriteString("# it keeps status, field and note. See test/conformance/README.md.\n")
	enc := yaml.NewEncoder(&b)
	enc.SetIndent(2)
	if err := enc.Encode(l); err != nil {
		return nil, err
	}
	return b.Bytes(), enc.Close()
}

// Count is the number of directives per status.
type Count struct {
	Total, Implemented, Partial, Fixed, Tested int
}

// Percent is the share of implemented directives; partial ones count half.
func (c Count) Percent() float64 {
	if c.Total == 0 {
		return 0
	}
	return 100 * (float64(c.Implemented) + float64(c.Partial)/2) / float64(c.Total)
}

func (c *Count) add(d Directive, tested bool) {
	c.Total++
	switch d.Status {
	case Implemented:
		c.Implemented++
	case Partial:
		c.Partial++
	case Fixed:
		c.Fixed++
	}
	if tested {
		c.Tested++
	}
}

// Module is the count of one nginx module.
type Module struct {
	Name string
	Count
}

// Lookup resolves a directive reference from a conformance case:
// "module/name", or a bare name when exactly one HTTP module has it.
func (l List) Lookup(ref string) (Directive, error) {
	var hits []Directive
	for _, d := range l.Directives {
		if d.Key() == ref || d.Name == ref && strings.HasPrefix(d.Module, "ngx_http_") {
			hits = append(hits, d)
		}
	}
	switch len(hits) {
	case 1:
		return hits[0], nil
	case 0:
		return Directive{}, fmt.Errorf("directive %q is not in directives.yaml", ref)
	}
	keys := make([]string, len(hits))
	for i, d := range hits {
		keys[i] = d.Key()
	}
	return Directive{}, fmt.Errorf("directive %q is ambiguous: %s", ref, strings.Join(keys, ", "))
}

// Summary counts the whole list and each module. tested holds the keys of
// directives some conformance case exercises.
func (l List) Summary(tested map[string]bool) (Count, []Module) {
	var all Count
	by := map[string]*Count{}
	for _, d := range l.Directives {
		all.add(d, tested[d.Key()])
		if by[d.Module] == nil {
			by[d.Module] = &Count{}
		}
		by[d.Module].add(d, tested[d.Key()])
	}
	mods := make([]Module, 0, len(by))
	for name, c := range by {
		mods = append(mods, Module{Name: name, Count: *c})
	}
	slices.SortFunc(mods, func(a, b Module) int { return cmp.Compare(a.Name, b.Name) })
	return all, mods
}

// Markdown renders the summary as a report section.
func (l List) Markdown(tested map[string]bool) string {
	all, mods := l.Summary(tested)
	var b strings.Builder
	fmt.Fprintf(&b, "## Directive coverage (nginx %s)\n\n", l.Nginx)
	fmt.Fprintf(&b, "%d directives: %d implemented, %d partial, %d fixed at the nginx default, %d missing; %d with a conformance case. Coverage %.1f%% (partial counts half, fixed none).\n\n",
		all.Total, all.Implemented, all.Partial, all.Fixed, all.Total-all.Implemented-all.Partial-all.Fixed, all.Tested, all.Percent())
	b.WriteString("Modules with nothing implemented yet are left out.\n\n")
	b.WriteString("| Module | Directives | Implemented | Partial | Fixed | Tested | Coverage |\n|---|---|---|---|---|---|---|\n")
	for _, m := range mods {
		if m.Implemented+m.Partial+m.Fixed+m.Tested == 0 {
			continue
		}
		fmt.Fprintf(&b, "| `%s` | %d | %d | %d | %d | %d | %.0f%% |\n", m.Name, m.Total, m.Implemented, m.Partial, m.Fixed, m.Tested, m.Percent())
	}
	return b.String()
}
