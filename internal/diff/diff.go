// Package diff compares and merges JSON documents decoded into any (maps,
// slices, strings, float64s, bools and nil). Objects are compared key by
// key; arrays and scalars are compared as whole values.
package diff

import (
	"encoding/json"
	"maps"
	"reflect"
	"slices"
	"strings"
)

// Change is one differing value. A missing side is nil.
type Change struct {
	Path string `json:"path"`
	Old  any    `json:"old,omitempty"`
	New  any    `json:"new,omitempty"`
}

// Doc decodes v's JSON form into a generic document.
func Doc(v any) any {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err) // only called on types that always marshal
	}
	var out any
	if err := json.Unmarshal(b, &out); err != nil {
		panic(err)
	}
	return out
}

// absent marks a key missing from an object.
type absent struct{}

func get(m map[string]any, k string) any {
	if v, ok := m[k]; ok {
		return v
	}
	return absent{}
}

func join(path, k string) string {
	if path == "" {
		return k
	}
	return path + "." + k
}

func clean(v any) any {
	if _, ok := v.(absent); ok {
		return nil
	}
	return v
}

// Compare returns the changes from a to b in path order.
func Compare(a, b any) []Change {
	var out []Change
	compare("", a, b, &out)
	return out
}

func compare(path string, a, b any, out *[]Change) {
	am, aok := a.(map[string]any)
	bm, bok := b.(map[string]any)
	if aok && bok {
		keys := slices.Sorted(maps.Keys(am))
		for k := range bm {
			if _, ok := am[k]; !ok {
				keys = append(keys, k)
			}
		}
		slices.Sort(keys)
		for _, k := range keys {
			compare(join(path, k), get(am, k), get(bm, k), out)
		}
		return
	}
	if !reflect.DeepEqual(a, b) {
		*out = append(*out, Change{Path: path, Old: clean(a), New: clean(b)})
	}
}

// Merge3 merges the changes from base to ours and from base to theirs. A
// value both sides changed differently is a conflict; ours is kept there.
func Merge3(base, ours, theirs any) (any, []string) {
	var conflicts []string
	v := merge3("", base, ours, theirs, &conflicts)
	return clean(v), conflicts
}

func merge3(path string, base, ours, theirs any, conflicts *[]string) any {
	switch {
	case reflect.DeepEqual(ours, theirs):
		return ours
	case reflect.DeepEqual(base, ours):
		return theirs
	case reflect.DeepEqual(base, theirs):
		return ours
	}
	bm, bok := base.(map[string]any)
	om, ook := ours.(map[string]any)
	tm, tok := theirs.(map[string]any)
	if ook && tok {
		if !bok {
			bm = map[string]any{}
		}
		out := map[string]any{}
		keys := map[string]bool{}
		for _, m := range []map[string]any{bm, om, tm} {
			for k := range m {
				keys[k] = true
			}
		}
		for _, k := range slices.Sorted(maps.Keys(keys)) {
			v := merge3(join(path, k), get(bm, k), get(om, k), get(tm, k), conflicts)
			if _, gone := v.(absent); !gone {
				out[k] = v
			}
		}
		return out
	}
	*conflicts = append(*conflicts, path)
	return ours
}

// Redact replaces the values of changes whose last path element is one of
// keys, for logs that must not hold secrets.
func Redact(cs []Change, keys ...string) []Change {
	for i, c := range cs {
		last := c.Path[strings.LastIndex(c.Path, ".")+1:]
		if slices.Contains(keys, last) {
			if cs[i].Old != nil {
				cs[i].Old = "<redacted>"
			}
			if cs[i].New != nil {
				cs[i].New = "<redacted>"
			}
		}
	}
	return cs
}
