package diff

import (
	"encoding/json"
	"reflect"
	"testing"
)

func doc(s string) any {
	var v any
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		panic(err)
	}
	return v
}

func TestCompare(t *testing.T) {
	got := Compare(doc(`{"a":1,"b":{"c":"x","d":[1]},"e":true}`), doc(`{"a":1,"b":{"c":"y","d":[1,2]},"f":null}`))
	want := []Change{
		{Path: "b.c", Old: "x", New: "y"},
		{Path: "b.d", Old: []any{1.0}, New: []any{1.0, 2.0}},
		{Path: "e", Old: true},
		{Path: "f"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v", got)
	}
}

func TestMerge3(t *testing.T) {
	base := doc(`{"a":1,"b":{"c":1,"d":1},"x":1}`)
	ours := doc(`{"a":2,"b":{"c":1,"d":2},"x":1}`)
	theirs := doc(`{"a":1,"b":{"c":3,"d":1},"y":1}`)
	got, conflicts := Merge3(base, ours, theirs)
	if len(conflicts) != 0 {
		t.Fatalf("conflicts %v", conflicts)
	}
	if want := doc(`{"a":2,"b":{"c":3,"d":2},"y":1}`); !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v", got)
	}
	_, conflicts = Merge3(base, doc(`{"a":2}`), doc(`{"a":3}`))
	if !reflect.DeepEqual(conflicts, []string{"a"}) {
		t.Fatalf("conflicts %v", conflicts)
	}
}
