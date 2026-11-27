package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
)

func TestWasmModules(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "t.db"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	b := []byte("\x00asm\x01\x00\x00\x00")
	m, err := st.PutWasm(ctx, "empty", b)
	if err != nil {
		t.Fatal(err)
	}
	if m.SHA256 != "93a44bbb96c751218e4c00d479e4c14358122a389acca16205b1e4d0dc5f9476" || m.Size != 8 {
		t.Fatalf("module = %+v", m)
	}
	// The same bytes again keep the first name.
	if again, err := st.PutWasm(ctx, "other", b); err != nil || again.Name != "empty" {
		t.Fatalf("again = %+v, %v", again, err)
	}
	if got, err := st.WasmBytes(ctx, m.SHA256); err != nil || string(got) != string(b) {
		t.Fatalf("bytes = %q, %v", got, err)
	}
	if ms, _ := st.WasmModules(ctx); len(ms) != 1 {
		t.Fatalf("list = %v", ms)
	}
	if err := st.DeleteWasm(ctx, m.SHA256); err != nil {
		t.Fatal(err)
	}
	if _, err := st.WasmBytes(ctx, m.SHA256); !errors.Is(err, ErrNotFound) {
		t.Fatalf("after delete: %v", err)
	}
}
