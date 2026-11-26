package model

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// schema.json must match the model; run go generate ./internal/model.
func TestSchemaUpToDate(t *testing.T) {
	// Generate into a copy so the checked-in file is left alone.
	dir := t.TempDir()
	srcs, _ := filepath.Glob("*.go")
	for _, f := range srcs {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, f), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.Command("go", "run", "schemagen.go")
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("schemagen: %v\n%s", err, out)
	}
	got, _ := os.ReadFile(filepath.Join(dir, "schema.json"))
	if !bytes.Equal(got, SchemaJSON) {
		t.Fatal("schema.json is stale; run go generate ./internal/model")
	}
}
