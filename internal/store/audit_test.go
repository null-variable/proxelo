package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
)

func TestAuditChain(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	for i := range 3 {
		if _, err := st.Audit(ctx, "owner", "test", "x", map[string]int{"i": i}); err != nil {
			t.Fatal(err)
		}
	}
	if n, err := st.VerifyAudit(ctx); err != nil || n != 3 {
		t.Fatalf("verify = %d, %v", n, err)
	}
	if _, err := st.db.Exec(`UPDATE audit SET actor = 'mallory' WHERE seq = 2`); err != nil {
		t.Fatal(err)
	}
	if n, err := st.VerifyAudit(ctx); !errors.Is(err, ErrAuditChain) || n != 1 {
		t.Fatalf("tampered verify = %d, %v", n, err)
	}
}
