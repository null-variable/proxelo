package compile

import (
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	simv1 "github.com/null-variable/proxelo-api/gen/go/proxelo/sim/v1"
	"google.golang.org/protobuf/proto"

	"github.com/null-variable/proxelo/internal/model"
	"github.com/null-variable/proxelo/internal/simulate"
)

// TestRoundTrip compiles every configuration in testdata/ and examples/,
// and has the proxy at $PROXELO_PROXY load it with its serving code (through
// the sim helper) and route a request. It checks that what Go writes is what
// the proxy reads: the IR contract between the two repositories. CI runs it
// against the proxy's main branch and its latest release.
func TestRoundTrip(t *testing.T) {
	bin := os.Getenv("PROXELO_PROXY")
	if bin == "" {
		t.Skip("PROXELO_PROXY is not set")
	}
	helper := simulate.New(bin, slog.New(slog.DiscardHandler))
	defer helper.Close()

	files, _ := filepath.Glob("testdata/*.json")
	examples, _ := filepath.Glob("../../examples/*.json")
	files = append(files, examples...)
	if len(files) == 0 {
		t.Fatal("no configurations found")
	}
	for _, f := range files {
		t.Run(f, func(t *testing.T) {
			raw, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			var cfg model.Config
			if err := json.Unmarshal(raw, &cfg); err != nil {
				t.Fatal(err)
			}
			snap, err := Compile(cfg, 7)
			if err != nil {
				t.Fatal(err)
			}
			b, err := proto.MarshalOptions{Deterministic: true}.Marshal(snap)
			if err != nil {
				t.Fatal(err)
			}
			if err := helper.DryLoad(b); err != nil {
				t.Fatalf("proxy rejects the snapshot: %v", err)
			}
			// One request per site, to its first hostname: the proxy must
			// resolve it to the same site ID the control plane compiled.
			var reqs []*simv1.HttpRequest
			var want []string
			for _, s := range cfg.Sites {
				if len(s.Spec.Hostnames) == 0 || s.Spec.Hostnames[0].Type != model.HostExact {
					continue
				}
				reqs = append(reqs, &simv1.HttpRequest{
					Listener: s.Spec.Listeners[0],
					Target:   "/",
					Headers:  []*simv1.Header{{Name: "Host", Value: s.Spec.Hostnames[0].Value}},
				})
				want = append(want, s.ID)
			}
			if len(reqs) == 0 {
				return
			}
			resp, err := helper.Run(b, reqs)
			if err != nil {
				t.Fatal(err)
			}
			if len(resp.Results) != len(reqs) {
				t.Fatalf("%d results for %d requests", len(resp.Results), len(reqs))
			}
			for i, r := range resp.Results {
				if r.Site != want[i] {
					t.Errorf("Host %s: proxy picked site %q, compiled for %q", reqs[i].Headers[0].Value, r.Site, want[i])
				}
			}
		})
	}
}
