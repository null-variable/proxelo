package coverage

import (
	"os"
	"strings"
	"testing"
)

func TestParseRejects(t *testing.T) {
	for name, src := range map[string]string{
		"unknown status": "nginx: 1\ndirectives:\n  - {name: a, module: m, status: done}\n",
		"no field":       "nginx: 1\ndirectives:\n  - {name: a, module: m, status: implemented}\n",
		"duplicate":      "nginx: 1\ndirectives:\n  - {name: a, module: m, status: missing}\n  - {name: a, module: m, status: missing}\n",
		"unknown key":    "nginx: 1\ndirectives:\n  - {name: a, module: m, status: missing, cases: [x]}\n",
	} {
		if _, err := Parse([]byte(src)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestLookupAndSummary(t *testing.T) {
	l := List{Nginx: "1", Directives: []Directive{
		{Name: "listen", Module: "ngx_http_core_module", Status: Partial, Field: "f"},
		{Name: "listen", Module: "ngx_stream_core_module", Status: Missing},
		{Name: "server", Module: "ngx_http_core_module", Status: Implemented, Field: "f"},
		{Name: "server", Module: "ngx_http_upstream_module", Status: Missing},
		{Name: "keepalive_timeout", Module: "ngx_http_core_module", Status: Fixed},
	}}
	d, err := l.Lookup("listen")
	if err != nil || d.Module != "ngx_http_core_module" {
		t.Errorf("listen: %v %v", d, err)
	}
	if _, err := l.Lookup("server"); err == nil || !strings.Contains(err.Error(), "ambiguous") {
		t.Errorf("server: %v", err)
	}
	if d, err := l.Lookup("ngx_http_upstream_module/server"); err != nil || d.Status != Missing {
		t.Errorf("module/server: %v %v", d, err)
	}
	if _, err := l.Lookup("nope"); err == nil {
		t.Error("unknown directive found")
	}

	all, mods := l.Summary(map[string]bool{"ngx_http_core_module/server": true})
	if all.Total != 5 || all.Implemented != 1 || all.Partial != 1 || all.Fixed != 1 || all.Tested != 1 {
		t.Errorf("summary %+v", all)
	}
	// 1 + ½ of 5.
	if got := all.Percent(); got != 30 {
		t.Errorf("percent %v", got)
	}
	if len(mods) != 3 || mods[0].Name != "ngx_http_core_module" || mods[0].Total != 3 {
		t.Errorf("modules %+v", mods)
	}
}

// The checked-in list parses, and every case refers to directives in it.
func TestDirectivesFile(t *testing.T) {
	raw, err := os.ReadFile("../directives.yaml")
	if err != nil {
		t.Fatal(err)
	}
	l, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(l.Directives) < 700 {
		t.Errorf("only %d directives", len(l.Directives))
	}
	out, err := l.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != string(raw) {
		t.Error("directives.yaml is not in the generated form; run ./test/conformance/directives")
	}
}
