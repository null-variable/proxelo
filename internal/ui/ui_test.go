package ui

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
)

func get(h http.Handler, path string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
	return w
}

func TestServe(t *testing.T) {
	h := Serve(fstest.MapFS{
		"index.html":          {Data: []byte(`<script type="module" src="/assets/index-abc.js"></script>`)},
		"assets/index-abc.js": {Data: []byte("export {}")},
		"theme.js":            {Data: []byte("")},
	})
	// Client-side routes get the app so reloads work.
	for _, p := range []string{"/", "/sites/site_x", "/changes"} {
		w := get(h, p)
		if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "/assets/index-abc.js") {
			t.Fatalf("%s: %d %.80q", p, w.Code, w.Body.String())
		}
		if csp := w.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "script-src 'self'") || strings.Contains(csp, "unsafe") {
			t.Fatalf("%s: CSP %q", p, csp)
		}
	}
	if w := get(h, "/assets/index-abc.js"); w.Code != http.StatusOK || !strings.Contains(w.Header().Get("Cache-Control"), "immutable") {
		t.Fatalf("asset: %d %q", w.Code, w.Header().Get("Cache-Control"))
	}
	if w := get(h, "/theme.js"); w.Header().Get("Cache-Control") != "no-cache" {
		t.Fatalf("theme.js cache: %q", w.Header().Get("Cache-Control"))
	}
	if w := get(h, "/missing.js"); w.Code != http.StatusNotFound {
		t.Fatalf("missing asset: %d", w.Code)
	}
}

func TestServeUnbuilt(t *testing.T) {
	if w := get(Serve(fstest.MapFS{".gitkeep": {}}), "/"); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("unbuilt: %d", w.Code)
	}
}
