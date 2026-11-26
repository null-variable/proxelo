// Package ui serves the web console built from web/ (Vite,
// React, TypeScript) into dist/ and embedded into the binary. Build it with
// `bun install && bun run build` in web/ (or go generate ./internal/ui)
// before go build; without it the console answers 503.
package ui

//go:generate sh -c "cd ../../web && bun install --frozen-lockfile && bun run build"

import (
	"embed"
	"io/fs"
	"net/http"
	"path"
	"strings"
)

//go:embed all:dist
var dist embed.FS

// Handler serves the embedded console at /.
func Handler() http.Handler {
	root, err := fs.Sub(dist, "dist")
	if err != nil {
		panic(err)
	}
	return Serve(root)
}

// Serve serves the console in root. Paths without a file extension get
// index.html, so client-side routes survive a reload. Hashed assets are
// cached for good; everything else is revalidated.
func Serve(root fs.FS) http.Handler {
	fileServer := http.FileServerFS(root)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		// Everything is same-origin; no inline scripts or styles.
		h.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Frame-Options", "DENY")
		p := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
		if p == "" || path.Ext(p) == "" {
			if _, err := fs.Stat(root, "index.html"); err != nil {
				http.Error(w, "web console not built: run `bun install && bun run build` in web/, then rebuild proxelo", http.StatusServiceUnavailable)
				return
			}
			h.Set("Cache-Control", "no-cache")
			r = r.Clone(r.Context())
			r.URL.Path = "/"
		} else if _, err := fs.Stat(root, p); err != nil {
			http.NotFound(w, r)
			return
		} else if strings.HasPrefix(p, "assets/") {
			h.Set("Cache-Control", "public, max-age=31536000, immutable")
		} else {
			h.Set("Cache-Control", "no-cache")
		}
		fileServer.ServeHTTP(w, r)
	})
}
