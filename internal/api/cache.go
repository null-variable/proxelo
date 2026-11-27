package api

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	distribv1 "github.com/null-variable/proxelo-api/gen/go/proxelo/distrib/v1"

	"github.com/null-variable/proxelo/internal/distrib"
)

// Purger is the cache purge side of the distributor.
type Purger interface {
	Purge(ctx context.Context, p *distribv1.Purge) ([]distrib.PurgeResult, error)
}

// purgeTimeout bounds the wait for every proxy's answer.
const purgeTimeout = 30 * time.Second

// purge removes responses of a cache policy's zone on every proxy:
// POST /api/v1/cache/{zone}:purge with keys, key prefixes, Cache-Tag values
// or all.
func (a *api) purge(w http.ResponseWriter, r *http.Request, zone string) {
	pd, ok := a.d.(Purger)
	if !ok {
		a.fail(w, httpError{status: http.StatusServiceUnavailable, msg: "cache purge is not available"})
		return
	}
	var req struct {
		Keys     []string `json:"keys"`
		Prefixes []string `json:"prefixes"`
		Tags     []string `json:"tags"`
		All      bool     `json:"all"`
	}
	if err := a.decode(r, &req); err != nil {
		a.fail(w, err)
		return
	}
	if !req.All && len(req.Keys) == 0 && len(req.Prefixes) == 0 && len(req.Tags) == 0 {
		a.fail(w, badRequest("give keys, prefixes, tags or all"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), purgeTimeout)
	defer cancel()
	res, err := pd.Purge(ctx, &distribv1.Purge{ZoneId: zone, Keys: req.Keys, Prefixes: req.Prefixes, Tags: req.Tags, All: req.All})
	if errors.Is(err, distrib.ErrNoNodes) {
		a.fail(w, httpError{status: http.StatusServiceUnavailable, msg: err.Error()})
		return
	}
	if err != nil {
		a.fail(w, err)
		return
	}
	var removed uint64
	for _, n := range res {
		removed += n.Removed
	}
	a.audit(r, "cache.purge", zone, map[string]any{
		"keys": len(req.Keys), "prefixes": len(req.Prefixes), "tags": len(req.Tags), "all": req.All, "removed": removed,
	})
	writeJSON(w, http.StatusOK, map[string]any{"removed": removed, "nodes": res})
}

// purgeRoute serves {zone}:purge; ServeMux patterns cannot hold the colon
// suffix of a wildcard.
func (a *api) purgeRoute(w http.ResponseWriter, r *http.Request) {
	zone, ok := strings.CutSuffix(r.PathValue("zone"), ":purge")
	if !ok || zone == "" {
		a.fail(w, httpError{status: http.StatusNotFound, msg: "not found"})
		return
	}
	a.purge(w, r, zone)
}
