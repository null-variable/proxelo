package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/null-variable/proxelo/internal/distrib"
	"github.com/null-variable/proxelo/internal/model"
	"github.com/null-variable/proxelo/internal/store"
)

// Live Tap limits.
const (
	tapMaxDuration = 30 * time.Minute
	tapMaxHeaders  = 16
)

// tapHeaderDenied are request headers Live Tap never shows: credentials.
var tapHeaderDenied = []string{"authorization", "proxy-authorization", "cookie", "x-api-key"}

// tap streams requests matching the query as server-sent events while the
// client stays connected: site, route and cidr (repeatable), sample (one
// in N) and header (request headers to show). Events are "request" with a
// JSON TapEvent and, every few seconds when proxies or this stream left
// some out, "dropped" with a count. Group members tap only sites they can
// read.
func (a *api) tap(w http.ResponseWriter, r *http.Request, ac *access) {
	q := r.URL.Query()
	f := distrib.TapFilter{Sites: q["site"], Routes: q["route"], CIDRs: q["cidr"]}
	if s := q.Get("sample"); s != "" {
		n, err := strconv.ParseUint(s, 10, 32)
		if err != nil || n == 0 {
			a.fail(w, badRequest("sample must be a positive number"))
			return
		}
		f.Sample = uint32(n)
	}
	for _, h := range q["header"] {
		h = strings.ToLower(strings.TrimSpace(h))
		if h == "" {
			continue
		}
		if !headerNameOK(h) {
			a.fail(w, badRequest("header %q is not a header name", h))
			return
		}
		for _, d := range tapHeaderDenied {
			if h == d {
				a.fail(w, badRequest("header %q holds credentials and is never shown", h))
				return
			}
		}
		f.Headers = append(f.Headers, h)
	}
	if len(f.Headers) > tapMaxHeaders {
		a.fail(w, badRequest("at most %d headers", tapMaxHeaders))
		return
	}
	if !ac.seesAll() {
		if len(f.Sites) == 0 {
			a.fail(w, httpError{status: http.StatusForbidden, msg: "choose sites to tap; you can read only some"})
			return
		}
		for _, id := range f.Sites {
			site, err := a.st.Get(r.Context(), "", model.SiteKind, id)
			if err == nil && !ac.canRead(model.SiteKind.Plural, site) {
				err = store.ErrNotFound
			}
			if err != nil {
				a.fail(w, err)
				return
			}
		}
	}
	td, ok := a.d.(Tapper)
	if !ok {
		a.fail(w, httpError{status: http.StatusServiceUnavailable, msg: "live tap is not available"})
		return
	}
	t, err := td.StartTap(f)
	if err != nil {
		a.fail(w, badRequest("cidr: %v", err))
		return
	}
	defer td.StopTap(t)
	fl, ok := w.(http.Flusher)
	if !ok {
		a.fail(w, httpError{status: http.StatusInternalServerError, msg: "streaming unsupported"})
		return
	}
	a.audit(r, "tap.start", "", map[string]any{"sites": f.Sites, "routes": f.Routes, "cidrs": f.CIDRs, "headers": f.Headers})
	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, ": tapping\n\n")
	fl.Flush()

	ctx := r.Context()
	end := time.NewTimer(tapMaxDuration)
	defer end.Stop()
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-end.C:
			fmt.Fprint(w, "event: end\ndata: {\"reason\":\"time limit\"}\n\n")
			fl.Flush()
			return
		case e := <-t.C:
			b, err := json.Marshal(tapJSON(e))
			if err != nil {
				continue
			}
			fmt.Fprintf(w, "event: request\ndata: %s\n\n", b)
			// Batch what is queued into one flush.
			for more := true; more; {
				select {
				case e := <-t.C:
					if b, err := json.Marshal(tapJSON(e)); err == nil {
						fmt.Fprintf(w, "event: request\ndata: %s\n\n", b)
					}
				default:
					more = false
				}
			}
			fl.Flush()
		case <-tick.C:
			if n := t.Dropped(); n > 0 {
				fmt.Fprintf(w, "event: dropped\ndata: {\"count\":%d}\n\n", n)
			} else {
				// Keeps idle connections through intermediaries.
				fmt.Fprint(w, ": ping\n\n")
			}
			fl.Flush()
		}
	}
}

// Tapper is the Live Tap side of the distributor.
type Tapper interface {
	StartTap(distrib.TapFilter) (*distrib.Tap, error)
	StopTap(*distrib.Tap)
}

type tapEvent struct {
	Time           time.Time         `json:"time"`
	Node           string            `json:"node"`
	Site           string            `json:"site"`
	Route          string            `json:"route,omitempty"`
	Client         string            `json:"client"`
	Method         string            `json:"method"`
	Host           string            `json:"host"`
	URI            string            `json:"uri"`
	Protocol       string            `json:"protocol"`
	Status         uint32            `json:"status"`
	DurationMS     float64           `json:"durationMs"`
	Upstream       string            `json:"upstream,omitempty"`
	UpstreamStatus uint32            `json:"upstreamStatus,omitempty"`
	BytesSent      uint64            `json:"bytesSent"`
	Headers        map[string]string `json:"headers,omitempty"`
}

func tapJSON(e distrib.TapEvent) tapEvent {
	out := tapEvent{
		Time: time.UnixMicro(e.GetTimeUs()).UTC(), Node: e.Node, Site: e.GetSiteId(), Route: e.GetRouteId(),
		Client: e.GetClient(), Method: e.GetMethod(), Host: e.GetHost(), URI: e.GetUri(), Protocol: e.GetProtocol(),
		Status: e.GetStatus(), DurationMS: float64(e.GetDurationUs()) / 1000, Upstream: e.GetUpstream(),
		UpstreamStatus: e.GetUpstreamStatus(), BytesSent: e.GetBytesSent(),
	}
	if hs := e.GetHeaders(); len(hs) > 0 {
		out.Headers = make(map[string]string, len(hs))
		for _, h := range hs {
			out.Headers[h.GetName()] = h.GetValue()
		}
	}
	return out
}

func headerNameOK(s string) bool {
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return s != ""
}
