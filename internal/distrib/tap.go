package distrib

import (
	"net/netip"
	"slices"
	"strconv"
	"sync"

	distribv1 "github.com/null-variable/proxelo-api/gen/go/proxelo/distrib/v1"
)

// TapFilter selects requests for one Live Tap viewer. Empty lists match
// anything.
type TapFilter struct {
	Sites  []string `json:"sites,omitempty"`
	Routes []string `json:"routes,omitempty"`
	CIDRs  []string `json:"cidrs,omitempty"`
	// Report one in Sample matching requests; 0 and 1 report all.
	Sample uint32 `json:"sample,omitempty"`
	// Request headers whose values are shown, lowercase.
	Headers []string `json:"headers,omitempty"`
}

// TapEvent is one tapped request.
type TapEvent struct {
	Node string `json:"node"`
	*distribv1.TapEvent
}

// Tap is one viewer's subscription. Events arrive on C; Dropped counts
// those the viewer did not take in time or the proxies left out.
type Tap struct {
	C       <-chan TapEvent
	c       chan TapEvent
	filter  TapFilter
	prefix  []netip.Prefix
	mu      sync.Mutex
	dropped uint64
	// Matching events seen, for this viewer's own sampling.
	seen uint64
}

// Dropped returns and resets the count of events not delivered.
func (t *Tap) Dropped() uint64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	n := t.dropped
	t.dropped = 0
	return n
}

func (t *Tap) drop(n uint64) {
	t.mu.Lock()
	t.dropped += n
	t.mu.Unlock()
}

func (t *Tap) matches(e *distribv1.TapEvent) bool {
	f := &t.filter
	if len(f.Sites) > 0 && !slices.Contains(f.Sites, e.GetSiteId()) {
		return false
	}
	if len(f.Routes) > 0 && !slices.Contains(f.Routes, e.GetRouteId()) {
		return false
	}
	if len(t.prefix) > 0 {
		ip, err := netip.ParseAddr(e.GetClient())
		if err != nil {
			return false
		}
		ip = ip.Unmap()
		if !slices.ContainsFunc(t.prefix, func(p netip.Prefix) bool { return p.Contains(ip) }) {
			return false
		}
	}
	return true
}

// taps are the open viewers; the proxies get their union.
type taps struct {
	mu   sync.Mutex
	list []*Tap
	// Bumped on every change, so filters sent to proxies are told apart.
	gen uint64
	// The union filter, nil when no tap is open.
	union *distribv1.TapFilter
}

// StartTap opens a viewer. Close it with StopTap.
func (d *Distributor) StartTap(f TapFilter) (*Tap, error) {
	t := &Tap{filter: f}
	for _, c := range f.CIDRs {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			a, aerr := netip.ParseAddr(c)
			if aerr != nil {
				return nil, err
			}
			p = netip.PrefixFrom(a, a.BitLen())
		}
		t.prefix = append(t.prefix, p.Masked())
	}
	t.c = make(chan TapEvent, 256)
	t.C = t.c
	d.taps.mu.Lock()
	d.taps.list = append(d.taps.list, t)
	d.retap()
	d.taps.mu.Unlock()
	d.mu.Lock()
	d.wakeAll()
	d.mu.Unlock()
	return t, nil
}

// StopTap closes a viewer; when it was the last, proxies stop tapping.
func (d *Distributor) StopTap(t *Tap) {
	d.taps.mu.Lock()
	d.taps.list = slices.DeleteFunc(d.taps.list, func(x *Tap) bool { return x == t })
	d.retap()
	d.taps.mu.Unlock()
	d.mu.Lock()
	d.wakeAll()
	d.mu.Unlock()
}

// retap recomputes the union filter. Callers hold taps.mu.
func (d *Distributor) retap() {
	d.taps.gen++
	if len(d.taps.list) == 0 {
		d.taps.union = nil
		return
	}
	u := &distribv1.TapFilter{Id: "tap-" + strconv.FormatUint(d.taps.gen, 10), Sample: 1}
	// A list narrows the union only when every viewer narrows it.
	all := func(get func(*TapFilter) []string) []string {
		var out []string
		for _, t := range d.taps.list {
			v := get(&t.filter)
			if len(v) == 0 {
				return nil
			}
			for _, s := range v {
				if !slices.Contains(out, s) {
					out = append(out, s)
				}
			}
		}
		return out
	}
	u.SiteIds = all(func(f *TapFilter) []string { return f.Sites })
	u.RouteIds = all(func(f *TapFilter) []string { return f.Routes })
	u.Cidrs = all(func(f *TapFilter) []string { return f.CIDRs })
	// Sampling: the densest viewer decides.
	sample := uint32(0)
	for i, t := range d.taps.list {
		s := max(t.filter.Sample, 1)
		if i == 0 || s < sample {
			sample = s
		}
		for _, h := range t.filter.Headers {
			if !slices.Contains(u.Headers, h) {
				u.Headers = append(u.Headers, h)
			}
		}
	}
	u.Sample = sample
	d.taps.union = u
}

// tapFilter is the filter proxies should run, an empty one when none.
func (d *Distributor) tapFilter() *distribv1.TapFilter {
	d.taps.mu.Lock()
	defer d.taps.mu.Unlock()
	if d.taps.union == nil {
		return &distribv1.TapFilter{}
	}
	return d.taps.union
}

// deliver hands a proxy's batch to the viewers it matches.
func (d *Distributor) deliver(node string, b *distribv1.TapEvents) {
	d.taps.mu.Lock()
	defer d.taps.mu.Unlock()
	if d.taps.union == nil || b.GetTapId() != d.taps.union.GetId() {
		// From a filter since replaced.
		return
	}
	for _, t := range d.taps.list {
		if b.GetDropped() > 0 {
			t.drop(b.GetDropped())
		}
		for _, e := range b.GetEvents() {
			if !t.matches(e) {
				continue
			}
			// The proxies sample for the densest viewer; sparser ones
			// thin out further here.
			t.seen++
			if s := uint64(max(t.filter.Sample, 1)); s > 1 && (t.seen-1)%s != 0 {
				continue
			}
			select {
			case t.c <- TapEvent{Node: node, TapEvent: e}:
			default:
				t.drop(1)
			}
		}
	}
}
