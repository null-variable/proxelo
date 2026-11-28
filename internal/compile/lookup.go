package compile

import (
	"cmp"
	"encoding/hex"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	snapshotv1 "github.com/null-variable/proxelo-api/gen/go/proxelo/snapshot/v1"

	"github.com/null-variable/proxelo/internal/model"
)

// Variable references in a template: $name or ${name}.
var varRefRE = regexp.MustCompile(`\$\{?([a-zA-Z0-9_]+)`)

// Prefixes of the proxy's built-in variable families; a lookup may not take
// such a name.
var builtinPrefixes = []string{"http_", "sent_http_", "arg_", "cookie_", "upstream_http_", "upstream_cookie_"}

// lookups compiles the enabled lookups so that each one comes after the
// lookups it uses, as the proxy requires.
func (c *compiler) lookups(ix index[*model.Lookup]) []*snapshotv1.Lookup {
	byVar := map[string]*model.Lookup{}
	var order []*model.Lookup
	for _, l := range ix.items {
		v := l.VariableName()
		path := fmt.Sprintf("lookups[%s].spec.variable", l.ID)
		if o, dup := byVar[v]; dup {
			c.add(path, "$%s is already defined by lookup %q", v, o.ID)
			continue
		}
		for _, p := range builtinPrefixes {
			if strings.HasPrefix(v, p) {
				c.add(path, "$%s is a built-in variable", v)
			}
		}
		byVar[v] = l
		order = append(order, l)
	}
	deps := func(l *model.Lookup) []string {
		var out []string
		for _, t := range lookupTemplates(l) {
			for _, m := range varRefRE.FindAllStringSubmatch(t, -1) {
				if _, ok := byVar[m[1]]; ok && !slices.Contains(out, m[1]) {
					out = append(out, m[1])
				}
			}
		}
		return out
	}
	const (
		unseen = iota
		visiting
		done
	)
	state := map[string]int{}
	var out []*snapshotv1.Lookup
	var visit func(l *model.Lookup) bool
	visit = func(l *model.Lookup) bool {
		v := l.VariableName()
		switch state[v] {
		case done:
			return true
		case visiting:
			c.add(fmt.Sprintf("lookups[%s].spec", l.ID), "$%s depends on itself", v)
			return false
		}
		state[v] = visiting
		for _, d := range deps(l) {
			if !visit(byVar[d]) {
				state[v] = done
				return false
			}
		}
		state[v] = done
		if lk := lookup(l); lk != nil {
			out = append(out, lk)
		}
		return true
	}
	for _, l := range order {
		visit(l)
	}
	return out
}

func lookupTemplates(l *model.Lookup) []string {
	s := l.Spec
	out := []string{s.Source}
	switch {
	case s.Map != nil:
		out = append(out, s.Map.Default)
		for _, e := range s.Map.Entries {
			out = append(out, e.Value)
		}
	case s.Geo != nil:
		out = append(out, s.Geo.Default)
		for _, e := range s.Geo.Entries {
			out = append(out, e.Value)
		}
	case s.Split != nil:
		for _, b := range s.Split.Buckets {
			out = append(out, b.Value)
		}
	}
	return out
}

var mapKinds = map[model.MapMatch]snapshotv1.LookupMapEntry_Kind{
	"":               snapshotv1.LookupMapEntry_KIND_EXACT,
	model.MapExact:   snapshotv1.LookupMapEntry_KIND_EXACT,
	model.MapRegex:   snapshotv1.LookupMapEntry_KIND_REGEX,
	model.MapRegexCI: snapshotv1.LookupMapEntry_KIND_REGEX_CI,
}

func lookup(l *model.Lookup) *snapshotv1.Lookup {
	s := l.Spec
	out := &snapshotv1.Lookup{Name: l.VariableName(), Source: s.Source}
	switch {
	case s.Type == model.LookupMap && s.Map != nil:
		m := &snapshotv1.LookupMap{Default: s.Map.Default, Hostnames: s.Map.Hostnames}
		for _, e := range s.Map.Entries {
			m.Entries = append(m.Entries, &snapshotv1.LookupMapEntry{Kind: mapKinds[e.Match], Key: e.Key, Value: e.Value})
		}
		out.Kind = &snapshotv1.Lookup_Map{Map: m}
	case s.Type == model.LookupGeo && s.Geo != nil:
		if out.Source == "" {
			out.Source = "$remote_addr"
		}
		g := &snapshotv1.LookupGeo{Default: s.Geo.Default}
		for _, e := range s.Geo.Entries {
			n, _ := model.ParseNetwork(e.Network)
			g.Entries = append(g.Entries, &snapshotv1.LookupGeoEntry{Cidr: n.String(), Value: e.Value})
		}
		out.Kind = &snapshotv1.Lookup_Geo{Geo: g}
	case s.Type == model.LookupSplit && s.Split != nil:
		sp := &snapshotv1.LookupSplit{}
		for _, b := range s.Split.Buckets {
			bp, _ := model.ParsePercent(b.Percent) // "*" is 0, the rest
			sp.Parts = append(sp.Parts, &snapshotv1.LookupSplitPart{BasisPoints: bp, Value: b.Value})
		}
		out.Kind = &snapshotv1.Lookup_Split{Split: sp}
	default:
		return nil // reported by model.Validate
	}
	return out
}

var encodings = map[string]snapshotv1.Compression_Encoding{
	"gzip": snapshotv1.Compression_ENCODING_GZIP,
	"br":   snapshotv1.Compression_ENCODING_BROTLI,
	"zstd": snapshotv1.Compression_ENCODING_ZSTD,
}

var proxiedFlags = map[string]snapshotv1.Compression_Proxied{
	"expired":          snapshotv1.Compression_PROXIED_EXPIRED,
	"no-cache":         snapshotv1.Compression_PROXIED_NO_CACHE,
	"no-store":         snapshotv1.Compression_PROXIED_NO_STORE,
	"private":          snapshotv1.Compression_PROXIED_PRIVATE,
	"no_last_modified": snapshotv1.Compression_PROXIED_NO_LAST_MODIFIED,
	"no_etag":          snapshotv1.Compression_PROXIED_NO_ETAG,
	"auth":             snapshotv1.Compression_PROXIED_AUTH,
	"any":              snapshotv1.Compression_PROXIED_ANY,
}

// filters returns the response filters as the proxy takes them, each from
// the closest policy that sets it; one turned off there is left out.
func filters(pols []*model.Policy) *snapshotv1.Filters {
	var sub *model.SubFilter
	var ssi *model.SSIFilter
	var add *model.AdditionFilter
	var uid *model.UseridFilter
	var cs *model.CharsetFilter
	for _, p := range pols {
		if f := p.Spec.Filters; p.Spec.Type == model.PolicyFilters && f != nil {
			sub = cmp.Or(f.Sub, sub)
			ssi = cmp.Or(f.SSI, ssi)
			add = cmp.Or(f.Addition, add)
			uid = cmp.Or(f.Userid, uid)
			cs = cmp.Or(f.Charset, cs)
		}
	}
	out := &snapshotv1.Filters{}
	if cs != nil && cs.Charset != "off" {
		out.Charset = charset(cs)
	}
	if sub != nil && len(sub.Pairs) > 0 {
		out.Sub = &snapshotv1.SubFilter{All: sub.All, LastModified: sub.LastModified, Types: lower(sub.Types)}
		for _, p := range sub.Pairs {
			out.Sub.Pairs = append(out.Sub.Pairs, &snapshotv1.SubPair{Match: p.Match, Replacement: p.Replacement})
		}
	}
	if uid != nil && uid.Mode != model.UseridOff {
		out.Userid = &snapshotv1.Userid{
			Mode: map[model.UseridMode]snapshotv1.Userid_Mode{
				model.UseridLog: snapshotv1.Userid_MODE_LOG, model.UseridV1: snapshotv1.Userid_MODE_V1, model.UseridOn: snapshotv1.Userid_MODE_ON,
			}[uid.Mode],
			Name: uid.Name, Domain: uid.Domain, Path: uid.Path, ExpiresMax: uid.Expires == "max", ExpiresS: seconds(uid.Expires),
			Secure: uid.Secure, HttpOnly: uid.HTTPOnly, SameSite: uid.SameSite, P3P: uid.P3P, Service: uid.Service, Mark: uid.Mark,
		}
	}
	if ssi != nil && (ssi.Enabled == nil || *ssi.Enabled) {
		out.Ssi = &snapshotv1.Ssi{SilentErrors: ssi.SilentErrors, Types: lower(ssi.Types), LastModified: ssi.LastModified, ValueLength: ssi.ValueLength}
	}
	if add != nil && (add.Before != "" || add.After != "") {
		out.Addition = &snapshotv1.Addition{Before: add.Before, After: add.After, Types: lower(add.Types)}
	}
	if out.Sub == nil && out.Ssi == nil && out.Addition == nil && out.Userid == nil && out.Charset == nil {
		return nil
	}
	return out
}

// charsetTypes is nginx's charset_types default.
var charsetTypes = []string{"text/html", "text/xml", "text/plain", "text/vnd.wap.wml", "application/javascript", "application/rss+xml"}

// charset builds nginx charset: the recode table runs from the source to
// the charset, whichever way the map was written.
func charset(c *model.CharsetFilter) *snapshotv1.Charset {
	out := &snapshotv1.Charset{Charset: c.Charset, Source: c.Source, Override: c.Override, Types: lower(c.Types)}
	if len(out.Types) == 0 {
		out.Types = charsetTypes
	} else if !slices.Contains(out.Types, "*") && !slices.Contains(out.Types, "text/html") {
		out.Types = append([]string{"text/html"}, out.Types...)
	}
	m := c.Map
	if m == nil || c.Source == "" || strings.EqualFold(c.Source, c.Charset) {
		return out
	}
	forward := strings.EqualFold(m.From, c.Source)
	pairs := map[byte][]byte{}
	for k, v := range m.Bytes {
		b, _ := strconv.ParseUint(k, 16, 8)
		raw, _ := hex.DecodeString(v)
		pairs[byte(b)] = raw
	}
	if strings.EqualFold(m.To, "utf-8") {
		codes := make([]uint32, 256)
		for i := range 128 {
			codes[i] = uint32(i)
		}
		for b, raw := range pairs {
			r, _ := utf8.DecodeRune(raw)
			codes[b] = uint32(r)
		}
		if forward {
			out.Recode = &snapshotv1.Charset_ToUtf8{ToUtf8: &snapshotv1.CharsetCodes{CodePoints: codes}}
		} else {
			out.Recode = &snapshotv1.Charset_FromUtf8{FromUtf8: &snapshotv1.CharsetCodes{CodePoints: codes}}
		}
		return out
	}
	// Bytes below 80 stay; the rest become "?" unless mapped, as nginx
	// fills a table before reading charset_map.
	table := make([]byte, 256)
	for i := range table {
		table[i] = '?'
		if i < 0x80 {
			table[i] = byte(i)
		}
	}
	for b, raw := range pairs {
		if forward {
			table[b] = raw[0]
		} else {
			table[raw[0]] = b
		}
	}
	out.Recode = &snapshotv1.Charset_Table{Table: table}
	return out
}

func lower(ts []string) []string {
	if len(ts) == 0 {
		return nil
	}
	out := make([]string, len(ts))
	for i, t := range ts {
		out[i] = strings.ToLower(t)
	}
	return out
}

// compression returns the closest compression policy as the proxy takes it.
func compression(pols []*model.Policy) *snapshotv1.Compression {
	var c *model.CompressionPolicy
	for _, p := range pols {
		if p.Spec.Type == model.PolicyCompression && p.Spec.Compression != nil {
			c = p.Spec.Compression
		}
	}
	if c == nil {
		return nil
	}
	out := &snapshotv1.Compression{
		Types: c.Types, MinLength: 20, GzipLevel: c.GzipLevel, BrotliLevel: c.BrotliLevel, ZstdLevel: c.ZstdLevel,
		Vary: c.Vary, Gunzip: c.Gunzip, Http10: c.HTTP10, Disable: c.Disable,
	}
	for _, e := range c.Encodings {
		out.Encodings = append(out.Encodings, encodings[e])
	}
	if c.MinLength != "" {
		n, _ := model.ParseSize(c.MinLength)
		out.MinLength = uint32(n)
	}
	for _, f := range c.Proxied {
		out.Proxied = append(out.Proxied, proxiedFlags[f])
	}
	switch c.Static {
	case "on":
		out.Static = snapshotv1.Compression_STATIC_ON
	case "always":
		out.Static = snapshotv1.Compression_STATIC_ALWAYS
	}
	return out
}
