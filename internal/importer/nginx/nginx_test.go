package nginx

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	snapshotv1 "github.com/null-variable/proxelo-api/gen/go/proxelo/snapshot/v1"

	"github.com/null-variable/proxelo/internal/compile"
	"github.com/null-variable/proxelo/internal/model"
)

func convert(t *testing.T, files Files) (model.Config, Report) {
	t.Helper()
	tree, err := Parse(files, "/etc/nginx/nginx.conf")
	if err != nil {
		t.Fatal(err)
	}
	cfg, rep := Convert(tree, files)
	for _, k := range model.Kinds {
		for _, r := range cfg.Of(k) {
			if es := model.Validate(r); es != nil {
				t.Errorf("%s %s: %v", k.Plural, r.Common().Name, es)
			}
		}
	}
	if _, err := compile.Compile(cfg, 1); err != nil {
		t.Fatal(err)
	}
	return cfg, rep
}

func TestLexEscapes(t *testing.T) {
	toks, err := lex("f", `return 200 "a\n\"b\"" ~\.php$;`)
	if err != nil {
		t.Fatal(err)
	}
	if got := toks[2].text; got != "a\n\"b\"" {
		t.Errorf("quoted: %q", got)
	}
	if got := toks[3].text; got != `~\.php$` {
		t.Errorf("bare: %q", got)
	}
}

func TestIncludeAndInheritance(t *testing.T) {
	cfg, rep := convert(t, Files{
		"/etc/nginx/nginx.conf": `events {}
http {
    proxy_set_header X-A a;
    include conf.d/*.conf;
}`,
		"/etc/nginx/conf.d/a.conf": `upstream app { server 127.0.0.1:8080; }
server {
    listen 80;
    server_name example.com;
    location / { proxy_pass http://app; }
    location /b/ {
        proxy_set_header X-B b;
        proxy_pass http://app;
    }
}`,
	})
	if len(cfg.Sites) != 1 || len(cfg.Routes) != 2 || len(cfg.Upstreams) != 1 {
		t.Fatalf("sites %d routes %d upstreams %d", len(cfg.Sites), len(cfg.Routes), len(cfg.Upstreams))
	}
	if rep.Counts[Unsupported] != 0 {
		t.Errorf("unsupported: %+v", rep.Entries)
	}
	// proxy_set_header in /b/ drops the inherited X-A, as in nginx.
	var b *model.Route
	for _, r := range cfg.Routes {
		if r.Spec.Match.Path.Value == "/b/" {
			b = r
		}
	}
	if b == nil || len(b.Spec.Policies) == 0 {
		t.Fatal("/b/ has no headers policy")
	}
	for _, p := range cfg.Policies {
		if p.ID == b.Spec.Policies[0] {
			set := p.Spec.Headers.Request.Set
			if _, ok := set["X-A"]; ok || set["X-B"] != "b" {
				t.Errorf("headers: %v", set)
			}
		}
	}
}

func TestStreamPreread(t *testing.T) {
	cfg, _ := convert(t, Files{"/etc/nginx/nginx.conf": `events {}
stream {
    upstream a { server 127.0.0.1:1; }
    upstream b { server 127.0.0.1:2; }
    map $ssl_preread_server_name $up {
        a.example.com a;
        default b;
    }
    server { listen 443; ssl_preread on; proxy_pass $up; }
}`})
	if len(cfg.Streams) != 1 {
		t.Fatalf("streams %d", len(cfg.Streams))
	}
	s := cfg.Streams[0].Spec
	if !s.SSLPreread || len(s.Routes) != 2 || len(s.Routes[0].ServerNames) != 1 || len(s.Routes[1].ServerNames) != 0 {
		t.Errorf("stream: %+v", s)
	}
}

func TestLoadModuleUnsupported(t *testing.T) {
	_, rep := convert(t, Files{"/etc/nginx/nginx.conf": "load_module modules/x.so;\nevents {}\n"})
	if rep.Counts[Unsupported] != 1 || rep.Entries[0].Line != 1 {
		t.Errorf("report: %+v", rep)
	}
}

func TestSplitDump(t *testing.T) {
	files, main, err := Load([]byte("# configuration file /etc/nginx/nginx.conf:\nevents {}\n\n# configuration file /etc/nginx/x.conf:\nserver {}\n"))
	if err != nil || main != "/etc/nginx/nginx.conf" || files["/etc/nginx/x.conf"] != "server {}\n" {
		t.Errorf("%v %q %q", err, main, files)
	}
}

func TestProxyCache(t *testing.T) {
	cfg, _ := convert(t, Files{
		"/etc/nginx/nginx.conf": `events {}
http {
    proxy_cache_path /var/cache/nginx levels=1:2 keys_zone=micro:10m max_size=1g inactive=1h;
    upstream app { server 127.0.0.1:8080; }
    server {
        listen 80;
        proxy_cache micro;
        proxy_cache_valid 200 302 1s;
        proxy_cache_valid any 1m;
        proxy_cache_lock on;
        proxy_cache_use_stale updating error;
        proxy_cache_background_update on;
        proxy_cache_bypass $http_pragma $arg_nocache;
        location / { proxy_pass http://app; }
        location /live/ {
            proxy_cache off;
            proxy_pass http://app;
        }
    }
}`,
	})
	var cache, off *model.CachePolicy
	for _, p := range cfg.Policies {
		if c := p.Spec.Cache; c != nil {
			if c.Enabled != nil {
				off = c
			} else {
				cache = c
			}
		}
	}
	if cache == nil || off == nil {
		t.Fatalf("policies: %+v", cfg.Policies)
	}
	if cache.Path != "/var/cache/nginx" || cache.MaxSize != "1g" || cache.Inactive != "1h" || cache.MaxEntries != 81920 ||
		len(cache.Valid) != 2 || cache.Valid[0].Time != "1s" || !cache.Lock || !cache.BackgroundUpdate {
		t.Errorf("cache: %+v", cache)
	}
	if want := `("pragma" in request.headers && request.headers["pragma"] != "" && request.headers["pragma"] != "0")`; !strings.HasPrefix(cache.Bypass, want) {
		t.Errorf("bypass: %s", cache.Bypass)
	}
	snap, err := compile.Compile(cfg, 1)
	if err != nil {
		t.Fatal(err)
	}
	cached := 0
	for _, r := range snap.GetSites()[0].GetRoutes() {
		if r.GetCache() != nil {
			cached++
		}
	}
	if cached != 1 || len(snap.GetCacheZones()) != 1 {
		t.Errorf("cached routes %d, zones %v", cached, snap.GetCacheZones())
	}
}

func TestListenQuic(t *testing.T) {
	cfg, _ := convert(t, Files{"/etc/nginx/nginx.conf": `events {}
http {
    server { listen 443 ssl; listen 443 quic reuseport; server_name a.example.com; }
    server { listen 8443 quic; http3 off; server_name b.example.com; }
}`})
	got := map[string]bool{}
	for _, l := range cfg.Listeners {
		got[l.Spec.Address] = l.Spec.HTTP3
		if l.Spec.TLS == nil {
			t.Errorf("%s: no tls", l.Spec.Address)
		}
	}
	if !got["0.0.0.0:443"] || got["0.0.0.0:8443"] {
		t.Errorf("http3: %v", got)
	}
}

func TestAuthJWTAndOIDC(t *testing.T) {
	cfg, _ := convert(t, Files{
		"/etc/nginx/nginx.conf": `events {}
http {
    oidc_provider idp {
        issuer https://login.example.com/realms/a;
        client_id app;
        client_secret s3cret;
        logout_uri /logout;
    }
    server {
        listen 80;
        server_name example.com;
        location /api/ {
            auth_jwt "api" token=$cookie_auth;
            auth_jwt_key_file /etc/nginx/keys.json;
            auth_jwt_leeway 30;
            return 200;
        }
        location /app/ {
            auth_oidc idp;
            return 200;
        }
    }
}`,
		"/etc/nginx/keys.json": `{"keys":[{"kty":"oct","k":"c2VjcmV0"}]}`,
	})
	var jwt, oidc *model.Policy
	for _, p := range cfg.Policies {
		switch p.Spec.Type {
		case model.PolicyJWT:
			jwt = p
		case model.PolicyOIDC:
			oidc = p
		}
	}
	if jwt == nil || jwt.Spec.JWT.Realm != "api" || jwt.Spec.JWT.Token != "$cookie_auth" || jwt.Spec.JWT.Leeway != "30s" || jwt.Spec.JWT.JWKS == "" {
		t.Errorf("jwt: %+v", jwt)
	}
	if oidc == nil || oidc.Spec.OIDC.Issuer != "https://login.example.com/realms/a" || oidc.Spec.OIDC.ClientSecret != "s3cret" || oidc.Spec.OIDC.LogoutURI != "/logout" {
		t.Errorf("oidc: %+v", oidc)
	}
}

func TestStaticHandlers(t *testing.T) {
	cfg, rep := convert(t, Files{"/etc/nginx/nginx.conf": `events {}
http {
    autoindex_exact_size off;
    server {
        listen 80;
        root /srv;
        location /files/ { autoindex on; autoindex_format json; autoindex_localtime on; }
        location /pick/ { random_index on; }
        location /up/ { dav_methods PUT DELETE; create_full_put_path on; dav_access user:rw group:r; min_delete_depth 2; }
        location /video/ { flv; }
        location /off/ { autoindex off; dav_methods off; }
    }
}`})
	by := map[string]*model.StaticAction{}
	for _, r := range cfg.Routes {
		if r.Spec.Action.Static != nil {
			by[r.Spec.Match.Path.Value] = r.Spec.Action.Static
		}
	}
	if a := by["/files/"].Autoindex; a == nil || a.Format != model.AutoindexJSON || !a.LocalTime || !a.ApproximateSize {
		t.Errorf("autoindex: %+v", a)
	}
	if !by["/pick/"].RandomIndex || !by["/video/"].FLV {
		t.Errorf("random_index or flv: %+v %+v", by["/pick/"], by["/video/"])
	}
	d := by["/up/"].DAV
	if d == nil || !slices.Equal(d.Methods, []string{"put", "delete"}) || !d.CreateFullPutPath || d.Access != "0640" || d.MinDeleteDepth != 2 {
		t.Errorf("dav: %+v", d)
	}
	if o := by["/off/"]; o.Autoindex != nil || o.DAV != nil {
		t.Errorf("off: %+v", o)
	}
	for _, e := range rep.Entries {
		if strings.HasPrefix(e.Directive, "autoindex") || strings.HasPrefix(e.Directive, "dav_") || e.Directive == "flv" || e.Directive == "random_index" {
			if e.Class != Converted {
				t.Errorf("%s: %s", e.Directive, e.Class)
			}
		}
	}
}

func TestSubrequestFilters(t *testing.T) {
	cfg, rep := convert(t, Files{"/etc/nginx/nginx.conf": `events {}
http {
    ssi on;
    ssi_types text/plain TEXT/HTML;
    server {
        listen 80;
        root /srv;
        add_after_body /footer.html;
        location /plain/ { ssi off; add_after_body ""; }
        location /quiet/ { ssi_silent_errors on; ssi_value_length 1024; ssi_min_file_chunk 2k; }
        location /api/ { mirror /copy; mirror /copy2; mirror_request_body off; }
        location /copy { internal; }
    }
}`})
	snap, err := compile.Compile(cfg, 1)
	if err != nil {
		t.Fatal(err)
	}
	site := snap.GetSites()[0]
	if f := site.GetFilters(); !slices.Equal(f.GetSsi().GetTypes(), []string{"text/plain"}) || f.GetAddition().GetAfter() != "/footer.html" {
		t.Errorf("site filters: %v", f)
	}
	by := map[string]*snapshotv1.Route{}
	for _, r := range site.GetRoutes() {
		by[r.GetPath().GetValue()] = r
	}
	if f := by["/plain/"].GetFilters(); f != nil {
		t.Errorf("plain: %v", f)
	}
	if s := by["/quiet/"].GetFilters().GetSsi(); !s.GetSilentErrors() || s.GetValueLength() != 1024 || by["/quiet/"].GetFilters().GetAddition() == nil {
		t.Errorf("quiet: %v", by["/quiet/"].GetFilters())
	}
	if m := by["/api/"].GetMirror(); !slices.Equal(m.GetUris(), []string{"/copy", "/copy2"}) || m.GetRequestBody() {
		t.Errorf("mirror: %v", m)
	}
	if !by["/copy"].GetInternal() || by["/api/"].GetInternal() || by["/copy"].GetMirror() != nil {
		t.Errorf("internal: %v %v", by["/copy"], by["/api/"])
	}
	for _, e := range rep.Entries {
		if strings.HasPrefix(e.Directive, "ssi") || strings.HasPrefix(e.Directive, "mirror") || e.Directive == "add_after_body" || e.Directive == "internal" {
			if e.Class != Converted && e.Directive != "ssi_min_file_chunk" {
				t.Errorf("%s: %s", e.Directive, e.Class)
			}
		}
	}
}

func TestSubAndUseridFilters(t *testing.T) {
	cfg, rep := convert(t, Files{"/etc/nginx/nginx.conf": `events {}
http {
    sub_filter_types text/css;
    userid on;
    userid_name vid;
    userid_expires 365d;
    userid_flags secure samesite=lax;
    server {
        listen 80;
        root /srv;
        sub_filter 'http://old' 'https://$host';
        sub_filter_once off;
        location /one/ { sub_filter a b; userid_domain none; userid_mark A; }
        location /plain/ { userid off; }
        location /forever/ { userid_expires max; userid_service 7; }
    }
}`})
	snap, err := compile.Compile(cfg, 1)
	if err != nil {
		t.Fatal(err)
	}
	site := snap.GetSites()[0]
	f := site.GetFilters()
	if s := f.GetSub(); len(s.GetPairs()) != 1 || s.GetPairs()[0].GetReplacement() != "https://$host" || !s.GetAll() || !slices.Equal(s.GetTypes(), []string{"text/css"}) {
		t.Errorf("site sub: %v", s)
	}
	if u := f.GetUserid(); u.GetMode() != snapshotv1.Userid_MODE_ON || u.GetName() != "vid" || u.GetExpiresS() != 365*86400 || !u.GetSecure() || u.GetSameSite() != "lax" {
		t.Errorf("site userid: %v", u)
	}
	by := map[string]*snapshotv1.Filters{}
	for _, r := range site.GetRoutes() {
		by[r.GetPath().GetValue()] = r.GetFilters()
	}
	// sub_filter pairs are an array directive: the location's replace the server's.
	if p := by["/one/"].GetSub().GetPairs(); len(p) != 1 || p[0].GetMatch() != "a" || by["/one/"].GetUserid().GetMark() != "A" {
		t.Errorf("one: %v", by["/one/"])
	}
	if by["/plain/"].GetUserid() != nil || by["/plain/"].GetSub() == nil {
		t.Errorf("plain: %v", by["/plain/"])
	}
	if u := by["/forever/"].GetUserid(); !u.GetExpiresMax() || u.GetService() != 7 || u.GetName() != "vid" {
		t.Errorf("forever: %v", u)
	}
	for _, e := range rep.Entries {
		if strings.HasPrefix(e.Directive, "sub_filter") || strings.HasPrefix(e.Directive, "userid") {
			if e.Class != Converted {
				t.Errorf("%s: %s", e.Directive, e.Class)
			}
		}
	}
}

func TestCharsetFilter(t *testing.T) {
	cfg, rep := convert(t, Files{"/etc/nginx/nginx.conf": `events {}
http {
    charset_map koi8-r windows-1251 {
        C1 E1;
        41 61;
    }
    charset_map windows-1251 utf-8 {
        C0 D090;
        E0 D0B0;
    }
    server {
        listen 80;
        root /srv;
        charset utf-8;
        location /koi/ { charset windows-1251; source_charset koi8-r; charset_types text/css; }
        location /win/ { source_charset windows-1251; override_charset on; }
        location /off/ { charset off; }
        location /html/ { charset_types text/html; }
    }
}`})
	snap, err := compile.Compile(cfg, 1)
	if err != nil {
		t.Fatal(err)
	}
	site := snap.GetSites()[0]
	if c := site.GetFilters().GetCharset(); c.GetCharset() != "utf-8" || c.GetRecode() != nil || len(c.GetTypes()) != 6 {
		t.Errorf("site: %v", c)
	}
	by := map[string]*snapshotv1.Charset{}
	for _, r := range site.GetRoutes() {
		by[r.GetPath().GetValue()] = r.GetFilters().GetCharset()
	}
	if k := by["/koi/"]; k.GetTable()[0xC1] != 0xE1 || k.GetTable()[0xC2] != '?' || k.GetTable()['A'] != 'a' || k.GetTable()['B'] != 'B' || !slices.Equal(k.GetTypes(), []string{"text/html", "text/css"}) {
		t.Errorf("koi: %v", k)
	}
	if w := by["/win/"]; w.GetToUtf8().GetCodePoints()[0xC0] != 0x410 || w.GetToUtf8().GetCodePoints()[0xE0] != 0x430 || !w.GetOverride() {
		t.Errorf("win: %v", w)
	}
	if by["/off/"] != nil || !slices.Equal(by["/html/"].GetTypes(), []string{"text/html"}) {
		t.Errorf("off or html: %v %v", by["/off/"], by["/html/"])
	}
	for _, e := range rep.Entries {
		if strings.Contains(e.Directive, "charset") && e.Class != Converted {
			t.Errorf("%s: %s", e.Directive, e.Class)
		}
	}
}

func TestProxyEdits(t *testing.T) {
	cfg, rep := convert(t, Files{"/etc/nginx/nginx.conf": `events {}
http {
    upstream app { server 127.0.0.1:9000; }
    proxy_cookie_path /app/ /;
    proxy_intercept_errors on;
    server {
        listen 80;
        location /plain/ { proxy_pass http://app; }
        location /uri/ { proxy_pass http://app/inner/; }
        location /rules/ {
            proxy_redirect default;
            proxy_redirect ~*^http://(.*)\.internal/ http://$1.example.com/;
            proxy_cookie_domain ~\.internal$ example.com;
            proxy_cookie_flags ~ secure samesite=strict;
            proxy_pass http://app;
        }
        location /off/ { proxy_redirect off; proxy_cookie_path off; proxy_intercept_errors off; proxy_pass http://app; }
    }
}`})
	for _, e := range rep.Entries {
		if strings.HasPrefix(e.Directive, "proxy_redirect") || strings.HasPrefix(e.Directive, "proxy_cookie") || strings.HasPrefix(e.Directive, "proxy_intercept") {
			if e.Class != Converted {
				t.Errorf("%s: %s %s", e.Directive, e.Class, e.Note)
			}
		}
	}
	by := map[string]*model.ProxyAction{}
	for _, r := range cfg.Routes {
		by[r.Spec.Match.Path.Value] = r.Spec.Action.Proxy
	}
	if p := by["/plain/"]; p.Redirects == nil || len(p.Redirects.Rules) != 1 || p.Redirects.Rules[0].Pattern != "http://app/" || p.Redirects.Rules[0].Replacement != "/" || !p.InterceptErrors {
		t.Errorf("plain: %+v", p.Redirects)
	}
	if p := by["/plain/"]; p.Cookies == nil || p.Cookies.Paths[0].Pattern != "/app/" {
		t.Errorf("plain cookies: %+v", p.Cookies)
	}
	if r := by["/uri/"].Redirects; r.Rules[0].Pattern != "http://app/inner/" || r.Rules[0].Replacement != "/uri/" {
		t.Errorf("uri: %+v", r)
	}
	r := by["/rules/"].Redirects
	if len(r.Rules) != 2 || r.Rules[1].Match != model.RewriteRegexCI || r.Rules[1].Pattern != `^http://(.*)\.internal/` {
		t.Errorf("rules: %+v", r)
	}
	c := by["/rules/"].Cookies
	if c.Domains[0].Match != model.RewriteRegex || c.Flags[0].Cookie != "" || !c.Flags[0].Regex || len(c.Paths) != 1 {
		t.Errorf("rules cookies: %+v", c)
	}
	if p := by["/off/"]; !p.Redirects.Off || p.Cookies != nil || p.InterceptErrors {
		t.Errorf("off: %+v %+v %v", p.Redirects, p.Cookies, p.InterceptErrors)
	}
	if _, err := compile.Compile(cfg, 1); err == nil {
		t.Log("compiled")
	} else {
		t.Error(err)
	}
}

func TestProxyRequestEdits(t *testing.T) {
	cfg, rep := convert(t, Files{"/etc/nginx/nginx.conf": `events {}
http {
    upstream app { server 127.0.0.1:9000; }
    proxy_pass_header Server;
    proxy_bind 10.0.0.1;
    server {
        listen 80;
        proxy_limit_rate 100k;
        location /plain/ { proxy_pass http://app; }
        location /req/ {
            proxy_pass_header X-Accel-Redirect;
            proxy_method $arg_m;
            proxy_set_body "a=$arg_a";
            proxy_pass_request_headers off;
            proxy_pass_request_body off;
            proxy_bind off;
            proxy_limit_rate 0;
            proxy_pass http://app;
        }
        location /cgi/ { fastcgi_pass app; fastcgi_bind $arg_ip; fastcgi_limit_rate 1m; }
        location /mc/ { memcached_pass app; memcached_bind 10.0.0.2; }
        location /grpc/ { grpc_pass grpc://app; grpc_pass_header X-Accel-Buffering; grpc_bind 10.0.0.3; }
        location /tr/ { proxy_bind $remote_addr transparent; proxy_pass http://app; }
    }
}`})
	// By directive and line.
	class := map[string]Class{}
	for _, e := range rep.Entries {
		class[fmt.Sprintf("%s:%d", e.Directive, e.Line)] = e.Class
	}
	for d, want := range map[string]Class{
		"proxy_pass_header:4":           Converted,
		"proxy_method:12":               Converted,
		"proxy_pass_request_headers:14": Converted,
		"fastcgi_bind:20":               Converted,
		"grpc_bind:22":                  Unsupported,
		"proxy_bind:23":                 Unsupported,
	} {
		if class[d] != want {
			t.Errorf("%s: %s, want %s", d, class[d], want)
		}
	}
	act := map[string]*model.Action{}
	for _, r := range cfg.Routes {
		act[r.Spec.Match.Path.Value] = &r.Spec.Action
	}
	if p := act["/plain/"].Proxy; !slices.Equal(p.PassHeaders, []string{"Server"}) || p.Bind != "10.0.0.1" || p.LimitRate != "100k" || p.Request != nil {
		t.Errorf("plain: %+v", p)
	}
	p := act["/req/"].Proxy
	want := model.UpstreamRequest{Method: "$arg_m", NoHeaders: true, NoBody: true}
	if p.Request == nil || p.Request.Body == nil || *p.Request.Body != "a=$arg_a" {
		t.Fatalf("req: %+v", p.Request)
	}
	if got := *p.Request; got.Method != want.Method || got.NoHeaders != want.NoHeaders || got.NoBody != want.NoBody {
		t.Errorf("req: %+v", got)
	}
	// The level's first pass_header drops the inherited list.
	if !slices.Equal(p.PassHeaders, []string{"X-Accel-Redirect"}) || p.Bind != "" || p.LimitRate != "" {
		t.Errorf("req: %+v", p)
	}
	if g := act["/cgi/"].Gateway; g.Bind != "$arg_ip" || g.LimitRate != "1m" {
		t.Errorf("cgi: %+v", g.ProxyAction)
	}
	if m := act["/mc/"].Memcached; m.Bind != "10.0.0.2" || m.PassHeaders != nil || m.LimitRate != "" {
		t.Errorf("mc: %+v", m.ProxyAction)
	}
	if g := act["/grpc/"].Grpc; !slices.Equal(g.PassHeaders, []string{"X-Accel-Buffering"}) || g.Bind != "" || g.LimitRate != "" {
		t.Errorf("grpc: %+v", g)
	}
	if _, err := compile.Compile(cfg, 1); err != nil {
		t.Error(err)
	}
}
