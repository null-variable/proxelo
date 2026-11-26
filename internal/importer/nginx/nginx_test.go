package nginx

import (
	"testing"

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
