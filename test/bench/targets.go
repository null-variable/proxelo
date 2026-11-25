package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/template"

	"google.golang.org/protobuf/proto"

	"github.com/null-variable/proxelo/internal/compile"
	"github.com/null-variable/proxelo/internal/model"
)

// Fixed request shape of S1 and S3. The proxy serves StaticPath from its own
// root (S1) and passes ProxyPath to the upstream unchanged (S3).
const (
	FileSize   = 1024
	StaticPath = "/1k.html"
	ProxyPath  = "/proxy/1k.html"
	HostHeader = "bench.local"
	// Idle upstream connections kept per worker (nginx "keepalive 64").
	UpstreamKeepalive = 64
	Backlog           = 4096
)

// Target is one proxy configuration under test.
type Target struct {
	Kind string // "nginx" or "proxelo"
	// proxelo only.
	Runtime   string // shared | per-core
	Allocator string // system | jemalloc | mimalloc
}

func (t Target) String() string {
	if t.Kind == "nginx" {
		return "nginx"
	}
	return "proxelo:" + t.Runtime + ":" + t.Allocator
}

// ParseTarget accepts "nginx", "proxelo", "proxelo:<runtime>" and
// "proxelo:<runtime>:<allocator>". Omitted parts default to shared and system.
func ParseTarget(s string) (Target, error) {
	parts := strings.Split(s, ":")
	switch parts[0] {
	case "nginx":
		if len(parts) != 1 {
			return Target{}, fmt.Errorf("target %q: nginx takes no options", s)
		}
		return Target{Kind: "nginx"}, nil
	case "proxelo":
		if len(parts) > 3 {
			return Target{}, fmt.Errorf("target %q: want proxelo[:runtime[:allocator]]", s)
		}
		t := Target{Kind: "proxelo", Runtime: "shared", Allocator: "system"}
		if len(parts) > 1 {
			t.Runtime = parts[1]
		}
		if len(parts) > 2 {
			t.Allocator = parts[2]
		}
		if t.Runtime != "shared" && t.Runtime != "per-core" {
			return Target{}, fmt.Errorf("target %q: runtime must be shared or per-core", s)
		}
		if t.Allocator != "system" && t.Allocator != "jemalloc" && t.Allocator != "mimalloc" {
			return Target{}, fmt.Errorf("target %q: allocator must be system, jemalloc or mimalloc", s)
		}
		return t, nil
	default:
		return Target{}, fmt.Errorf("target %q: unknown kind", s)
	}
}

// nginxConf follows nginx's documented performance settings and is limited to
// what proxelo implements, so both sides do the same work. Access logging is
// off and keepalive_requests is unbounded because proxelo has neither yet.
// The upstream role uses the same template without the proxy location.
var nginxConf = template.Must(template.New("nginx").Parse(`worker_processes {{.Workers}};
worker_rlimit_nofile 65535;
error_log stderr warn;
pid /tmp/nginx.pid;

events {
    worker_connections 16384;
}

http {
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    access_log off;
    server_tokens off;
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 75s;
    keepalive_requests 1000000;
{{- if .Upstream}}

    upstream backend {
        server {{.Upstream}};
        keepalive {{.Keepalive}};
    }
{{- end}}

    server {
        listen {{.Listen}} reuseport backlog={{.Backlog}};
        server_name {{.Host}};

        location / {
{{- if .Body}}
            default_type text/html;
            return 200 "{{.Body}}";
{{- else}}
            root /srv/www;
{{- end}}
        }
{{- if .Upstream}}

        location /proxy/ {
            proxy_pass http://backend;
            proxy_http_version 1.1;
            proxy_set_header Connection "";
        }
{{- end}}
    }
}
`))

type nginxParams struct {
	Workers   int
	Listen    string
	Backlog   int
	Host      string
	Upstream  string // empty for the upstream role
	Keepalive int
	Body      string // upstream role: fixed response body
}

// NginxConfig renders the nginx configuration under test.
func NginxConfig(workers int, listen, upstream string) []byte {
	return renderNginx(nginxParams{Workers: workers, Listen: listen, Backlog: Backlog, Host: HostHeader, Upstream: upstream, Keepalive: UpstreamKeepalive})
}

// UpstreamConfig renders the dummy upstream: nginx answering every request
// with FileBody from memory, the cheapest response nginx can produce, so the
// upstream is not what limits S3.
func UpstreamConfig(workers int, listen string) []byte {
	return renderNginx(nginxParams{Workers: workers, Listen: listen, Backlog: Backlog, Host: "_", Body: string(FileBody)})
}

func renderNginx(p nginxParams) []byte {
	var b bytes.Buffer
	if err := nginxConf.Execute(&b, p); err != nil {
		panic(err)
	}
	return b.Bytes()
}

// ProxeloSnapshot compiles the configuration of NginxConfig through the
// control plane compiler.
func ProxeloSnapshot(listen, upstream string) ([]byte, error) {
	cfg := model.Config{
		Listeners: []*model.Listener{{Meta: model.Meta{ID: "lst_bench", Name: "bench"}, Spec: model.ListenerSpec{
			Address: listen, ReusePort: true, Backlog: Backlog, DefaultSite: "site_bench",
		}}},
		Sites: []*model.Site{{Meta: model.Meta{ID: "site_bench", Name: "bench"}, Spec: model.SiteSpec{
			Listeners: []string{"lst_bench"},
			Hostnames: []model.HostMatch{{Type: model.HostExact, Value: HostHeader}},
			Routes:    []string{"rt_static", "rt_proxy"},
		}}},
		Routes: []*model.Route{
			{Meta: model.Meta{ID: "rt_static", Name: "static"}, Spec: model.RouteSpec{
				Match:  model.Match{Path: model.PathMatch{Type: model.PathPrefix, Value: "/"}},
				Action: model.Action{Type: model.ActionStatic, Static: &model.StaticAction{Root: "/srv/www"}},
			}},
			{Meta: model.Meta{ID: "rt_proxy", Name: "proxy"}, Spec: model.RouteSpec{
				Match:  model.Match{Path: model.PathMatch{Type: model.PathPrefix, Value: "/proxy/"}},
				Action: model.Action{Type: model.ActionProxy, Proxy: &model.ProxyAction{Upstream: "up_backend"}},
			}},
		},
		Upstreams: []*model.Upstream{{Meta: model.Meta{ID: "up_backend", Name: "backend"}, Spec: model.UpstreamSpec{
			Targets:   []model.Target{{Address: upstream}},
			Keepalive: model.Keepalive{Idle: UpstreamKeepalive},
		}}},
	}
	snap, err := compile.Compile(cfg, 1)
	if err != nil {
		return nil, err
	}
	return proto.MarshalOptions{Deterministic: true}.Marshal(snap)
}

// FileBody is the content of every served file.
var FileBody = bytes.Repeat([]byte("0123456789abcdef"), FileSize/16)

// WriteContent writes the StaticPath file under dir.
func WriteContent(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, filepath.FromSlash(StaticPath)), FileBody, 0o644)
}
