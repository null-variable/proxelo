package discovery

import (
	"cmp"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/null-variable/proxelo/internal/model"
)

// maxResponse bounds a registry response.
const maxResponse = 32 << 20

func decodeLimited(resp *http.Response, v any) error {
	return json.NewDecoder(io.LimitReader(resp.Body, maxResponse)).Decode(v)
}

// Docker reads the Engine API: running containers with every selector
// label, at their address on the network, on the container port.
type docker struct {
	client *http.Client
	base   string
	labels []string
	port   int
	net    string
}

func newDocker(d model.Discovery) (*docker, error) {
	port, err := strconv.Atoi(d.Port)
	if err != nil {
		return nil, fmt.Errorf("port: %w", err)
	}
	ep := cmp.Or(d.Endpoint, "unix:///var/run/docker.sock")
	c := &docker{labels: d.Selector, port: port, net: d.Network}
	if sock, ok := strings.CutPrefix(ep, "unix://"); ok {
		c.base = "http://docker"
		c.client = &http.Client{Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", sock)
			},
		}}
	} else {
		c.base = strings.TrimSuffix(ep, "/")
		c.client = &http.Client{}
	}
	return c, nil
}

func (c *docker) targets(ctx context.Context) ([]string, error) {
	filters, _ := json.Marshal(map[string][]string{"label": c.labels, "status": {"running"}})
	var list []struct {
		ID              string
		NetworkSettings struct {
			Networks map[string]struct {
				IPAddress         string
				GlobalIPv6Address string
			}
		}
	}
	u := c.base + "/containers/json?filters=" + url.QueryEscape(string(filters))
	if err := getJSON(ctx, c.client, u, nil, &list); err != nil {
		return nil, err
	}
	out := []string{}
	for _, ct := range list {
		nets := ct.NetworkSettings.Networks
		var ip string
		if c.net != "" {
			n, ok := nets[c.net]
			if !ok {
				continue
			}
			ip = cmp.Or(n.IPAddress, n.GlobalIPv6Address)
		} else {
			// The first network by name, so the choice is stable.
			first := ""
			for name, n := range nets {
				if a := cmp.Or(n.IPAddress, n.GlobalIPv6Address); a != "" && (first == "" || name < first) {
					first, ip = name, a
				}
			}
		}
		if ip != "" {
			out = append(out, hostPort(ip, c.port))
		}
	}
	return out, nil
}

// Kubernetes reads the EndpointSlices of a Service: ready endpoints on the
// named or numbered port.
type kubernetes struct {
	client    *http.Client
	base      string
	namespace string
	service   string
	port      string
	token     string
	tokenFile string
}

const serviceAccount = "/var/run/secrets/kubernetes.io/serviceaccount"

func newKubernetes(d model.Discovery) (*kubernetes, error) {
	ns, svc, _ := strings.Cut(d.Selector[0], "/")
	k := &kubernetes{namespace: ns, service: svc, port: d.Port, token: d.Token, client: &http.Client{}}
	if d.Endpoint != "" {
		k.base = strings.TrimSuffix(d.Endpoint, "/")
		return k, nil
	}
	host, port := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT")
	if host == "" {
		return nil, errors.New("no endpoint and not running in a cluster")
	}
	k.base = "https://" + net.JoinHostPort(host, cmp.Or(port, "443"))
	ca, err := os.ReadFile(serviceAccount + "/ca.crt")
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return nil, errors.New("service account ca.crt has no certificates")
	}
	k.client.Transport = &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}
	if k.token == "" {
		k.tokenFile = serviceAccount + "/token"
	}
	return k, nil
}

func (k *kubernetes) targets(ctx context.Context) ([]string, error) {
	h := http.Header{}
	tok := k.token
	if k.tokenFile != "" {
		// Projected tokens rotate: read it each time.
		b, err := os.ReadFile(k.tokenFile)
		if err != nil {
			return nil, err
		}
		tok = strings.TrimSpace(string(b))
	}
	if tok != "" {
		h.Set("Authorization", "Bearer "+tok)
	}
	var list struct {
		Items []struct {
			Ports []struct {
				Name *string
				Port *int
			}
			Endpoints []struct {
				Addresses  []string
				Conditions struct {
					Ready *bool
				}
			}
		}
	}
	u := fmt.Sprintf("%s/apis/discovery.k8s.io/v1/namespaces/%s/endpointslices?labelSelector=%s",
		k.base, url.PathEscape(k.namespace), url.QueryEscape("kubernetes.io/service-name="+k.service))
	if err := getJSON(ctx, k.client, u, h, &list); err != nil {
		return nil, err
	}
	out := []string{}
	for _, s := range list.Items {
		port := 0
		for _, p := range s.Ports {
			if p.Port == nil {
				continue
			}
			name := ""
			if p.Name != nil {
				name = *p.Name
			}
			if k.port == "" || k.port == name || k.port == strconv.Itoa(*p.Port) {
				port = *p.Port
				break
			}
		}
		if port == 0 {
			continue
		}
		for _, e := range s.Endpoints {
			// Unset ready means ready.
			if e.Conditions.Ready != nil && !*e.Conditions.Ready {
				continue
			}
			for _, a := range e.Addresses {
				out = append(out, hostPort(a, port))
			}
		}
	}
	return out, nil
}

// Consul reads the healthy instances of a service from the agent's
// health endpoint, with blocking queries so a change arrives at once.
type consul struct {
	client  *http.Client
	base    string
	service string
	tag     string
	port    int
	token   string
	index   string
}

func newConsul(d model.Discovery) (*consul, error) {
	c := &consul{
		client:  &http.Client{},
		base:    strings.TrimSuffix(cmp.Or(d.Endpoint, "http://127.0.0.1:8500"), "/"),
		service: d.Selector[0],
		tag:     d.Tag,
		token:   d.Token,
	}
	if d.Port != "" {
		c.port, _ = strconv.Atoi(d.Port)
	}
	return c, nil
}

// consulWait bounds a blocking query; it stays below requestTimeout.
const consulWait = 5 * time.Second

func (c *consul) targets(ctx context.Context) ([]string, error) {
	q := url.Values{"passing": {"1"}}
	if c.tag != "" {
		q.Set("tag", c.tag)
	}
	if c.index != "" {
		q.Set("index", c.index)
		q.Set("wait", consulWait.String())
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		c.base+"/v1/health/service/"+url.PathEscape(c.service)+"?"+q.Encode(), nil)
	if err != nil {
		return nil, err
	}
	if c.token != "" {
		req.Header.Set("X-Consul-Token", c.token)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("consul: %s", resp.Status)
	}
	var list []struct {
		Node struct {
			Address string
		}
		Service struct {
			Address string
			Port    int
		}
	}
	if err := decodeLimited(resp, &list); err != nil {
		return nil, err
	}
	c.index = resp.Header.Get("X-Consul-Index")
	out := []string{}
	for _, e := range list {
		addr := cmp.Or(e.Service.Address, e.Node.Address)
		port := e.Service.Port
		if c.port != 0 {
			port = c.port
		}
		if addr == "" || port == 0 {
			continue
		}
		out = append(out, hostPort(addr, port))
	}
	return out, nil
}
