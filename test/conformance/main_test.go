package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/null-variable/proxelo/internal/compile"
	"github.com/null-variable/proxelo/internal/model"
	"github.com/null-variable/proxelo/test/conformance/coverage"
)

// Every case loads, names known directives and compiles, without Docker or
// a proxy binary.
func TestCasesLoadAndCompile(t *testing.T) {
	raw, err := os.ReadFile("directives.yaml")
	if err != nil {
		t.Fatal(err)
	}
	list, err := coverage.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if "nginx:"+list.Nginx != nginxImage {
		t.Errorf("directives.yaml is from nginx %s, the reference image is %s", list.Nginx, nginxImage)
	}
	cases, err := loadCases("cases", list)
	if err != nil {
		t.Fatal(err)
	}
	if len(cases) == 0 {
		t.Fatal("no cases")
	}
	for _, k := range cases {
		raw, err := os.ReadFile(filepath.Join(k.Dir, "proxelo.json"))
		if err != nil {
			t.Fatal(err)
		}
		var cfg model.Config
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&cfg); err != nil {
			t.Errorf("%s: %v", k.Name, err)
			continue
		}
		if _, err := compile.Compile(cfg, 1); err != nil {
			t.Errorf("%s: %v", k.Name, err)
		}
		conf, err := os.ReadFile(filepath.Join(k.Dir, "nginx.conf"))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(conf), "127.0.0.1:18480") {
			t.Errorf("%s: nginx.conf does not listen on 127.0.0.1:18480", k.Name)
		}
	}
}

func TestCompare(t *testing.T) {
	base := Response{Status: 200, Headers: map[string]string{"content-type": "text/plain", "date": "a"}, BodyHash: "x"}
	same := Response{Status: 200, Headers: map[string]string{"content-type": "text/plain", "date": "b", "server": "proxelo"}, BodyHash: "x"}
	if d := compare(base, same, nil); len(d) != 0 {
		t.Errorf("volatile headers compared: %v", d)
	}
	other := Response{Status: 404, Headers: map[string]string{"content-type": "text/html", "etag": "1"}, BodyHash: "y"}
	if d := compare(base, other, nil); len(d) != 4 {
		t.Errorf("want status, two headers and body, got %v", d)
	}
	if d := compare(base, other, []string{"Content-Type", "ETag"}); len(d) != 2 {
		t.Errorf("ignore list not applied: %v", d)
	}
	up := &EchoRecord{Method: "GET", URI: "/a", Headers: []string{"host: backend", "connection: close", "x: 1"}}
	up2 := &EchoRecord{Method: "GET", URI: "/a", Headers: []string{"x: 1", "host: backend"}}
	if d := up.diff(up2); len(d) != 0 {
		t.Errorf("header order or Connection compared: %v", d)
	}
	up3 := &EchoRecord{Method: "GET", URI: "/b", Headers: []string{"host: example.com"}}
	if d := up.diff(up3); len(d) != 4 {
		t.Errorf("want uri, two missing and one extra header, got %v", d)
	}
}
