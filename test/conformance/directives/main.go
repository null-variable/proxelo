// Command directives extracts every configuration directive from an nginx
// source tree and merges the list into directives.yaml, keeping the status,
// field and note already recorded for each one.
//
//	git clone --depth 1 -b release-1.31.10 https://github.com/nginx/nginx /tmp/nginx
//	go run ./test/conformance/directives -src /tmp/nginx
//
// Directives new in the source are added as missing; directives no longer in
// it are dropped and printed. With -check it writes nothing and exits 1 when
// the file is not up to date, so CI catches a new nginx release.
package main

import (
	"bytes"
	"cmp"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/null-variable/proxelo/test/conformance/coverage"
)

func main() {
	src := flag.String("src", "", "nginx source checkout")
	out := flag.String("file", "test/conformance/directives.yaml", "directive list to update")
	check := flag.Bool("check", false, "exit 1 instead of writing when the file would change")
	flag.Parse()
	if *src == "" {
		fmt.Fprintln(os.Stderr, "usage: directives -src <nginx source> [-file directives.yaml] [-check]")
		os.Exit(2)
	}
	if err := run(*src, *out, *check); err != nil {
		fmt.Fprintln(os.Stderr, "directives:", err)
		os.Exit(1)
	}
}

func run(src, out string, check bool) error {
	version, err := nginxVersion(src)
	if err != nil {
		return err
	}
	found, err := extract(filepath.Join(src, "src"))
	if err != nil {
		return err
	}
	if len(found) == 0 {
		return fmt.Errorf("no directives found under %s/src", src)
	}

	old := coverage.List{}
	if raw, err := os.ReadFile(out); err == nil {
		if old, err = coverage.Parse(raw); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	known := map[string]coverage.Directive{}
	for _, d := range old.Directives {
		known[d.Key()] = d
	}

	if check && old.Nginx != "" && old.Nginx != version {
		return fmt.Errorf("%s is from nginx %s, the source is %s; regenerate it and move the reference image", out, old.Nginx, version)
	}
	next := coverage.List{Nginx: version}
	seen := map[string]bool{}
	for _, d := range found {
		if k, ok := known[d.Key()]; ok {
			d.Status, d.Field, d.Note = k.Status, k.Field, k.Note
		} else {
			d.Status = coverage.Missing
			fmt.Printf("new: %s %s\n", d.Module, d.Name)
		}
		seen[d.Key()] = true
		next.Directives = append(next.Directives, d)
	}
	for _, d := range old.Directives {
		if !seen[d.Key()] {
			fmt.Printf("removed: %s %s (was %s)\n", d.Module, d.Name, d.Status)
		}
	}

	raw, err := next.Marshal()
	if err != nil {
		return err
	}
	cur, _ := os.ReadFile(out)
	if bytes.Equal(cur, raw) {
		return nil
	}
	if check {
		return fmt.Errorf("%s is out of date with nginx %s; run without -check", out, version)
	}
	return os.WriteFile(out, raw, 0o644)
}

var versionRe = regexp.MustCompile(`#define NGINX_VERSION\s+"([^"]+)"`)

func nginxVersion(src string) (string, error) {
	raw, err := os.ReadFile(filepath.Join(src, "src/core/nginx.h"))
	if err != nil {
		return "", err
	}
	m := versionRe.FindSubmatch(raw)
	if m == nil {
		return "", fmt.Errorf("no NGINX_VERSION in src/core/nginx.h")
	}
	return string(m[1]), nil
}

var (
	// static ngx_command_t  ngx_http_rewrite_commands[] = { ... ngx_null_command
	arrayRe = regexp.MustCompile(`(?s)ngx_command_t\s+(\w+)_commands\[\]\s*=\s*\{(.*?)ngx_null_command`)
	// { ngx_string("rewrite"), NGX_HTTP_SRV_CONF|...|NGX_CONF_TAKE23,
	commandRe = regexp.MustCompile(`\{\s*ngx_string\("([^"]+)"\),\s*([A-Z0-9_|\s]+),`)
)

// contexts maps nginx's configuration context flags to the block names used
// in its documentation.
var contexts = []struct{ flag, name string }{
	{"NGX_MAIN_CONF", "main"},
	{"NGX_EVENT_CONF", "events"},
	{"NGX_HTTP_MAIN_CONF", "http"},
	{"NGX_HTTP_SRV_CONF", "server"},
	{"NGX_HTTP_SIF_CONF", "server if"},
	{"NGX_HTTP_LOC_CONF", "location"},
	{"NGX_HTTP_LIF_CONF", "location if"},
	{"NGX_HTTP_LMT_CONF", "limit_except"},
	{"NGX_HTTP_UPS_CONF", "upstream"},
	{"NGX_STREAM_MAIN_CONF", "stream"},
	{"NGX_STREAM_SRV_CONF", "stream server"},
	{"NGX_STREAM_UPS_CONF", "stream upstream"},
	{"NGX_MAIL_MAIN_CONF", "mail"},
	{"NGX_MAIL_SRV_CONF", "mail server"},
	{"NGX_ANY_CONF", "any"},
}

// extract reads every ngx_command_t array under dir. Directives behind
// build-time #if blocks are included: the list covers every directive nginx
// can be built with.
func extract(dir string) ([]coverage.Directive, error) {
	var out []coverage.Directive
	err := filepath.WalkDir(dir, func(path string, e fs.DirEntry, err error) error {
		if err != nil || e.IsDir() || !strings.HasSuffix(path, ".c") {
			return err
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, a := range arrayRe.FindAllSubmatch(raw, -1) {
			module := string(a[1]) + "_module"
			for _, c := range commandRe.FindAllSubmatch(a[2], -1) {
				d := coverage.Directive{Name: string(c[1]), Module: module}
				flags := string(c[2])
				for _, cx := range contexts {
					if hasFlag(flags, cx.flag) {
						d.Contexts = append(d.Contexts, cx.name)
					}
				}
				out = append(out, d)
			}
		}
		return nil
	})
	slices.SortStableFunc(out, func(a, b coverage.Directive) int { return cmp.Compare(a.Module, b.Module) })
	return slices.CompactFunc(out, func(a, b coverage.Directive) bool { return a.Key() == b.Key() }), err
}

func hasFlag(flags, flag string) bool {
	for f := range strings.SplitSeq(flags, "|") {
		if strings.TrimSpace(f) == flag {
			return true
		}
	}
	return false
}
