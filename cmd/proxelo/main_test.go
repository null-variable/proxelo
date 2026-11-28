package main

import "testing"

func TestDialAddr(t *testing.T) {
	for in, want := range map[string]string{
		"0.0.0.0:9443":   "127.0.0.1:9443",
		"[::]:9443":      "127.0.0.1:9443",
		":9443":          "127.0.0.1:9443",
		"127.0.0.1:9443": "127.0.0.1:9443",
		"10.0.0.5:9443":  "10.0.0.5:9443",
		"[::1]:9443":     "[::1]:9443",
		"localhost:9443": "localhost:9443",
		"no-port":        "no-port",
	} {
		if got := dialAddr(in); got != want {
			t.Errorf("dialAddr(%q) = %q, want %q", in, got, want)
		}
	}
}
