package main

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"slices"
	"strings"
	"sync"
	"time"
)

// EchoRecord is the request an upstream received, as it arrived on the wire.
type EchoRecord struct {
	Method  string
	URI     string
	Proto   string
	Headers []string // "name: value", lowercase names, in arrival order
	Body    string
}

func (r *EchoRecord) String() string { return r.Method + " " + r.URI }

// upstreamVolatile headers depend on how the proxy reuses upstream
// connections, which the cases do not configure alike.
var upstreamVolatile = map[string]bool{"connection": true}

func (r *EchoRecord) diff(p *EchoRecord) []string {
	var d []string
	if r.Method != p.Method {
		d = append(d, fmt.Sprintf("upstream method: nginx %s, proxelo %s", r.Method, p.Method))
	}
	if r.URI != p.URI {
		d = append(d, fmt.Sprintf("upstream uri: nginx %s, proxelo %s", r.URI, p.URI))
	}
	nh, ph := r.headerSet(), p.headerSet()
	for _, h := range nh {
		if !slices.Contains(ph, h) {
			d = append(d, "upstream header only from nginx: "+h)
		}
	}
	for _, h := range ph {
		if !slices.Contains(nh, h) {
			d = append(d, "upstream header only from proxelo: "+h)
		}
	}
	if r.Body != p.Body {
		d = append(d, fmt.Sprintf("upstream body: nginx %q, proxelo %q", preview([]byte(r.Body)), preview([]byte(p.Body))))
	}
	return d
}

// headerSet is the headers without volatile ones, sorted: header order is
// not part of HTTP semantics.
func (r *EchoRecord) headerSet() []string {
	var out []string
	for _, h := range r.Headers {
		name, _, _ := strings.Cut(h, ":")
		if !upstreamVolatile[name] {
			out = append(out, h)
		}
	}
	slices.Sort(out)
	return out
}

// echo is the upstream of every case: it records each request and answers
// 200 with a fixed body that names the request and the port that took it,
// so a wrong URI or a different target choice also shows in the response.
type echo struct {
	lns  []net.Listener
	mu   sync.Mutex
	rec  *EchoRecord
	done sync.WaitGroup
}

// startEcho listens on every address in addrs.
func startEcho(addrs ...string) (*echo, error) {
	e := &echo{}
	for _, addr := range addrs {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			e.Close()
			return nil, err
		}
		e.lns = append(e.lns, ln)
		e.done.Add(1)
		go e.serve(ln)
	}
	return e, nil
}

func (e *echo) Close() {
	for _, ln := range e.lns {
		ln.Close()
	}
	e.done.Wait()
}

func (e *echo) reset() {
	e.mu.Lock()
	e.rec = nil
	e.mu.Unlock()
}

// last is the request of the current exchange. It is stored before the
// response is written, so it is set once the client has the response.
func (e *echo) last() *EchoRecord {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.rec
}

func (e *echo) serve(ln net.Listener) {
	defer e.done.Done()
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go e.conn(c)
	}
}

// conn reads requests with a minimal parser rather than net/http, so the
// record is what came over the wire (header case aside) with nothing added
// or merged.
func (e *echo) conn(c net.Conn) {
	defer c.Close()
	br := bufio.NewReader(c)
	for {
		c.SetReadDeadline(time.Now().Add(30 * time.Second))
		line, err := br.ReadString('\n')
		if err != nil {
			return
		}
		parts := strings.SplitN(strings.TrimRight(line, "\r\n"), " ", 3)
		if len(parts) != 3 {
			return
		}
		rec := &EchoRecord{Method: parts[0], URI: parts[1], Proto: parts[2]}
		length, chunked, closeConn := 0, false, parts[2] == "HTTP/1.0"
		for {
			h, err := br.ReadString('\n')
			if err != nil {
				return
			}
			h = strings.TrimRight(h, "\r\n")
			if h == "" {
				break
			}
			name, value, _ := strings.Cut(h, ":")
			name, value = strings.ToLower(strings.TrimSpace(name)), strings.TrimSpace(value)
			rec.Headers = append(rec.Headers, name+": "+value)
			switch name {
			case "content-length":
				fmt.Sscan(value, &length)
			case "transfer-encoding":
				chunked = strings.EqualFold(value, "chunked")
			case "connection":
				closeConn = strings.EqualFold(value, "close")
			}
		}
		body, err := readBody(br, length, chunked)
		if err != nil {
			return
		}
		rec.Body = body
		e.mu.Lock()
		e.rec = rec
		e.mu.Unlock()

		_, port, _ := net.SplitHostPort(c.LocalAddr().String())
		resp := "upstream " + port + " saw " + rec.Method + " " + rec.URI + "\n"
		conn := "keep-alive"
		if closeConn {
			conn = "close"
		}
		fmt.Fprintf(c, "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: %d\r\nX-Upstream: echo\r\nConnection: %s\r\n\r\n%s", len(resp), conn, resp)
		if closeConn {
			return
		}
	}
}

func readBody(br *bufio.Reader, length int, chunked bool) (string, error) {
	if !chunked {
		b := make([]byte, length)
		_, err := io.ReadFull(br, b)
		return string(b), err
	}
	var out strings.Builder
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return "", err
		}
		var n int
		if _, err := fmt.Sscanf(strings.TrimSpace(line), "%x", &n); err != nil {
			return "", err
		}
		if n == 0 {
			for {
				t, err := br.ReadString('\n')
				if err != nil || t == "\r\n" {
					return out.String(), err
				}
			}
		}
		b := make([]byte, n+2)
		if _, err := io.ReadFull(br, b); err != nil {
			return "", err
		}
		out.Write(b[:n])
	}
}
