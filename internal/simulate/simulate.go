// Package simulate runs requests against snapshots with the proxy's own
// engine: a resident `proxelo-proxy sim` helper loads each snapshot like a
// serving proxy and takes the requests through the same phases.
// The control plane never re-implements routing.
package simulate

import (
	"github.com/null-variable/proxelo/internal/model"

	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os/exec"
	"sync"
	"time"

	simv1 "github.com/null-variable/proxelo-api/gen/go/proxelo/sim/v1"
	"google.golang.org/protobuf/encoding/protodelim"
	"google.golang.org/protobuf/proto"
)

// ErrUnavailable means no helper binary is configured.
var ErrUnavailable = errors.New("simulator unavailable: no proxelo-proxy binary")

// callTimeout bounds one exchange with the helper. A snapshot build resolves
// addresses, so it gets more than a lookup would need.
const callTimeout = 30 * time.Second

// Helper owns one helper process, started on first use and restarted after
// it fails. Calls are serialized: the helper answers one message at a time.
type Helper struct {
	bin string
	log *slog.Logger

	mu  sync.Mutex
	cmd *exec.Cmd
	in  io.WriteCloser
	out *bufio.Reader
}

// New returns a helper running `bin sim`. An empty bin gives a helper whose
// calls fail with ErrUnavailable.
func New(bin string, log *slog.Logger) *Helper {
	return &Helper{bin: bin, log: log}
}

// Run loads snapshot and runs requests against it. A snapshot the proxy
// rejects is reported in the response's Error, not as an error.
func (h *Helper) Run(snapshot []byte, requests []*simv1.HttpRequest) (*simv1.SimResponse, error) {
	if h.bin == "" {
		return nil, ErrUnavailable
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.cmd == nil {
		if err := h.start(); err != nil {
			return nil, err
		}
	}
	resp, err := h.call(&simv1.SimRequest{Snapshot: snapshot, Requests: requests})
	if err != nil {
		h.log.Warn("simulator helper failed; restarting on next use", "err", err)
		h.stop()
		return nil, err
	}
	return resp, nil
}

// DryLoad loads a snapshot in the proxy engine before it is stored, so what
// only the engine checks (PCRE2 grammar, template variables, CEL,
// certificates) fails the change instead of the proxies.
// Without a helper binary it accepts everything. A rejection is a
// model.FieldErrors; ErrUnavailable-like failures are returned as is.
func (h *Helper) DryLoad(snapshot []byte) error {
	if h.bin == "" {
		return nil
	}
	resp, err := h.Run(snapshot, nil)
	if err != nil {
		return err
	}
	if resp.Error != "" {
		return model.FieldErrors{{Path: "snapshot", Message: resp.Error}}
	}
	return nil
}

func (h *Helper) start() error {
	cmd := exec.Command(h.bin, "sim")
	in, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	cmd.Stderr = nil
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("starting simulator: %w", err)
	}
	h.cmd, h.in, h.out = cmd, in, bufio.NewReader(out)
	return nil
}

func (h *Helper) stop() {
	if h.cmd == nil {
		return
	}
	h.in.Close()
	h.cmd.Process.Kill()
	h.cmd.Wait()
	h.cmd, h.in, h.out = nil, nil, nil
}

// Close stops the helper process.
func (h *Helper) Close() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.stop()
}

func (h *Helper) call(req *simv1.SimRequest) (*simv1.SimResponse, error) {
	b, err := proto.Marshal(req)
	if err != nil {
		return nil, err
	}
	frame := binary.AppendUvarint(nil, uint64(len(b)))
	frame = append(frame, b...)

	type result struct {
		resp *simv1.SimResponse
		err  error
	}
	done := make(chan result, 1)
	go func() {
		if _, err := h.in.Write(frame); err != nil {
			done <- result{err: fmt.Errorf("simulator write: %w", err)}
			return
		}
		resp := &simv1.SimResponse{}
		if err := (protodelim.UnmarshalOptions{MaxSize: -1}).UnmarshalFrom(h.out, resp); err != nil {
			done <- result{err: fmt.Errorf("simulator read: %w", err)}
			return
		}
		done <- result{resp: resp}
	}()
	select {
	case r := <-done:
		return r.resp, r.err
	case <-time.After(callTimeout):
		// Killing the helper unblocks the goroutine.
		return nil, errors.New("simulator timed out")
	}
}
