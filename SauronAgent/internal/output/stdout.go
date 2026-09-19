package output

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/define42/SauronAgent/internal/config"
)

// Errors and the encoding below are shared by every sink in this package.

// errNilEnvelope is returned rather than panicking or writing "null": a caller
// that lost an envelope on the way to a sink must find out about it.
var errNilEnvelope = errors.New("output: nil envelope")

// errSinkClosed is returned by a sink that has already been closed. Accepting
// a write after Close would promise delivery that nothing is left to perform.
var errSinkClosed = errors.New("output: sink is closed")

// marshalLine renders one envelope as a single JSON document terminated by a
// newline, which is the form every sink here delivers.
//
// The whole document is built in memory before anything is written. Streaming
// straight into the destination would let a marshalling failure leave half an
// object in the evidence file, and a half object is indistinguishable from
// truncation by an intruder.
func marshalLine(env *Envelope, pretty bool) ([]byte, error) {
	if env == nil {
		return nil, errNilEnvelope
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	// Command lines and file paths routinely contain <, > and &. Escaping them
	// to < makes the evidence harder to read and to compare against the
	// preserved raw records, and buys no safety for a consumer that parses
	// JSON rather than pasting it into a web page.
	enc.SetEscapeHTML(false)
	if pretty {
		enc.SetIndent("", "  ")
	}
	if err := enc.Encode(env); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// stdoutSink writes newline-delimited JSON to an io.Writer.
type stdoutSink struct {
	// mu serializes whole envelopes. The collector serves many guests
	// concurrently, and two goroutines writing to the same fd without it
	// would splice one guest's event into another's line.
	mu     sync.Mutex
	w      io.Writer
	pretty bool
}

// NewStdout returns a sink writing newline-delimited JSON to standard output.
func NewStdout(cfg config.StdoutOutput) (Sink, error) {
	return newStdout(os.Stdout, cfg.Pretty), nil
}

// newStdout is the injectable form used by tests, which need to read back what
// was emitted rather than inspect the process's own standard output.
func newStdout(w io.Writer, pretty bool) *stdoutSink {
	return &stdoutSink{w: w, pretty: pretty}
}

// Write emits one envelope as a single JSON document.
func (s *stdoutSink) Write(ctx context.Context, env *Envelope) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	line, err := marshalLine(env, s.pretty)
	if err != nil {
		return fmt.Errorf("output/stdout: encoding envelope: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.w.Write(line); err != nil {
		return fmt.Errorf("output/stdout: %w", err)
	}
	return nil
}

// Flush is a no-op: every envelope is handed to the file descriptor by the
// time Write returns, so there is nothing held back that a flush could
// release. Standard output is deliberately not fsynced -- it is usually a pipe
// or a terminal, where Sync fails, and the operator's journal or log shipper
// owns durability from there.
func (s *stdoutSink) Flush(ctx context.Context) error { return ctx.Err() }

// Close does not close the underlying writer. The process does not own
// os.Stdout exclusively; closing it would break diagnostic logging configured
// to the same stream.
func (s *stdoutSink) Close() error { return nil }

// Name identifies the sink in logs and metrics.
func (s *stdoutSink) Name() string { return "stdout" }
