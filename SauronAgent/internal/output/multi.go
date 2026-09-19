package output

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// multiSink fans one envelope out to several destinations.
type multiSink struct {
	sinks []Sink
	name  string
}

// NewMulti returns a Sink that writes every envelope to all of sinks.
//
// Every operation is attempted on every sink even after one has failed. A
// broken destination must not hide events from the working ones, and the
// collector needs to know which sinks rejected an event, not merely the first.
// The failures are combined with errors.Join, so errors.Is and errors.As still
// find any of them.
//
// Nil sinks are skipped rather than stored: a nil entry is a wiring mistake in
// the caller, and panicking on the event path would take the collector down.
func NewMulti(sinks ...Sink) Sink {
	live := make([]Sink, 0, len(sinks))
	names := make([]string, 0, len(sinks))
	for _, s := range sinks {
		if s == nil {
			continue
		}
		live = append(live, s)
		names = append(names, s.Name())
	}
	return &multiSink{sinks: live, name: "multi(" + strings.Join(names, ",") + ")"}
}

// Write delivers the envelope to every sink, reporting failure if any sink
// rejected it. A non-nil result means the event must not be acknowledged to
// the guest, even though some sinks did accept it: a duplicate on replay is
// recoverable, a hole is not.
func (m *multiSink) Write(ctx context.Context, env *Envelope) error {
	var errs []error
	for _, s := range m.sinks {
		if err := s.Write(ctx, env); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", s.Name(), err))
		}
	}
	return errors.Join(errs...)
}

// Flush flushes every sink and reports every failure.
func (m *multiSink) Flush(ctx context.Context) error {
	var errs []error
	for _, s := range m.sinks {
		if err := s.Flush(ctx); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", s.Name(), err))
		}
	}
	return errors.Join(errs...)
}

// Close closes every sink. One sink failing to close must not leave the others
// open, so all of them are closed before the combined error is returned.
func (m *multiSink) Close() error {
	var errs []error
	for _, s := range m.sinks {
		if err := s.Close(); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", s.Name(), err))
		}
	}
	return errors.Join(errs...)
}

// Name lists the destinations, so a log line about a failing fan-out says
// which sinks were involved.
func (m *multiSink) Name() string { return m.name }
