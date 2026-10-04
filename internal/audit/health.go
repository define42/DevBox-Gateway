package audit

import (
	"errors"
	"fmt"
	"io"
	"log"
	"sync"
)

// auditHealth latches the first rejected record. A later successful write
// cannot recover that record, so readiness requires operator intervention and
// a restart rather than silently turning healthy again.
type auditHealth struct {
	mu  sync.Mutex
	err error
}

func (h *auditHealth) failure(err error) {
	h.mu.Lock()
	first := h.err == nil
	if first {
		h.err = fmt.Errorf("application audit persistence failed: %w", err)
	}
	h.mu.Unlock()
	if first {
		// Operational logging must remain separate from slog's audit destination.
		log.Printf("audit: record persistence failed; audit readiness remains unhealthy until restart: %v", err)
	}
}

func (h *auditHealth) status() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.err
}

type observedAuditWriter struct {
	destination io.Writer
	health      *auditHealth
}

func (w observedAuditWriter) Write(p []byte) (int, error) {
	n, err := w.destination.Write(p)
	if err == nil && n != len(p) {
		err = io.ErrShortWrite
	}
	if err != nil {
		w.health.failure(err)
	}
	return n, err
}

// Readiness reports rejected audit records even though slog's logging API does
// not return handler errors, spool pressure, and HEC delivery that has stalled
// for longer than the configured timeout. The gateway uses it for its probe.
func (sink *configuredSink) Readiness() error {
	if sink.forwarder == nil {
		return sink.health.status()
	}
	return errors.Join(sink.health.status(), sink.forwarder.readiness())
}

// Admission refuses new audit-producing work when persistence has failed or
// the spool is under pressure. A remote outage alone can continue to buffer
// events even when the independent delivery-stall check fails readiness.
func (sink *configuredSink) Admission() error {
	if sink.forwarder == nil {
		return sink.health.status()
	}
	return errors.Join(sink.health.status(), sink.forwarder.capacityReadiness())
}
