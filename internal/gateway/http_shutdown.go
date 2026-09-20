package gateway

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
)

// httpServerRegistry owns the per-connection HTTP servers on the shared front
// listener. A hijacked connection stays registered until its handler returns;
// gateway shutdown closes the session registry first so the connection's
// session handoff either joins that drain or is refused, after which this
// registry waits for the handler to unwind. Admission stays closed once shutdown
// starts, including for connections that were still negotiating TLS when the
// listener stopped.
type httpServerRegistry struct {
	mu      sync.Mutex
	servers map[*http.Server]*httpServerRegistration
	closing bool
}

type httpServerRegistration struct {
	registry *httpServerRegistry
	server   *http.Server
	cancel   context.CancelFunc
	abort    func()
	done     chan struct{}
	once     sync.Once
	hijacked atomic.Bool
}

func newHTTPServerRegistry() *httpServerRegistry {
	return &httpServerRegistry{servers: make(map[*http.Server]*httpServerRegistration)}
}

func (r *httpServerRegistry) register(server *http.Server, cancel context.CancelFunc, abort func()) (*httpServerRegistration, bool) {
	entry := &httpServerRegistration{
		registry: r,
		server:   server,
		cancel:   cancel,
		abort:    abort,
		done:     make(chan struct{}),
	}
	server.Handler = entry.wrapHandler(server.Handler)
	server.ConnState = entry.connectionState
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closing {
		return nil, false
	}
	r.servers[server] = entry
	return entry, true
}

func (e *httpServerRegistration) connectionState(_ net.Conn, state http.ConnState) {
	switch state {
	case http.StateClosed:
		e.finish()
	case http.StateHijacked:
		// Hijack is only the start of the ownership transfer. The handler can
		// still be opening its backend before it registers with session.Manager,
		// so wrapHandler keeps this entry alive until the handler returns.
		e.hijacked.Store(true)
	case http.StateNew, http.StateActive, http.StateIdle:
		// Non-terminal HTTP states remain owned by the registry.
	}
}

func (e *httpServerRegistration) wrapHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		defer func() {
			if e.hijacked.Load() {
				e.finish()
			}
		}()
		if next == nil {
			http.DefaultServeMux.ServeHTTP(w, req)
			return
		}
		next.ServeHTTP(w, req)
	})
}

func (e *httpServerRegistration) finish() {
	e.once.Do(func() {
		e.registry.mu.Lock()
		delete(e.registry.servers, e.server)
		e.registry.mu.Unlock()
		close(e.done)
	})
}

func (r *httpServerRegistry) shutdown(ctx context.Context) error {
	r.mu.Lock()
	r.closing = true
	servers := make([]*httpServerRegistration, 0, len(r.servers))
	for _, server := range r.servers {
		servers = append(servers, server)
	}
	r.mu.Unlock()

	results := make(chan error, len(servers))
	for _, server := range servers {
		go func() { results <- server.shutdown(ctx) }()
	}
	var errs []error
	for range servers {
		if err := <-results; err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (e *httpServerRegistration) shutdown(ctx context.Context) error {
	// Shutdown can be inside a connection Close (for example, a TLS
	// close-notify write to a stalled peer) when its deadline expires. Interrupt
	// the transport independently so that even that path observes the bound.
	stopAbort := context.AfterFunc(ctx, e.abortRequest)
	defer stopAbort()
	err := e.server.Shutdown(ctx)
	if err == nil {
		err = ctx.Err()
	}
	if err == nil {
		select {
		case <-e.done:
			return nil
		case <-ctx.Done():
			err = ctx.Err()
		}
	}
	select {
	case <-e.done:
		// The handler may have completed as the grace period ended. Do not
		// interrupt cleanup that has already finished.
		return err
	default:
	}

	// Cancel even handlers that have not read their request body. Closing the
	// underlying transport first also prevents TLS close-notify from stalling
	// Server.Close. Wait briefly for cancellation-aware handlers to finish their
	// cleanup and audit events before the runtime closes the audit sink.
	e.abortRequest()
	err = errors.Join(err, e.server.Close())
	cleanupCtx, cancel := context.WithTimeout(context.Background(), gatewayShutdownTimeout)
	defer cancel()
	select {
	case <-e.done:
		return err
	case <-cleanupCtx.Done():
		return errors.Join(err, fmt.Errorf("HTTP handler did not stop after cancellation: %w", cleanupCtx.Err()))
	}
}

func (e *httpServerRegistration) abortRequest() {
	select {
	case <-e.done:
		return
	default:
		e.cancel()
		e.abort()
	}
}
