package gateway

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	httppprof "net/http/pprof"
	"strings"
	"sync"
	"time"

	"github.com/define42/devbox-gateway/internal/config"
)

const (
	pprofReadHeaderTimeout = 5 * time.Second
	pprofIdleTimeout       = 30 * time.Second
)

// pprofRuntime owns the optional profiler listener. It deliberately has no
// relationship to the public gateway handler or its multiplexed TLS listener.
type pprofRuntime struct {
	listener net.Listener
	server   *http.Server
	done     <-chan error

	closeOnce sync.Once
	closeErr  error
}

func startPprofServer(settings *config.Settings) (*pprofRuntime, error) {
	if settings == nil {
		return nil, nil
	}

	listenAddr := strings.TrimSpace(settings.String(config.PPROF_LISTEN_ADDR))
	if listenAddr == "" {
		return nil, nil
	}
	if err := validatePprofListenAddress(listenAddr); err != nil {
		return nil, fmt.Errorf("%s: %w", config.PPROF_LISTEN_ADDR, err)
	}

	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return nil, fmt.Errorf("listen on %q: %w", listenAddr, err)
	}

	server := &http.Server{
		Handler:           newPprofHandler(),
		ReadHeaderTimeout: pprofReadHeaderTimeout,
		IdleTimeout:       pprofIdleTimeout,
	}
	done := make(chan error, 1)
	runtime := &pprofRuntime{
		listener: listener,
		server:   server,
		done:     done,
	}
	go func() {
		serveErr := server.Serve(listener)
		if errors.Is(serveErr, http.ErrServerClosed) || errors.Is(serveErr, net.ErrClosed) {
			serveErr = nil
		}
		if serveErr != nil {
			log.Printf("pprof listener stopped: %v", serveErr)
		}
		done <- serveErr
		close(done)
	}()

	log.Printf("pprof listening on http://%s/debug/pprof/ (loopback only)", listener.Addr())
	return runtime, nil
}

func validatePprofListenAddress(listenAddr string) error {
	host, port, err := net.SplitHostPort(listenAddr)
	if err != nil {
		return fmt.Errorf("must be a host:port address: %w", err)
	}
	if port == "" {
		return fmt.Errorf("port must not be empty")
	}

	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("host %q must be a literal loopback IP address", host)
	}
	if !ip.IsLoopback() {
		return fmt.Errorf("host %q is not a loopback IP address", host)
	}
	return nil
}

func newPprofHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/debug/pprof/", httppprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", httppprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", httppprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", httppprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", httppprof.Trace)
	return mux
}

func (p *pprofRuntime) Close() error {
	if p == nil {
		return nil
	}
	p.closeOnce.Do(func() {
		p.closeErr = p.close()
	})
	return p.closeErr
}

func (p *pprofRuntime) close() error {
	shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), gatewayShutdownTimeout)
	defer cancelShutdown()

	var errs []error
	if err := p.server.Shutdown(shutdownCtx); err != nil {
		errs = append(errs, fmt.Errorf("shut down pprof server: %w", err))
		if closeErr := p.server.Close(); closeErr != nil {
			errs = append(errs, fmt.Errorf("close pprof server: %w", closeErr))
		}
	}

	select {
	case serveErr := <-p.done:
		if serveErr != nil {
			errs = append(errs, fmt.Errorf("serve pprof: %w", serveErr))
		}
	case <-time.After(gatewayShutdownTimeout):
		errs = append(errs, fmt.Errorf("pprof listener did not stop in time"))
	}

	return errors.Join(errs...)
}
