// Package gateway provides the DevBox HTTPS and RDP-over-TLS gateway.
package gateway

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"github.com/define42/devbox-gateway/internal/audit"
	"github.com/define42/devbox-gateway/internal/cert"
	"github.com/define42/devbox-gateway/internal/config"
	consolepkg "github.com/define42/devbox-gateway/internal/console"
	"github.com/define42/devbox-gateway/internal/rdp"
	"github.com/define42/devbox-gateway/internal/session"
	"github.com/define42/devbox-gateway/internal/virt"
)

const gatewayShutdownTimeout = 5 * time.Second

// Run boots the gateway and blocks until ctx is canceled or the listener stops.
// It returns a process exit code so the command entrypoint remains a thin
// adapter around the application lifecycle.
func Run(ctx context.Context) int {
	gateway, err := bootGateway()
	if err != nil {
		// If booting the gateway fails, we can't do much about it, so log and exit.
		log.Printf("Failed to boot gateway: %v", err)
		return 1
	}
	defer func() {
		if err := gateway.Close(); err != nil {
			log.Printf("gateway shutdown: %v", err)
		}
	}()

	select {
	case <-ctx.Done():
		return 0
	case <-gateway.done:
		// The accept loop exited without a shutdown signal, i.e. Accept failed
		// permanently. Exit non-zero so systemd's Restart=on-failure replaces
		// the process instead of leaving it alive but unable to serve anything
		// (including /api/health, which is answered through this listener).
		if gateway.serveErr != nil {
			log.Printf("gateway stopped serving: %v", gateway.serveErr)
		}
		return 1
	}
}

type gatewayRuntime struct {
	listener       net.Listener
	frontTLS       *cert.TLSManager
	sessionManager *session.Manager
	auditSink      io.Closer

	// stopAutoShutdown stops the VDI auto-shutdown worker; nil when the
	// feature is disabled or the worker was never started.
	stopAutoShutdown func()

	// done is closed when the accept loop exits; serveErr is written exactly
	// once before that close, so it may be read only after done is observed
	// closed. A non-nil serveErr means the loop died on a permanent Accept
	// failure rather than a listener close.
	done     <-chan struct{}
	serveErr error

	closeOnce sync.Once
	closeErr  error
}

func (g *gatewayRuntime) Close() error {
	g.closeOnce.Do(func() {
		g.closeErr = g.close()
	})
	return g.closeErr
}

func (g *gatewayRuntime) close() error {
	if g.stopAutoShutdown != nil {
		g.stopAutoShutdown()
	}

	return errors.Join(
		g.closeListener(),
		g.drainConnections(),
		g.closeFrontTLS(),
		g.closeAuditSink(),
	)
}

func (g *gatewayRuntime) closeListener() error {
	var errs []error

	if g.listener != nil {
		if err := g.listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			errs = append(errs, err)
		}
	}

	if g.done != nil {
		select {
		case <-g.done:
		case <-time.After(gatewayShutdownTimeout):
			errs = append(errs, fmt.Errorf("gateway listener did not stop in time"))
		}
	}

	return errors.Join(errs...)
}

func (g *gatewayRuntime) drainConnections() error {
	if g.sessionManager == nil {
		return nil
	}

	drainCtx, cancelDrain := context.WithTimeout(context.Background(), gatewayShutdownTimeout)
	defer cancelDrain()
	closed, err := g.sessionManager.CloseAllConnections(drainCtx)
	if err != nil {
		return fmt.Errorf("drain %d live gateway connection(s): %w", closed, err)
	}
	return nil
}

func (g *gatewayRuntime) closeFrontTLS() error {
	if g.frontTLS == nil {
		return nil
	}
	return g.frontTLS.Close()
}

func (g *gatewayRuntime) closeAuditSink() error {
	// Keep the audit sink open until all active gateway connections have been
	// drained so their disconnect records are durably emitted before shutdown.
	if g.auditSink == nil {
		return nil
	}
	if err := g.auditSink.Close(); err != nil {
		return fmt.Errorf("close audit log: %w", err)
	}
	return nil
}

func bootGateway() (_ *gatewayRuntime, retErr error) {
	vmInventory := virt.NewInventory()

	rdp.InitLogging()

	settings, err := loadBootSettings()
	if err != nil {
		return nil, err
	}

	auditSink, err := audit.ConfigureJSONFile(settings.Get(config.AUDIT_LOG_FILE))
	if err != nil {
		return nil, fmt.Errorf("configure audit log: %w", err)
	}
	keepAuditSink := false
	defer func() {
		if keepAuditSink {
			return
		}
		if err := auditSink.Close(); err != nil {
			retErr = errors.Join(retErr, fmt.Errorf("close audit log after failed startup: %w", err))
		}
	}()

	sessionManager := session.New()
	sessionManager.SetUserConnectionLimit(settings.Int(config.MAX_CONNECTIONS_PER_USER))

	configureConnectionDebugLogging(settings)

	if err := virt.Init(settings); err != nil {
		return nil, fmt.Errorf("failed to initialize virtualization: %w", err)
	}

	if err := config.EnsureSNIHashSecret(settings); err != nil {
		return nil, fmt.Errorf("failed to resolve sni hash secret: %w", err)
	}

	runtime, err := startGatewayRuntime(settings, vmInventory, sessionManager, auditSink)
	if err != nil {
		return nil, err
	}
	keepAuditSink = true
	return runtime, nil
}

func startGatewayRuntime(
	settings *config.Settings,
	vmInventory *virt.Inventory,
	sessionManager *session.Manager,
	auditSink io.Closer,
) (*gatewayRuntime, error) {
	frontTLS, err := cert.NewTLSManager(settings, vmInventory.VMNames)
	if err != nil {
		return nil, fmt.Errorf("tls setup: %w", err)
	}

	ln, err := openFrontListener(settings)
	if err != nil {
		_ = frontTLS.Close()
		return nil, err
	}

	done := make(chan struct{})
	runtime := &gatewayRuntime{
		listener:       ln,
		frontTLS:       frontTLS,
		sessionManager: sessionManager,
		auditSink:      auditSink,
		done:           done,
	}
	mux := NewHandler(sessionManager, settings)
	go func() {
		runtime.serveErr = serveListener(ln, mux, frontTLS, sessionManager, settings)
		close(done)
	}()

	// Start ACME only once the front listener is accepting connections. Failure
	// is non-fatal: the gateway continues with its fallback certificate.
	if err := frontTLS.StartManaging(); err != nil {
		log.Printf("%v; continuing with the fallback certificate", err)
	}

	// Started last so no failure path has to unwind it; this is a no-op when
	// VDI_AUTO_SHUTDOWN_HOURS is unset or non-positive.
	runtime.stopAutoShutdown = virt.StartAutoShutdownWorker(settings)
	return runtime, nil
}

func configureConnectionDebugLogging(settings *config.Settings) {
	// Verbose per-connection console diagnostics, off unless DEBUG_CONNECTIONS.
	debugConns := settings.Bool(config.DEBUG_CONNECTIONS)
	consolepkg.SetDebugLogging(debugConns)
	virt.SetVNCDebugLogging(debugConns)
	rdp.SetDebugLogging(debugConns)
}

// loadBootSettings resolves the process configuration for boot. Configuration
// lives in a KEY=VALUE config file (default
// /etc/devbox-gateway/devbox-gateway.conf, overridable via CONFIG_FILE), with
// explicit environment variables taking precedence so containers and
// development setups can override individual values.
func loadBootSettings() (*config.Settings, error) {
	if err := config.LoadConfigFile(config.FilePath()); err != nil {
		return nil, fmt.Errorf("failed to load config file: %w", err)
	}

	// Refuse to boot when a leftover config still enables the removed SSH
	// reverse-tunnel mode, rather than silently bind LISTEN_ADDR on a host that
	// only ever published itself through an outbound tunnel.
	if err := config.ValidateRemovedSSHTunnelMode(); err != nil {
		return nil, err
	}

	settings := config.NewSettings(true)
	if err := config.ValidateLDAPURL(settings); err != nil {
		return nil, err
	}

	// FRONT_DOMAIN is the suffix the RDP front handler strips to recover a VM's
	// routing label; with it empty every RDP connection is rejected while the
	// dashboard still issues .rdp files. Refuse to boot in that broken state
	// rather than fail silently at connect time.
	if err := config.ValidateFrontDomain(settings); err != nil {
		return nil, err
	}
	return settings, nil
}
