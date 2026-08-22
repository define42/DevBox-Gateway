// Package gateway provides the DevBox HTTPS and RDP-over-TLS gateway.
package gateway

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/define42/devbox-gateway/internal/cert"
	"github.com/define42/devbox-gateway/internal/config"
	consolepkg "github.com/define42/devbox-gateway/internal/console"
	"github.com/define42/devbox-gateway/internal/rdp"
	"github.com/define42/devbox-gateway/internal/session"
	"github.com/define42/devbox-gateway/internal/virt"
)

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
	listener net.Listener
	frontTLS *cert.TLSManager

	// stopAutoShutdown stops the VDI auto-shutdown worker; nil when the
	// feature is disabled or the worker was never started.
	stopAutoShutdown func()

	// done is closed when the accept loop exits; serveErr is written exactly
	// once before that close, so it may be read only after done is observed
	// closed. A non-nil serveErr means the loop died on a permanent Accept
	// failure rather than a listener close.
	done     <-chan struct{}
	serveErr error
}

func (g *gatewayRuntime) Close() error {
	var errs []error

	if g.stopAutoShutdown != nil {
		g.stopAutoShutdown()
	}

	if g.listener != nil {
		if err := g.listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			errs = append(errs, err)
		}
	}

	if g.done != nil {
		select {
		case <-g.done:
		case <-time.After(5 * time.Second):
			errs = append(errs, fmt.Errorf("gateway listener did not stop in time"))
		}
	}

	if g.frontTLS != nil {
		if err := g.frontTLS.Close(); err != nil {
			errs = append(errs, err)
		}
	}

	return errors.Join(errs...)
}

func bootGateway() (*gatewayRuntime, error) {
	virt.GetInstance()

	rdp.InitLogging()

	settings, err := loadBootSettings()
	if err != nil {
		return nil, err
	}

	sessionManager := session.NewManager()
	sessionManager.SetUserConnectionLimit(settings.GetInt(config.MAX_CONNECTIONS_PER_USER))

	// Verbose per-connection console diagnostics, off unless DEBUG_CONNECTIONS.
	debugConns := settings.GetBool(config.DEBUG_CONNECTIONS)
	consolepkg.SetDebugLogging(debugConns)
	virt.SetVNCDebugLogging(debugConns)
	rdp.SetDebugLogging(debugConns)

	if err := virt.InitVirt(settings); err != nil {
		return nil, fmt.Errorf("failed to initialize virtualization: %w", err)
	}

	if err := config.EnsureSNIHashSecret(settings); err != nil {
		return nil, fmt.Errorf("failed to resolve SNI hash secret: %w", err)
	}

	mux := NewHandler(sessionManager, settings)

	frontTLS, err := cert.NewTLSManager(settings)
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
		listener: ln,
		frontTLS: frontTLS,
		done:     done,
	}
	go func() {
		runtime.serveErr = serveListener(ln, mux, frontTLS, sessionManager, settings)
		close(done)
	}()

	// Start ACME only once the front listener is accepting connections: ACME
	// TLS-ALPN-01 validation is answered through that listener. This is
	// non-fatal — the gateway serves the self-signed fallback while certmagic
	// keeps retrying issuance in the background, so slow DNS does not prevent
	// boot.
	if err := frontTLS.StartManaging(); err != nil {
		log.Printf("%v; continuing with the fallback certificate", err)
	}

	// Started last so no bootGateway failure path has to unwind it; a no-op
	// when VDI_AUTO_SHUTDOWN_HOURS is unset or non-positive.
	runtime.stopAutoShutdown = virt.StartAutoShutdownWorker(settings)

	return runtime, nil
}

// loadBootSettings resolves the process configuration for boot. Configuration
// lives in a KEY=VALUE config file (default
// /etc/devbox-gateway/devbox-gateway.conf, overridable via CONFIG_FILE), with
// explicit environment variables taking precedence so containers and
// development setups can override individual values.
func loadBootSettings() (*config.SettingsType, error) {
	if err := config.LoadConfigFile(config.FilePath()); err != nil {
		return nil, fmt.Errorf("failed to load config file: %w", err)
	}

	// Refuse to boot when a leftover config still enables the removed SSH
	// reverse-tunnel mode, rather than silently bind LISTEN_ADDR on a host that
	// only ever published itself through an outbound tunnel.
	if err := config.ValidateRemovedSSHTunnelMode(); err != nil {
		return nil, err
	}

	settings := config.NewSettingType(true)

	// FRONT_DOMAIN is the suffix the RDP front handler strips to recover a VM's
	// routing label; with it empty every RDP connection is rejected while the
	// dashboard still issues .rdp files. Refuse to boot in that broken state
	// rather than fail silently at connect time.
	if err := config.ValidateFrontDomain(settings); err != nil {
		return nil, err
	}
	return settings, nil
}
