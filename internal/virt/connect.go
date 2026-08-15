package virt

import (
	"fmt"
	"log"
	"sync"
	"time"

	"libvirt.org/go/libvirt"
)

// Keepalive parameters for every gateway-opened libvirt connection. Once a
// connection goes quiet libvirtd is probed every
// libvirtKeepAliveIntervalSeconds; after libvirtKeepAliveMaxMisses unanswered
// probes the client closes the connection, which fails every RPC blocked on
// it. This is the only mechanism that bounds an in-flight libvirt cgo call —
// such a call cannot be cancelled from Go — so without it a wedged libvirtd
// leaves request-path goroutines (VM create/remove, power, console, ownership
// checks) blocked forever. Worst-case detection is roughly
// (1+libvirtKeepAliveMaxMisses)*libvirtKeepAliveIntervalSeconds, ~20s.
const (
	libvirtKeepAliveIntervalSeconds = 5
	libvirtKeepAliveMaxMisses       = 3
)

var (
	libvirtEventLoopOnce sync.Once //nolint:gochecknoglobals // the libvirt event loop is registered once per process
	libvirtEventLoopErr  error     //nolint:gochecknoglobals // sticky result of the one-time event loop registration
	keepAliveWarnOnce    sync.Once //nolint:gochecknoglobals // connections are opened per request and per sweep; warn once, not per connection
)

// ensureLibvirtEventLoop registers libvirt's default event-loop implementation
// and starts the goroutine that runs it for the life of the process. The
// keepalive timers armed by SetKeepAlive only fire from this loop; without it
// keepalive is inert and a dead libvirtd is never detected. Registration
// happens lazily on the first connection rather than in main so every binary
// and test that reaches libvirt through this package gets it.
func ensureLibvirtEventLoop() error {
	libvirtEventLoopOnce.Do(func() {
		if err := libvirt.EventRegisterDefaultImpl(); err != nil {
			libvirtEventLoopErr = fmt.Errorf("register libvirt event loop: %w", err)
			return
		}
		go func() {
			for {
				if err := libvirt.EventRunDefaultImpl(); err != nil {
					log.Printf("libvirt event loop iteration: %v", err)
					// EventRunDefaultImpl blocks while healthy, so an error can
					// only repeat immediately; the pause keeps a persistent
					// failure from spinning this goroutine hot.
					time.Sleep(time.Second)
				}
			}
		}()
	})
	return libvirtEventLoopErr
}

// connectLibvirt opens the gateway's libvirt connection with keepalive armed
// so a hung libvirtd fails blocked RPCs in bounded time instead of wedging
// their goroutines forever. All production connections go through here;
// libvirt.NewConnect is called directly only by test fixtures.
func connectLibvirt() (*libvirt.Connect, error) {
	if err := ensureLibvirtEventLoop(); err != nil {
		return nil, err
	}
	conn, err := libvirt.NewConnect(LibvirtURI())
	if err != nil {
		return nil, err
	}
	if err := conn.SetKeepAlive(libvirtKeepAliveIntervalSeconds, libvirtKeepAliveMaxMisses); err != nil {
		// Local drivers (e.g. test:///default) have no RPC channel and refuse
		// keepalive. The connection still works; it just cannot detect a dead
		// peer, which matches the pre-keepalive behavior.
		keepAliveWarnOnce.Do(func() {
			log.Printf("libvirt keepalive unavailable on %s (hung RPCs will not be detected): %v", LibvirtURI(), err)
		})
	}
	return conn, nil
}
