// Package sauron runs the SauronAgent host collector inside the gateway.
//
// Every VM the gateway boots gets a virtio-vsock device. The SauronAgent
// inside it reads the guest kernel's audit stream and sends it to the host
// over AF_VSOCK, so it needs no guest networking at all. The collector
// attributes each connection to a VM by the CID libvirt assigned to it --
// never by anything the guest says about itself -- and writes every event to
// a local JSON Lines file and, optionally, to a durable spool that is
// forwarded to a Splunk HTTP Event Collector.
package sauron

import (
	"context"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/define42/SauronAgent/collector"

	"github.com/define42/devbox-gateway/internal/splunkhec"
)

// stopTimeout bounds Close. Sessions end promptly: no output waits on Splunk.
const stopTimeout = 5 * time.Second

// VM is what the gateway knows about the VM behind a CID.
type VM struct {
	Name  string
	UUID  string
	Owner string
}

// Options configures the embedded collector.
type Options struct {
	// Port is the AF_VSOCK port guests dial on the host (CID 2).
	Port uint32
	// EventLogFile is the JSON Lines file every event is appended to, rotated
	// by size; empty disables it.
	EventLogFile string
	// HEC also delivers every event to a Splunk HTTP Event Collector when its
	// Endpoint is set, by way of the spool below.
	HEC splunkhec.Config
	// SpoolDir holds guest events until Splunk has accepted them; they
	// survive gateway restarts there. Used when HEC.Endpoint is set.
	SpoolDir string
	// SpoolMaxBytes bounds the spool. When it is full, events are no longer
	// acknowledged, so they wait in the guests' own spools.
	SpoolMaxBytes int64
	// Resolve returns the running VM that holds a CID. Its answer is the
	// authoritative identity of every event on a connection, so it must come
	// from the hypervisor.
	Resolve func(cid uint32) (VM, bool, error)

	// listener replaces the AF_VSOCK socket in tests.
	listener net.Listener
}

// Collector is the running SauronAgent collector.
type Collector struct {
	server *collector.Server
	cancel context.CancelFunc
	done   chan struct{}
	runErr error

	closeOnce sync.Once
	closeErr  error
}

// Start opens the event outputs, binds the AF_VSOCK listener and starts
// accepting guests. A collector that cannot listen fails here, so a gateway
// configured to collect guest events never runs without doing so.
func Start(options Options) (*Collector, error) {
	sink, err := openSinks(options)
	if err != nil {
		return nil, err
	}

	config := collector.DefaultConfig()
	config.Listen.Port = options.Port
	server, err := collector.New(collector.Options{
		Config:   config,
		Sink:     sink,
		Logger:   newLogger(),
		Resolve:  resolver(options.Resolve),
		Listener: options.listener,
	})
	if err != nil {
		// The server never took ownership of the sink.
		return nil, errors.Join(err, sink.Close())
	}

	ctx, cancel := context.WithCancel(context.Background())
	c := &Collector{server: server, cancel: cancel, done: make(chan struct{})}
	go func() {
		defer close(c.done)
		c.runErr = server.Run(ctx)
	}()
	log.Printf("sauron: collecting SauronAgent guest events on vsock port %d", options.Port)
	return c, nil
}

// openSinks builds the configured outputs. The collector accepts an event --
// and the guest deletes it -- only when every one of them has, which for
// Splunk means once the event is in the gateway's spool.
func openSinks(options Options) (collector.Sink, error) {
	var sinks []collector.Sink
	if path := strings.TrimSpace(options.EventLogFile); path != "" {
		file, err := collector.NewFileSink(path)
		if err != nil {
			return nil, fmt.Errorf("open sauron event log: %w", err)
		}
		sinks = append(sinks, file)
	}

	if strings.TrimSpace(options.HEC.Endpoint) != "" {
		forwarding, err := newHECForwarding(options.HEC, options.SpoolDir, options.SpoolMaxBytes)
		if err != nil {
			for _, sink := range sinks {
				_ = sink.Close()
			}
			return nil, fmt.Errorf("configure sauron splunk hec forwarding: %w", err)
		}
		forwarding.start()
		sinks = append(sinks, forwarding)
	}

	if len(sinks) == 0 {
		return nil, errors.New("sauron: no event output is configured")
	}
	return collector.NewMultiSink(sinks...), nil
}

// resolver adapts the gateway's VM lookup to the collector. A failed lookup
// records the guest as unknown rather than refusing it, so its events are
// still collected, under an unknown-cid-N name.
func resolver(resolve func(cid uint32) (VM, bool, error)) func(cid uint32) (collector.VM, bool) {
	if resolve == nil {
		return nil
	}
	return func(cid uint32) (collector.VM, bool) {
		vm, ok, err := resolve(cid)
		if err != nil {
			log.Printf("sauron: resolve vsock cid %d: %v; recording the guest as unknown", cid, err)
			return collector.VM{}, false
		}
		if !ok {
			return collector.VM{}, false
		}
		mapping := collector.VM{CID: cid, Name: vm.Name, UUID: vm.UUID}
		if vm.Owner != "" {
			mapping.Labels = map[string]string{"owner": vm.Owner}
		}
		return mapping, true
	}
}

// Close stops accepting guests and ends every session, acknowledging what
// was accepted, then closes the outputs. Spooled events not yet delivered to
// Splunk are delivered after the next start.
func (c *Collector) Close() error {
	c.closeOnce.Do(func() {
		c.cancel()
		select {
		case <-c.done:
			c.closeErr = c.runErr
		case <-time.After(stopTimeout):
			c.closeErr = errors.New("sauron collector did not stop in time")
		}
	})
	return c.closeErr
}

// newLogger routes the collector's diagnostics to the standard log package.
// It must not use slog.Default: that is the gateway's audit logger, and guest
// session diagnostics do not belong in the audit stream.
func newLogger() *slog.Logger {
	handler := slog.NewTextHandler(stdLogWriter{}, &slog.HandlerOptions{
		ReplaceAttr: func(groups []string, attr slog.Attr) slog.Attr {
			// The log package stamps its own time.
			if len(groups) == 0 && attr.Key == slog.TimeKey {
				return slog.Attr{}
			}
			return attr
		},
	})
	return slog.New(handler).With("component", "sauron")
}

// stdLogWriter writes each formatted record through the log package, so it
// follows whatever destination and prefix log is configured with.
type stdLogWriter struct{}

func (stdLogWriter) Write(record []byte) (int, error) {
	if err := log.Output(2, string(record)); err != nil {
		return 0, err
	}
	return len(record), nil
}
