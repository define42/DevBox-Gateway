// Package collector embeds SauronHost -- the hypervisor-side collector that
// accepts SauronAgent guests over AF_VSOCK -- in another Go program.
//
// cmd/sauronhost is one such program: it reads a YAML file with a static
// CID-to-VM list and writes to the journal, a file or syslog. A program that
// manages the VMs itself, such as a libvirt front end, can instead build the
// configuration in code, resolve each connecting CID to a VM live with
// Options.Resolve, and deliver events to a Sink of its own.
//
// Every type here is an alias of the collector's own, so it carries the same
// documentation and, more importantly, the same guarantees: an event is
// acknowledged to the guest -- which then deletes its only copy -- once
// Sink.Write has returned nil for it, and not before.
package collector

import (
	"log/slog"
	"net"

	"github.com/define42/SauronAgent/internal/config"
	"github.com/define42/SauronAgent/internal/event"
	"github.com/define42/SauronAgent/internal/host"
	"github.com/define42/SauronAgent/internal/output"
	"github.com/define42/SauronAgent/internal/transport"
)

type (
	// Config is the collector configuration; start from DefaultConfig.
	Config = config.Host
	// VM is the trusted identity of the guest behind one CID.
	VM = config.VMMapping
	// Sink is a destination for enriched events. Write must return nil only
	// once the event is durably held, because that is what the guest is told.
	Sink = output.Sink
	// Envelope is one event as the collector emits it: the guest's event and
	// the host's trusted view of where it came from.
	Envelope = output.Envelope
	// Source is the host's description of where an event came from.
	Source = output.Source
	// Reported is what the guest claimed about itself. Untrusted.
	Reported = output.Reported
	// Event is one normalized SauronAgent event.
	Event = event.Event
	// Server is a running collector; see New.
	Server = host.Server
)

// Transport kinds for Config.Listen.Kind.
const (
	// TransportVSOCK is the production transport.
	TransportVSOCK = config.TransportVSOCK
	// TransportTCP carries no hypervisor-backed identity and exists for
	// development and tests only.
	TransportTCP = config.TransportTCP
)

// DefaultConfig returns the built-in collector configuration: AF_VSOCK on
// every CID, port 9000, no static VMs, and the default limits.
func DefaultConfig() Config {
	return config.DefaultHost()
}

// Options configures an embedded collector.
type Options struct {
	// Config is validated by New. Its output and logging sections are unused:
	// events go to Sink and diagnostics to Logger.
	Config Config
	// Sink receives every event, including the collector's own sauron.*
	// events. It is closed when the Server shuts down.
	Sink Sink
	// Logger receives the collector's diagnostics; nil discards them.
	Logger *slog.Logger
	// Resolve maps a hypervisor-assigned CID to its VM when a connection
	// arrives. It is consulted once per connection, before Config.VMs; see
	// the field of the same name in the collector's own options.
	Resolve func(cid uint32) (VM, bool)
	// Listener, when set, replaces the socket Config.Listen describes. The
	// Server owns it and closes it on shutdown.
	Listener net.Listener
}

// New validates the configuration and binds the listening socket, so a
// collector that cannot listen fails here rather than after it has been
// reported healthy. Call Run to serve and Close to stop.
func New(opts Options) (*Server, error) {
	hostOptions := host.Options{
		Config:  opts.Config,
		Sink:    opts.Sink,
		Logger:  opts.Logger,
		Resolve: opts.Resolve,
	}
	// Assigned only when set: a nil net.Listener stored in the interface would
	// be a non-nil transport.Listener, and the collector would accept on it.
	if opts.Listener != nil {
		hostOptions.Listener = transport.Listener(opts.Listener)
	}
	return host.New(hostOptions)
}

// NewFileSink returns a Sink that appends newline-delimited JSON envelopes to
// path with the collector's default size-based rotation (256 MiB per file,
// eight rotated files kept). Parent directories are created as needed.
func NewFileSink(path string) (Sink, error) {
	cfg := config.DefaultHost().Output.File
	cfg.Enabled = true
	cfg.Path = path
	return output.NewFile(cfg)
}

// NewMultiSink returns a Sink that writes every envelope to all of sinks and
// accepts it only when every one of them did.
func NewMultiSink(sinks ...Sink) Sink {
	return output.NewMulti(sinks...)
}
