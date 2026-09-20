package config

import (
	"fmt"
	"path/filepath"
)

// TransportKind selects how the agent reaches the host.
type TransportKind string

const (
	// TransportVSOCK is the production transport: AF_VSOCK, independent of the
	// guest's IP configuration.
	TransportVSOCK TransportKind = "vsock"
	// TransportTCP is for development and integration testing only. It is
	// never the right choice in a deployment, because it reintroduces the
	// dependency on guest networking that VSOCK exists to remove.
	TransportTCP TransportKind = "tcp"
)

// VMADDR_CID_HOST is the CID Linux reserves for the hypervisor host.
const VMADDR_CID_HOST = 2

// Agent is the guest-side configuration.
type Agent struct {
	Agent     AgentSection     `yaml:"agent"`
	Audit     AuditSection     `yaml:"audit"`
	Transport TransportSection `yaml:"transport"`
	VSOCK     VSOCKSection     `yaml:"vsock"`
	Queue     QueueSection     `yaml:"queue"`
	Spool     SpoolSection     `yaml:"spool"`
	Heartbeat HeartbeatSection `yaml:"heartbeat"`
	Reconnect ReconnectSection `yaml:"reconnect"`
	Logging   LoggingSection   `yaml:"logging"`
}

// AgentSection carries agent-wide identification.
type AgentSection struct {
	// Name appears in local logs only. The host does not trust it.
	Name string `yaml:"name"`
}

// AuditSection configures audit collection.
type AuditSection struct {
	// Enabled turns the NETLINK_AUDIT reader on. Disabling it is only useful
	// for testing the transport in isolation.
	Enabled bool `yaml:"enabled"`

	// ManageRules enables kernel auditing and installs the built-in security
	// policy at startup. Production enables it and requires CAP_AUDIT_CONTROL
	// and CAP_AUDIT_READ, plus CAP_DAC_READ_SEARCH for private SSH directories.
	ManageRules bool `yaml:"manage_rules"`

	// PreserveRaw keeps the original kernel record text on every event.
	// Turning it off shrinks events but discards the forensic evidence that
	// normalization was derived from.
	PreserveRaw bool `yaml:"preserve_raw"`

	// CorrelationTimeout is how long a partially assembled event waits for
	// more records before being emitted anyway. The kernel usually closes an
	// event with an EOE record, but not for every record type, so a timeout is
	// what guarantees an event is never held forever.
	CorrelationTimeout Duration `yaml:"correlation_timeout"`

	// MaxPendingEvents bounds how many partially assembled events the
	// correlator holds at once. Reaching it forces the oldest out early
	// rather than growing without limit.
	MaxPendingEvents int `yaml:"max_pending_events"`

	// SocketReceiveBuffer requests a larger SO_RCVBUF on the netlink socket.
	// Audit traffic is bursty and the kernel drops multicast records that do
	// not fit, so this directly affects how much burst is survivable.
	SocketReceiveBuffer Size `yaml:"socket_receive_buffer"`

	// ExcludeTypes lists canonical record type names to drop before
	// correlation, e.g. ["NETFILTER_PKT"]. Use sparingly: anything excluded
	// here never reaches the host.
	ExcludeTypes []string `yaml:"exclude_types"`
}

// TransportSection selects the transport implementation.
type TransportSection struct {
	Kind TransportKind `yaml:"kind"`

	// TCPAddress is the host:port used when Kind is "tcp". Testing only.
	TCPAddress string `yaml:"tcp_address"`

	// MaxPayloadSize bounds an individual protocol frame.
	MaxPayloadSize Size `yaml:"max_payload_size"`

	// WriteTimeout bounds a single frame write, so a host that stops reading
	// cannot wedge the sender indefinitely.
	WriteTimeout Duration `yaml:"write_timeout"`

	// AckTimeout is how long the sender waits for acknowledgement progress
	// before treating the connection as dead.
	AckTimeout Duration `yaml:"ack_timeout"`

	// MaxUnacked bounds how many events may be in flight without
	// acknowledgement before the sender pauses.
	MaxUnacked int `yaml:"max_unacked"`
}

// VSOCKSection addresses the host collector.
type VSOCKSection struct {
	// CID is the destination context ID. It should normally stay at 2, which
	// Linux reserves as VMADDR_CID_HOST.
	CID uint32 `yaml:"cid"`
	// Port is the host collector's VSOCK port.
	Port uint32 `yaml:"port"`
}

// QueueSection bounds the in-memory queue between collection and transport.
type QueueSection struct {
	// Capacity is the maximum number of events held in memory.
	Capacity int `yaml:"capacity"`
}

// SpoolSection configures the disk-backed spool.
type SpoolSection struct {
	Enabled bool   `yaml:"enabled"`
	Path    string `yaml:"path"`

	// MaxSize bounds total spool size on disk. On reaching it the agent emits
	// sauron.spool.full and drops the oldest unsent data, recording exactly
	// which sequence numbers were lost.
	MaxSize Size `yaml:"max_size"`

	// SegmentSize is the size at which a spool segment is rolled.
	SegmentSize Size `yaml:"segment_size"`

	// SyncOnWrite fsyncs every appended record. It is the difference between
	// surviving an agent crash and surviving a guest power loss, and costs a
	// great deal of throughput.
	SyncOnWrite bool `yaml:"sync_on_write"`

	// SyncInterval fsyncs periodically when SyncOnWrite is false.
	SyncInterval Duration `yaml:"sync_interval"`
}

// HeartbeatSection configures the agent's liveness reporting.
type HeartbeatSection struct {
	Interval Duration `yaml:"interval"`
	// Timeout is how long to wait for a PONG before assuming the link is dead.
	Timeout Duration `yaml:"timeout"`
}

// ReconnectSection configures exponential backoff on transport failure.
type ReconnectSection struct {
	InitialDelay Duration `yaml:"initial_delay"`
	MaxDelay     Duration `yaml:"max_delay"`
	// Multiplier grows the delay after each consecutive failure.
	Multiplier float64 `yaml:"multiplier"`
	// Jitter is the fraction of the delay randomised, in [0,1). It stops a
	// fleet of guests from reconnecting to a restarted host in lockstep.
	Jitter float64 `yaml:"jitter"`
}

// LoggingSection configures the agent's own diagnostic logging, which is
// separate from the audit events it forwards.
type LoggingSection struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
	// Output is "stderr", "stdout" or a file path.
	Output string `yaml:"output"`
}

// DefaultAgent returns the complete configuration compiled into sauronagent.
// Production startup uses this value directly and does not layer a file over it.
func DefaultAgent() Agent {
	return Agent{
		Agent: AgentSection{Name: "sauronagent"},
		Audit: AuditSection{
			ManageRules:         true,
			Enabled:             true,
			PreserveRaw:         true,
			CorrelationTimeout:  Duration(2_000_000_000), // 2s
			MaxPendingEvents:    4096,
			SocketReceiveBuffer: Size(8 << 20), // 8 MiB
		},
		Transport: TransportSection{
			Kind:           TransportVSOCK,
			MaxPayloadSize: Size(1 << 20), // 1 MiB
			WriteTimeout:   Duration(10_000_000_000),
			AckTimeout:     Duration(60_000_000_000),
			MaxUnacked:     1024,
		},
		VSOCK: VSOCKSection{CID: VMADDR_CID_HOST, Port: 9000},
		Queue: QueueSection{Capacity: 10000},
		Spool: SpoolSection{
			Enabled:      true,
			Path:         "/var/lib/sauronagent/spool",
			MaxSize:      Size(1 << 30), // 1 GiB
			SegmentSize:  Size(16 << 20),
			SyncOnWrite:  false,
			SyncInterval: Duration(1_000_000_000),
		},
		Heartbeat: HeartbeatSection{
			Interval: Duration(30_000_000_000),
			Timeout:  Duration(90_000_000_000),
		},
		Reconnect: ReconnectSection{
			InitialDelay: Duration(100_000_000),
			MaxDelay:     Duration(10_000_000_000),
			Multiplier:   2.0,
			Jitter:       0.2,
		},
		Logging: LoggingSection{Level: "info", Format: "text", Output: "stderr"},
	}
}

// Validate checks the configuration for values that cannot work.
func (c *Agent) Validate() error {
	if c.Queue.Capacity <= 0 {
		return fmt.Errorf("queue.capacity must be greater than 0")
	}
	if c.Audit.MaxPendingEvents <= 0 {
		return fmt.Errorf("audit.max_pending_events must be greater than 0")
	}
	if c.Audit.CorrelationTimeout <= 0 {
		return fmt.Errorf("audit.correlation_timeout must be greater than 0")
	}
	switch c.Transport.Kind {
	case TransportVSOCK:
		if c.VSOCK.Port == 0 {
			return fmt.Errorf("vsock.port must be set")
		}
	case TransportTCP:
		if c.Transport.TCPAddress == "" {
			return fmt.Errorf("transport.tcp_address must be set when transport.kind is tcp")
		}
	default:
		return fmt.Errorf("transport.kind must be %q or %q, got %q",
			TransportVSOCK, TransportTCP, c.Transport.Kind)
	}
	if c.Transport.MaxPayloadSize <= 0 {
		return fmt.Errorf("transport.max_payload_size must be greater than 0")
	}
	if c.Transport.MaxUnacked <= 0 {
		return fmt.Errorf("transport.max_unacked must be greater than 0")
	}
	if c.Spool.Enabled {
		if c.Spool.Path == "" {
			return fmt.Errorf("spool.path must be set when spool.enabled is true")
		}
		if !filepath.IsAbs(c.Spool.Path) {
			return fmt.Errorf("spool.path must be absolute, got %q", c.Spool.Path)
		}
		if c.Spool.MaxSize <= 0 {
			return fmt.Errorf("spool.max_size must be greater than 0")
		}
		if c.Spool.SegmentSize <= 0 {
			return fmt.Errorf("spool.segment_size must be greater than 0")
		}
		if c.Spool.SegmentSize > c.Spool.MaxSize {
			return fmt.Errorf("spool.segment_size (%s) must not exceed spool.max_size (%s)",
				c.Spool.SegmentSize, c.Spool.MaxSize)
		}
	}
	if c.Heartbeat.Interval <= 0 {
		return fmt.Errorf("heartbeat.interval must be greater than 0")
	}
	if c.Reconnect.InitialDelay <= 0 {
		return fmt.Errorf("reconnect.initial_delay must be greater than 0")
	}
	if c.Reconnect.MaxDelay < c.Reconnect.InitialDelay {
		return fmt.Errorf("reconnect.max_delay must be at least reconnect.initial_delay")
	}
	if c.Reconnect.Multiplier < 1 {
		return fmt.Errorf("reconnect.multiplier must be at least 1")
	}
	if c.Reconnect.Jitter < 0 || c.Reconnect.Jitter >= 1 {
		return fmt.Errorf("reconnect.jitter must be in [0,1)")
	}
	return validateLogging(c.Logging)
}
