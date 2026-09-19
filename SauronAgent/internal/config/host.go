package config

import (
	"fmt"
	"io"
	"os"

	"errors"
	"gopkg.in/yaml.v3"
)

// VMADDR_CID_ANY is the wildcard CID a listener binds to in order to accept
// connections from every guest.
const VMADDR_CID_ANY uint32 = 0xFFFFFFFF

// Host is the hypervisor-side collector configuration.
type Host struct {
	Host    HostSection    `yaml:"host"`
	Listen  ListenSection  `yaml:"listen"`
	VMs     []VMMapping    `yaml:"vms"`
	Output  OutputSection  `yaml:"output"`
	Monitor MonitorSection `yaml:"monitor"`
	Limits  LimitsSection  `yaml:"limits"`
	Logging LoggingSection `yaml:"logging"`
}

// HostSection identifies the hypervisor itself. Unlike anything the guest
// sends, this is trusted metadata: it is configured on the host.
type HostSection struct {
	Name string `yaml:"name"`
}

// ListenSection configures the collector's listening socket.
type ListenSection struct {
	Kind TransportKind `yaml:"kind"`

	// CID is the local context ID to bind. The default accepts any guest.
	CID uint32 `yaml:"cid"`
	// Port is the VSOCK port to listen on.
	Port uint32 `yaml:"port"`

	// TCPAddress is used when Kind is "tcp". Testing only.
	TCPAddress string `yaml:"tcp_address"`
}

// VMMapping is the trusted CID-to-identity mapping.
//
// The guest's own claims about who it is are never used for this. A
// compromised guest can put any hostname in its HELLO, but it cannot choose
// the CID its connection arrives on -- that is assigned by the hypervisor.
type VMMapping struct {
	CID uint32 `yaml:"cid"`

	// Name is the authoritative VM name attached to every event from this CID.
	Name string `yaml:"name"`

	// UUID, Environment, SecurityDomain and VLAN are optional asset metadata
	// attached to events as trusted host-side enrichment.
	UUID           string            `yaml:"uuid"`
	Environment    string            `yaml:"environment"`
	SecurityDomain string            `yaml:"security_domain"`
	VLAN           string            `yaml:"vlan"`
	Labels         map[string]string `yaml:"labels"`

	// Expected marks a VM whose audit stream must always be present. A
	// missing stream from an expected VM is itself reported as a security
	// event, because silencing the agent is the first thing an intruder does.
	Expected bool `yaml:"expected"`
}

// OutputSection configures where received events are written.
type OutputSection struct {
	Stdout StdoutOutput `yaml:"stdout"`
	File   FileOutput   `yaml:"file"`
	Syslog SyslogOutput `yaml:"syslog"`
}

// StdoutOutput writes newline-delimited JSON to standard output.
type StdoutOutput struct {
	Enabled bool `yaml:"enabled"`
	Pretty  bool `yaml:"pretty"`
}

// FileOutput writes newline-delimited JSON to a file, with size-based rotation.
type FileOutput struct {
	Enabled bool   `yaml:"enabled"`
	Path    string `yaml:"path"`

	// MaxSize rolls the file once it grows past this size. Zero disables
	// rotation, leaving it to an external tool such as logrotate.
	MaxSize Size `yaml:"max_size"`
	// MaxFiles is how many rotated files to keep.
	MaxFiles int `yaml:"max_files"`

	// SyncOnWrite fsyncs after every event.
	SyncOnWrite bool `yaml:"sync_on_write"`
}

// SyslogOutput forwards events to a syslog daemon such as rsyslog.
type SyslogOutput struct {
	Enabled bool `yaml:"enabled"`

	// Network is "" for the local syslog socket, or "tcp"/"udp"/"unix".
	Network string `yaml:"network"`
	// Address is the syslog endpoint when Network is set.
	Address string `yaml:"address"`

	Tag      string `yaml:"tag"`
	Facility string `yaml:"facility"`
}

// MonitorSection configures stream-health tracking.
type MonitorSection struct {
	Enabled bool `yaml:"enabled"`

	// Timeout is how long a VM marked Expected may go without a heartbeat or
	// event before the host reports sauron.stream.lost.
	Timeout Duration `yaml:"timeout"`

	// CheckInterval is how often stream health is evaluated.
	CheckInterval Duration `yaml:"check_interval"`
}

// LimitsSection bounds what a connected guest may consume. A guest is
// untrusted, so every one of these is a defence against a hostile or
// malfunctioning agent rather than a tuning knob.
type LimitsSection struct {
	// MaxPayloadSize bounds a single protocol frame.
	MaxPayloadSize Size `yaml:"max_payload_size"`

	// MaxConnectionsPerCID stops one guest from exhausting host resources by
	// opening connections in a loop.
	MaxConnectionsPerCID int `yaml:"max_connections_per_cid"`

	// MaxConnections bounds total concurrent guest connections.
	MaxConnections int `yaml:"max_connections"`

	// HandshakeTimeout bounds how long a connection may stay silent before
	// completing the HELLO exchange.
	HandshakeTimeout Duration `yaml:"handshake_timeout"`

	// IdleTimeout closes a connection that sends nothing at all, including
	// heartbeats, for this long.
	IdleTimeout Duration `yaml:"idle_timeout"`

	// AckInterval is how often, in events, the host acknowledges. Zero
	// acknowledges every event.
	AckInterval int `yaml:"ack_interval"`

	// AckMaxDelay forces an acknowledgement even if AckInterval events have
	// not yet arrived, so a slow trickle of events is still released from the
	// guest's spool promptly.
	AckMaxDelay Duration `yaml:"ack_max_delay"`

	// DedupWindow is how many recent sequence numbers per (CID, boot ID) are
	// remembered for duplicate suppression after a reconnect.
	DedupWindow int `yaml:"dedup_window"`

	// AllowUnknownCIDs accepts guests with no entry in vms. They are recorded
	// with a synthetic name so that an unexpected guest is visible rather than
	// silently dropped.
	AllowUnknownCIDs bool `yaml:"allow_unknown_cids"`
}

// DefaultHost returns the built-in collector configuration.
func DefaultHost() Host {
	return Host{
		Host:   HostSection{Name: hostnameOrUnknown()},
		Listen: ListenSection{Kind: TransportVSOCK, CID: VMADDR_CID_ANY, Port: 9000},
		Output: OutputSection{
			Stdout: StdoutOutput{Enabled: true},
			File:   FileOutput{Enabled: false, Path: "/var/log/sauronhost/events.json", MaxSize: Size(256 << 20), MaxFiles: 8},
			Syslog: SyslogOutput{Enabled: false, Tag: "sauronhost", Facility: "authpriv"},
		},
		Monitor: MonitorSection{
			Enabled:       true,
			Timeout:       Duration(90_000_000_000),
			CheckInterval: Duration(15_000_000_000),
		},
		Limits: LimitsSection{
			MaxPayloadSize:       Size(1 << 20),
			MaxConnectionsPerCID: 4,
			MaxConnections:       1024,
			HandshakeTimeout:     Duration(10_000_000_000),
			IdleTimeout:          Duration(300_000_000_000),
			AckInterval:          64,
			AckMaxDelay:          Duration(2_000_000_000),
			DedupWindow:          65536,
			AllowUnknownCIDs:     true,
		},
		Logging: LoggingSection{Level: "info", Format: "text", Output: "stderr"},
	}
}

func hostnameOrUnknown() string {
	if h, err := os.Hostname(); err == nil && h != "" {
		return h
	}
	return "unknown"
}

// LoadHost reads a collector configuration file layered over the defaults.
func LoadHost(path string) (Host, error) {
	cfg := DefaultHost()
	if path == "" {
		return cfg, cfg.Validate()
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, fmt.Errorf("reading host config %s: %w", path, err)
	}
	dec := yaml.NewDecoder(strictReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil && !errors.Is(err, io.EOF) {
		return cfg, fmt.Errorf("parsing host config %s: %w", path, err)
	}
	if err := cfg.Validate(); err != nil {
		return cfg, fmt.Errorf("invalid host config %s: %w", path, err)
	}
	return cfg, nil
}

// Validate checks the collector configuration.
func (c *Host) Validate() error {
	switch c.Listen.Kind {
	case TransportVSOCK:
		if c.Listen.Port == 0 {
			return fmt.Errorf("listen.port must be set")
		}
	case TransportTCP:
		if c.Listen.TCPAddress == "" {
			return fmt.Errorf("listen.tcp_address must be set when listen.kind is tcp")
		}
	default:
		return fmt.Errorf("listen.kind must be %q or %q, got %q",
			TransportVSOCK, TransportTCP, c.Listen.Kind)
	}
	seen := make(map[uint32]string, len(c.VMs))
	for i, vm := range c.VMs {
		if vm.Name == "" {
			return fmt.Errorf("vms[%d]: name must be set", i)
		}
		if prev, dup := seen[vm.CID]; dup {
			return fmt.Errorf("vms[%d]: CID %d is already mapped to %q; a CID identifies exactly one VM",
				i, vm.CID, prev)
		}
		seen[vm.CID] = vm.Name
	}
	if c.Limits.MaxPayloadSize <= 0 {
		return fmt.Errorf("limits.max_payload_size must be greater than 0")
	}
	if c.Limits.MaxConnections <= 0 {
		return fmt.Errorf("limits.max_connections must be greater than 0")
	}
	if c.Limits.MaxConnectionsPerCID <= 0 {
		return fmt.Errorf("limits.max_connections_per_cid must be greater than 0")
	}
	if c.Limits.DedupWindow < 0 {
		return fmt.Errorf("limits.dedup_window must not be negative")
	}
	if c.Limits.AckInterval < 0 {
		return fmt.Errorf("limits.ack_interval must not be negative")
	}
	if c.Output.File.Enabled && c.Output.File.Path == "" {
		return fmt.Errorf("output.file.path must be set when output.file.enabled is true")
	}
	if c.Monitor.Enabled {
		if c.Monitor.Timeout <= 0 {
			return fmt.Errorf("monitor.timeout must be greater than 0")
		}
		if c.Monitor.CheckInterval <= 0 {
			return fmt.Errorf("monitor.check_interval must be greater than 0")
		}
	}
	return validateLogging(c.Logging)
}

// LookupVM returns the trusted mapping for a CID.
func (c *Host) LookupVM(cid uint32) (VMMapping, bool) {
	for _, vm := range c.VMs {
		if vm.CID == cid {
			return vm, true
		}
	}
	return VMMapping{}, false
}
