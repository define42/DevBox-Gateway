// Package output delivers enriched events from the host collector onwards to
// wherever an installation keeps its security logs.
package output

import (
	"context"
	"time"

	"github.com/define42/SauronAgent/internal/event"
)

// Source is the host's description of where an event came from.
//
// The distinction between the trusted fields here and the Reported block is
// the point of the type. CID, VM, UUID and the asset metadata come from the
// hypervisor's own configuration and cannot be influenced by the guest.
// Everything under Reported was supplied by the guest agent and is worth
// recording but must never be used to decide what a VM is.
type Source struct {
	// CID is the VSOCK context ID the connection arrived on. Authoritative.
	CID uint32 `json:"cid"`

	// VM is the configured name for CID. Authoritative.
	VM string `json:"vm"`

	// Host is the hypervisor's name. Authoritative.
	Host string `json:"host,omitempty"`

	UUID           string            `json:"uuid,omitempty"`
	Environment    string            `json:"environment,omitempty"`
	SecurityDomain string            `json:"security_domain,omitempty"`
	VLAN           string            `json:"vlan,omitempty"`
	Labels         map[string]string `json:"labels,omitempty"`

	// Known is false when no configuration entry exists for CID. Such a guest
	// is recorded rather than dropped, because an unexpected VM connecting to
	// the collector is itself something an analyst should see.
	Known bool `json:"known"`

	// Reported is what the guest claimed about itself. Untrusted.
	Reported *Reported `json:"reported,omitempty"`
}

// Reported holds the guest's own claims from its HELLO message. A disagreement
// between Reported.Hostname and Source.VM is worth alerting on.
type Reported struct {
	Hostname     string `json:"hostname,omitempty"`
	MachineID    string `json:"machine_id,omitempty"`
	BootID       string `json:"boot_id,omitempty"`
	Kernel       string `json:"kernel,omitempty"`
	AgentVersion string `json:"agent_version,omitempty"`
}

// Envelope is one event as the collector emits it: the guest's event plus the
// host's trusted view of where it came from.
type Envelope struct {
	// ReceivedAt is the host's clock when the event arrived, which is
	// independent of the guest's possibly wrong or manipulated clock.
	ReceivedAt time.Time `json:"received_at"`

	Source Source `json:"source"`

	Event *event.Event `json:"event"`
}

// Sink is a destination for enriched events.
//
// Write must not block indefinitely: the collector calls it on the path that
// decides whether an event can be acknowledged, and an event is only
// acknowledged to the guest once every sink has durably accepted it.
type Sink interface {
	// Write delivers one envelope. Returning an error means the event was not
	// accepted and must not be acknowledged to the guest.
	Write(ctx context.Context, env *Envelope) error

	// Flush makes previously written events durable.
	Flush(ctx context.Context) error

	// Close flushes and releases the sink's resources.
	Close() error

	// Name identifies the sink in logs and metrics.
	Name() string
}
