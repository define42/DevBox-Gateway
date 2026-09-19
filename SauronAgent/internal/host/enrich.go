package host

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/define42/SauronAgent/internal/config"
	"github.com/define42/SauronAgent/internal/event"
	"github.com/define42/SauronAgent/internal/output"
	"github.com/define42/SauronAgent/internal/protocol"
)

// cidUnidentified is the CID recorded for a connection whose identity is not
// hypervisor-backed, which in practice means the TCP development transport.
//
// It is VMADDR_CID_ANY: a wildcard that no guest can ever be assigned, so it
// cannot collide with a real VM. Recording 0 instead would be worse than
// useless -- 0 is VMADDR_CID_HYPERVISOR, a real address -- and would quietly
// present an unauthenticated peer as an identified one.
const cidUnidentified uint32 = config.VMADDR_CID_ANY

// peer is the collector's view of who is on the other end of a connection.
//
// vsock is the load-bearing field. It records whether cid came from the
// hypervisor, which is the only identity claim in the system a compromised
// guest cannot forge. When it is false there is no VM identity at all, only a
// network address the peer chose to connect from.
type peer struct {
	cid   uint32
	vsock bool
	addr  string
}

// peerOf resolves the peer identity of an accepted connection.
//
// It is called before a single byte is read, because the answer must not
// depend on anything the guest sends.
func (s *Server) peerOf(conn net.Conn) peer {
	p := peer{cid: cidUnidentified}
	if conn != nil {
		if a := conn.RemoteAddr(); a != nil {
			p.addr = a.String()
		}
	}
	if cid, ok := s.peerCID(conn); ok {
		p.cid, p.vsock = cid, true
	}
	return p
}

// bucket is the key connection limits and deduplication are accounted against.
//
// For a VSOCK guest that is the CID, which the guest cannot change. For an
// unidentified peer it is the network host it dialled from, which the peer can
// change -- that is exactly why such a peer is not a VM identity and why the
// TCP transport is documented as development-only.
func (p peer) bucket() string {
	if p.vsock {
		return fmt.Sprintf("cid:%d", p.cid)
	}
	return "peer:" + hostPart(p.addr)
}

// logCID renders the CID for logs, keeping "no hypervisor identity" distinct
// from any number a guest could be assigned.
func (p peer) logCID() any {
	if !p.vsock {
		return "none"
	}
	return p.cid
}

// hostPart strips the port from an address, so that a peer reconnecting from a
// new ephemeral port lands in the same bucket.
func hostPart(addr string) string {
	if h, _, err := net.SplitHostPort(addr); err == nil && h != "" {
		return h
	}
	if addr == "" {
		return "unknown"
	}
	return addr
}

// enricher turns a peer into the trusted half of an output.Source.
type enricher struct {
	hostName     string
	vms          map[uint32]config.VMMapping
	allowUnknown bool
}

// newEnricher indexes the configured CID-to-VM mapping.
func newEnricher(cfg config.Host) *enricher {
	vms := make(map[uint32]config.VMMapping, len(cfg.VMs))
	for _, vm := range cfg.VMs {
		vms[vm.CID] = vm
	}
	return &enricher{
		hostName:     cfg.Host.Name,
		vms:          vms,
		allowUnknown: cfg.Limits.AllowUnknownCIDs,
	}
}

// authorized reports whether a peer may connect at all.
//
// An unmapped CID is accepted when limits.allow_unknown_cids is set, because an
// unexpected VM connecting to the collector is something an analyst must see
// rather than something to drop. When it is not set the connection is refused
// and counted, which is a deliberate choice to have no record of that guest at
// all.
func (e *enricher) authorized(p peer) bool {
	if !p.vsock {
		// No hypervisor-backed identity. Such a peer is treated exactly like an
		// unmapped CID: it cannot be attributed to a VM, so it is only accepted
		// where unknown guests are accepted.
		return e.allowUnknown
	}
	if _, ok := e.vms[p.cid]; ok {
		return true
	}
	return e.allowUnknown
}

// source builds the trusted half of an event's provenance.
//
// Nothing here comes from the guest. The CID is the hypervisor's, the VM name
// and asset metadata are the operator's, and the hypervisor name is this host's
// own configuration. The guest's claims are attached separately as
// Source.Reported and never overwrite any of it -- a guest reporting a hostname
// that disagrees with its CID mapping is a signal, not a correction.
func (e *enricher) source(p peer) output.Source {
	src := output.Source{CID: p.cid, Host: e.hostName}

	if !p.vsock {
		// Deliberately does not consult the CID mapping: looking one up for a
		// peer with no hypervisor-backed identity is how an unauthenticated
		// connection would end up wearing a real VM's name.
		src.VM = "unidentified-peer-" + hostPart(p.addr)
		src.Known = false
		return src
	}

	vm, ok := e.vms[p.cid]
	if !ok {
		src.VM = fmt.Sprintf("unknown-cid-%d", p.cid)
		src.Known = false
		return src
	}

	src.VM = vm.Name
	src.UUID = vm.UUID
	src.Environment = vm.Environment
	src.SecurityDomain = vm.SecurityDomain
	src.VLAN = vm.VLAN
	src.Labels = vm.Labels
	src.Known = true
	return src
}

// reportedFrom records the guest's own claims. Every field is untrusted; they
// are kept because host-side logs are unreadable without them and because a
// disagreement with the trusted mapping is worth alerting on.
func reportedFrom(hello *protocol.Hello) *output.Reported {
	if hello == nil {
		return nil
	}
	return &output.Reported{
		Hostname:     hello.Hostname,
		MachineID:    hello.MachineID,
		BootID:       hello.BootID,
		Kernel:       hello.Kernel,
		AgentVersion: hello.AgentVersion,
	}
}

// envelopeFor wraps an event in the collector's view of where it came from.
//
// ReceivedAt is the host's clock. The guest's own timestamp stays on the event
// where an analyst can compare the two, but the collector never adopts it: a
// compromised guest can set its clock to anything, and correlation across VMs
// has to rest on a clock the guest cannot move.
func envelopeFor(now time.Time, src output.Source, ev *event.Event) *output.Envelope {
	return &output.Envelope{
		ReceivedAt: now.UTC(),
		Source:     src,
		Event:      ev,
	}
}

// reporter publishes host-generated internal events.
//
// They go to the sink so they land in the same stream as the audit data an
// analyst is already watching, and to Options.OnInternalEvent so a supervising
// process can react without parsing its own output.
type reporter struct {
	sink    output.Sink
	onEvent func(*output.Envelope)
	log     *slog.Logger
	now     func() time.Time
}

// publish delivers one internal event.
//
// A failure to write an internal event is logged and dropped rather than
// reported as another internal event: the most likely reason for it is that the
// sink itself is broken, and reporting the failure of a report is how a
// collector turns one broken output into an infinite loop.
func (r *reporter) publish(ctx context.Context, src output.Source, ev *event.Event) *output.Envelope {
	env := envelopeFor(r.now(), src, ev)
	if err := r.sink.Write(ctx, env); err != nil {
		r.log.Error("writing internal event failed",
			"type", ev.Type, "vm", src.VM, "cid", src.CID, "error", err)
	}
	if r.onEvent != nil {
		r.onEvent(env)
	}
	return env
}
