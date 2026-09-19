// Package e2e holds SauronAgent's end-to-end tests: a real guest agent and a
// real host collector, wired to each other in one process, driven with real
// kernel audit record text.
//
// The package has no code of its own. Everything lives in the test files, and
// this file exists to say what the harness does and -- more usefully -- what
// it does not.
//
// # What runs
//
// Each test builds a host.Server with a recording output.Sink on a TCP
// listener (config.TransportTCP on 127.0.0.1:0) and an agent.Agent dialling
// it, with audit records injected through agent.Options.Source. Between those
// two ends everything is the shipped code:
//
//	audit.ParseLine -> correlator -> normalizer -> sequencer -> queue -> spool
//	  -> SAUR codec -> TCP -> session -> dedup -> enrichment -> sink
//
// So these tests cover the record parser on real auditd record syntax, event
// correlation by audit event id, normalization and categorisation, raw record
// preservation, sequence assignment and its continuity across a restart, the
// disk spool and its replay, the wire protocol in both directions, the
// handshake, cumulative acknowledgement, at-least-once delivery with
// deduplication on (CID, boot id, sequence), the collector's rejection of a
// malformed peer, trusted host enrichment, and the shipped commands' -version
// and -check-config paths against the example configuration files.
//
// # What does not run
//
// Three parts of a deployment are absent, and no test here says anything about
// them:
//
//   - The netlink socket. Records are injected as text through
//     agent.Options.Source rather than received from NETLINK_AUDIT, so nothing
//     here exercises CAP_AUDIT_READ, the multicast subscription, SO_RCVBUF
//     sizing or the ENOBUFS path where the kernel discards records. Those are
//     covered by internal/audit's own tests against a synthetic socket.
//
//   - The VSOCK device. The transport is TCP on the loopback interface.
//     AF_VSOCK addressing, the hypervisor's CID assignment and the behaviour of
//     a virtio-vsock link are not tested; internal/transport tests the dialler
//     and listener directly, and examples/qemu-vsock.md is how the real path is
//     checked by hand.
//
//     Because the collector identifies a guest by transport.PeerCID, which
//     reads the connection's remote address, the harness gives each accepted
//     connection the *vsock.Addr the kernel would have written. That is the
//     one value these tests fake. Everything that consumes it -- the CID-to-VM
//     map, the authorisation check, the per-CID connection limits, the
//     deduplication key -- is the real implementation running on a real CID,
//     but a test that passes here does not prove the CID would have been right
//     on a hypervisor.
//
//   - A fleet. One collector serves at most two simulated VMs on a loopback
//     interface. Nothing here says anything about many guests at once, about
//     the collector under load, or about a real hypervisor's scheduling.
//
// Two smaller gaps are worth naming. The stream monitor is switched off in the
// harness, so sauron.stream.lost is exercised in internal/host rather than
// here; and the tests assert on what the collector wrote to its sink, not on
// what rsyslog, a file or a SIEM did with it afterwards.
package e2e
