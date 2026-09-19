package event

// Normalized event categories.
//
// Raw Linux audit record types are mapped onto these names so that SIEM
// queries do not have to encode knowledge of every kernel record type. The
// numeric record type and the raw text are still carried on the event, so
// mapping never loses information.
const (
	// Process lifecycle.
	TypeProcessExec = "process.exec"
	TypeProcessExit = "process.exit"

	// Filesystem activity.
	TypeFileAccess = "file.access"
	TypeFileCreate = "file.create"
	TypeFileModify = "file.modify"
	TypeFileDelete = "file.delete"

	// Authentication and sessions.
	TypeAuthLogin   = "authentication.login"
	TypeAuthLogout  = "authentication.logout"
	TypeAuthFailure = "authentication.failure"

	// Commands run through a privilege helper such as sudo.
	TypeUserCommand = "user.command"

	// Changes to credentials or privileges.
	TypePrivilegeChange = "privilege.change"

	// The audit subsystem's own configuration. Never routine.
	TypeAuditConfiguration = "audit.configuration"

	// Netfilter / firewall configuration activity.
	TypeFirewallConfiguration = "firewall.configuration"

	// SELinux access-vector denials.
	TypeSELinuxDenial = "selinux.denial"

	// Anything security-relevant that does not fit a more specific category.
	TypeSystemSecurity = "system.security"
)

// Internal agent and host events.
//
// SauronAgent reports its own failures as events rather than only to a log
// file. A collector that never learns an agent dropped records cannot tell a
// quiet guest from a broken one, so every loss of fidelity becomes visible
// telemetry in the same stream as the audit data.
const (
	TypeParseFailure        = "sauron.parse.failure"
	TypeQueueOverflow       = "sauron.queue.overflow"
	TypeSpoolFull           = "sauron.spool.full"
	TypeSpoolError          = "sauron.spool.error"
	TypeTransportDisconnect = "sauron.transport.disconnected"
	TypeTransportConnected  = "sauron.transport.connected"
	TypeAgentStarted        = "sauron.agent.started"
	TypeAgentStopping       = "sauron.agent.stopping"
	TypeAuditKernelLost     = "sauron.audit.lost"
	TypeStreamLost          = "sauron.stream.lost"
	TypeStreamResumed       = "sauron.stream.resumed"
	TypeProtocolViolation   = "sauron.protocol.violation"
)

// IsInternal reports whether typ is an agent- or host-generated event about
// SauronAgent itself rather than an observation about the guest.
func IsInternal(typ string) bool {
	return len(typ) > 7 && typ[:7] == "sauron."
}
