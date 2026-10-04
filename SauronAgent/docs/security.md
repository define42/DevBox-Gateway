# Security model

This document describes the standalone agent and collector, their trust
boundaries, and their limits. The embedded DevBox Gateway collector uses the
gateway's configuration and process permissions; the standalone collector's
systemd sandbox does not apply to that process.

## 1. Trust boundaries

```text
+-------------------------------------------------------------+
|  Guest VM                        UNTRUSTED as a whole        |
|                                                              |
|   kernel audit subsystem                                     |
|        |  NETLINK_AUDIT                                      |
|   sauronagent  (uid sauronagent)                              |
|     CAP_AUDIT_READ + CAP_AUDIT_CONTROL + CAP_DAC_READ_SEARCH   |
|        |                                                     |
|   /var/lib/sauronagent/spool  (0700, still inside the guest) |
+--------|-----------------------------------------------------+
         |  virtio-vsock -- the guest cannot choose its CID
+--------v-----------------------------------------------------+
|  Hypervisor                      TRUSTED                     |
|                                                              |
|   sauronhost  (uid sauronhost, no capabilities)              |
|        |                                                     |
|   /var/log/sauronhost, syslog, SIEM   <-- out of the guest's |
|                                           reach entirely     |
+--------------------------------------------------------------+
```

Everything above the vsock line is in the blast radius of a guest compromise.
Everything below it is not.

## 2. What the design does protect

**Delivered records cannot be altered.** Once an event has crossed the vsock
boundary and been written by the collector, nothing inside the guest can change
it, redact it, or delete it. An attacker who gains root at 12:00 cannot rewrite
what the agent sent at 11:59. This is the core property, and it is the reason
the collector runs on the hypervisor rather than inside the VM.

**A silenced stream is itself an event.** An intruder's first move is to stop
the telemetry. The collector tracks every VM marked `expected: true` and emits
`sauron.stream.lost` when one goes quiet for longer than `monitor.timeout`
(default 90s, against a 30s heartbeat). Killing the agent, unloading the vsock
module, blocking the device, or crashing the guest all look the same from the
host, and all of them are reported. **This alert is only as good as your
`vms:` list**: a VM that is not marked expected can go silent forever without a
word.

**Identity cannot be forged.** The collector attributes every event to the CID
the connection arrived on. The hypervisor assigns that CID and the kernel
writes it into the connection's address. A guest can lie about its hostname,
machine-id and boot-id -- and those claims are recorded, under
`source.reported`, precisely so that a disagreement with the CID mapping can
be alerted on -- but it cannot connect from a CID that is not its own.

**Detected loss is reported.** The agent reports known pipeline losses in
the event stream: `sauron.queue.overflow` and
`sauron.spool.full` name the exact range of missing sequence numbers,
`sauron.audit.lost` reports records the kernel dropped before the agent saw
them, `sauron.parse.failure` carries the text that could not be parsed. A gap
in the sequence numbers with no such event next to it is a finding, not a
tuning problem.

**The standalone service restricts collector access.** The shipped unit uses
a VSOCK listener, an empty capability bounding set, and a mostly read-only
filesystem with a writable log directory and private temporary directories.
Protocol decoding validates the 20-byte header and payload size before
allocating a payload buffer. Other host services remain outside this
collector's security boundary.

**Auditing keeps working alongside auditd.** The agent is a consumer on the
audit multicast group. It never registers as the audit daemon, so deploying it
does not displace an existing `auditd`. At startup it enables auditing and
installs its built-in execution, access-rights, privilege, configuration,
persistence, kernel, network-configuration, time, and mount rules, preserving
unrelated rules. Identity/credential watches remain part of the baseline, and
existing local users' `.ssh` directories are discovered at startup. That
baseline is compiled into the agent and cannot be disabled with a configuration
file. See the [full policy](deployment.md#guest-audit-rules) for exact paths,
keys, overlap precedence, and startup discovery limits.

## 3. What the design does not protect against

**A fully compromised guest kernel can stop the truth at its source.** With
root and kernel control in the guest an attacker can:

* disable auditing (`auditctl -e 0`), delete audit rules, or set the audit
  backlog so small that records are dropped;
* kill, `SIGSTOP`, or `ptrace` the agent process;
* patch or replace the agent binary, or change the service command, to exclude
  the record types their next action would produce;
* delete or rewrite `/var/lib/sauronagent/spool` -- everything not yet
  acknowledged by the host is still inside the guest and is still theirs;
* unload `vmw_vsock_virtio_transport` or otherwise break the path to the host;
* inject fabricated user-space audit records (`AUDIT_USER_*` needs only
  `CAP_AUDIT_WRITE`), producing events that look genuine and carry whatever
  the attacker chose;
* run a kernel module or rootkit that suppresses specific records before the
  audit subsystem ever emits them.

Host storage keeps already-delivered records outside the guest's direct
control. Stream monitoring detects stopped delivery for expected VMs, including
agents that never connect. Standalone SauronHost uses its static expected list;
DevBox Gateway refreshes expectations from running managed VMs. A compromised
guest can continue heartbeats while selectively
suppressing or fabricating audit events, so those actions need not trigger a
stream-loss alert. The heartbeat's `audit_enabled` flag reflects startup
configuration and is not an independent kernel-status check.

**Event contents are guest-controlled data.** There is no signature on an
event and no cryptography in the protocol. An attacker with root in a guest can
make the agent send, or can send directly, any event they like, and it will
arrive correctly attributed to that guest's CID. Attribution is trustworthy;
content is not. A SIEM rule must never treat `uid`, `exe` or `command` from a
guest as authenticated -- only as what that guest reported.

**The window before acknowledgement is lost on a guest compromise.** Events in
the queue or spool that the host has not yet acknowledged can be destroyed by
an attacker who reaches root in that moment. A disk spool remains under guest control even when every write is synced.
Sync-on-write protects against some crash loss, not malicious deletion.
Forwarding promptly to host storage reduces this exposure; acknowledgement
batching controls how long the guest retains its copy after sink acceptance.

**There is no confidentiality boundary on the wire.** vsock traffic is carried
by the host kernel. Anyone with root on the hypervisor can read it -- but they
can also read guest memory, so this is not a meaningful additional exposure.
It does mean the hypervisor must be treated as a high-value asset: it holds
every guest's audit trail.

**The agent is not a boundary against the hypervisor.** SauronAgent tells you
what happened inside VMs. It says nothing about the host they run on, and an
attacker who owns the hypervisor owns the collector too.

**Absence of events is not proof of absence of activity.** Retained spool
events are replayed, while detected queue and spool losses produce reports.
Those reports use the same pipeline and can themselves be lost. Abrupt exits
can lose records still in memory; guest power loss can lose unsynced spool
writes. Host acknowledgements follow sink acceptance, which does not guarantee
durable storage with the default outputs. Collector deduplication state is
in memory, so restarts and state eviction can produce duplicates.

**Guest timestamps can be wrong.** Event timestamps come from the guest kernel.
The collector stamps `received_at` from its own clock, and `PONG` carries the
host's clock so drift is detectable. Correlation across VMs should use
`received_at`.

## 4. Capability model

| Component | Runs as | Capabilities | Why |
|---|---|---|---|
| `sauronagent` | `sauronagent` (system user) | `CAP_AUDIT_READ`, `CAP_AUDIT_CONTROL`, `CAP_DAC_READ_SEARCH`, ambient and bounded | collecting audit records, configuring the managed policy, and discovering watched paths inside private directories |
| `sauronhost` | `sauronhost` (system user) | none; empty bounding set | it parses hostile input and needs no privilege to do so |

`CAP_AUDIT_READ` permits receiving audit events. `CAP_AUDIT_CONTROL` permits
enabling auditing and installing the managed policy without a separate audit
service. `CAP_DAC_READ_SEARCH` bypasses discretionary read/search permissions,
allowing discovery inside root's and users' private home directories and
restricted configuration directories. It does not grant write access, and the
agent does not read SSH keys or watched credential-file contents to create
rules. It is nevertheless broader than directory traversal: a compromised
agent can use it to read otherwise protected files visible within its service
sandbox. These capabilities remain available throughout the process lifetime.
A compromise also exposes audit contents and grants the ability to change
rules or disable auditing when policy is mutable.

The service does not get:

* `CAP_AUDIT_WRITE` -- it cannot inject user-space audit records.
* `CAP_NET_ADMIN` -- which means `SO_RCVBUFFORCE` on the netlink socket falls
  back to `SO_RCVBUF`, clamped by `net.core.rmem_max`. That is a deliberate
  trade: see the built-in receive-buffer value in the deployment guide.
* `CAP_SYS_ADMIN` -- never, for anything.

Note what `CAP_AUDIT_READ` *does* give an attacker who compromises the agent
process: a live feed of every audited command line, file path and username on
the guest, plus the spool on disk. That is sensitive material, which is why the
agent is hardened as if it were exposed -- because it is.

## 5. Untrusted input, and how it is handled

Three surfaces parse data an attacker can influence. All three are bounded, and
the two that are reachable across a trust boundary are fuzz-tested (`make
fuzz`).

| Surface | Influenced by | Protection |
|---|---|---|
| Audit record text | the guest kernel, and any process with `CAP_AUDIT_WRITE` | no allocation sized from a record field (`argc` is a hint, never a size), bounded loops over embedded key/value pairs, no recursion, no panics on malformed input |
| Protocol frames | a compromised guest, at the collector | full header validation before any payload byte is read, payload length checked against the receiver's own limit before allocation, one JSON document per frame with trailing data rejected |
| Spool segments | anyone with write access inside the guest | per-record magic to resynchronise on, CRC32C on every payload, a record-size ceiling, so a tampered or truncated spool file cannot dictate an allocation |

The guest agent accepts no configuration file; its security settings come from
the compiled `config.DefaultAgent` value. SauronHost still parses its YAML
strictly, so an unknown collector key is a startup failure rather than a
silently ignored setting.

## 6. Hardening in the unit files

Both units are in `packaging/systemd/` and every directive there is commented
with why it is present. The security-relevant ones:

| Directive | Effect |
|---|---|
| `User=` / `Group=` | neither component ever runs as root |
| `CapabilityBoundingSet=` | a ceiling on what a successful exploit can acquire: audit read/control and DAC read/search for the agent, none for the collector |
| `NoNewPrivileges=true` | no path to more privilege through setuid or file capabilities |
| `ProtectSystem=strict` | the filesystem is read-only except the state or log directory |
| `ProtectHome=read-only` (agent), `ProtectHome=true` (collector) | agent home paths remain visible for SSH-directory discovery but cannot be written; the collector's home paths are hidden |
| `StateDirectory=` / `LogsDirectory=` | persistent writable state/log paths owned by the service user, mode 0700 / 0750; `PrivateTmp` also supplies writable temporary directories |
| `PrivateDevices=true` | a private device namespace; AF_VSOCK sockets do not need access to `/dev/vsock` |
| `RestrictAddressFamilies=` | the agent may use only `AF_NETLINK`, `AF_VSOCK` and `AF_UNIX`; the collector only `AF_VSOCK` and `AF_UNIX` |
| `IPAddressDeny=any` | neither component can be turned into an IP exfiltration path |
| `SystemCallFilter=@system-service` minus `@privileged @resources` | a seccomp allow-list |
| `MemoryDenyWriteExecute=true`, `LockPersonality=true` | no writable-executable mappings, no personality tricks |
| `ProtectKernelModules/Tunables/Logs`, `RestrictNamespaces`, `RestrictSUIDSGID` | the usual escalation routes are closed |

Two directives are deliberately *absent* from the agent unit, and both would
break it silently rather than loudly:

* `PrivateUsers=` -- in a user namespace, `CAP_AUDIT_READ` is a capability over
  that namespace only. The agent would start and receive nothing.
* `ProcSubset=pid` -- it hides `/proc/sys`, and with it
  `/proc/sys/kernel/random/boot_id`, which is what scopes the sequence numbers
  the collector deduplicates on.

## 7. Operating this safely

* **Keep expected agents accurate.** Standalone SauronHost uses `vms:` entries
  marked `expected: true`; DevBox Gateway supplies running managed VMs from
  libvirt. Monitor the gateway's `/api/ready` as well as stream-loss events.
  Inventory failures, overdue agents, output failures and pending stream alerts
  can make collection unready while the HTTP listener remains alive. Stream
  liveness does not establish that a compromised guest reports every event.
  Rejected guest records remain unhealthy until a retry of the retained copy or
  matching guest replay is accepted by every output; unrelated successful
  events cannot clear them. The gateway retries copies every second with their original
  attribution, including after disconnect or identity recovery. Retention is
  bounded at 4096 records and 64 MiB of encoded data. Investigate pending records
  and overflow before restarting, because retry copies and health state are
  held in memory. See
  [output recovery](deployment.md#output-failure-recovery).
  Pending sequence gaps also fail readiness until their loss evidence reaches
  outputs or missing arrivals remove the gap. Accepting a loss report does not
  prove delivery of the missing records. Unresolved dynamic connections can
  reconnect when fresh inventory restores their identity; existing records
  and fully resolved sessions keep their pinned attribution.
  Decoded originals are protected before output waits, so concurrent loss
  reports cannot acknowledge them before storage. Loss reports wait for
  accounting capacity before another output attempt. Arrival-protection
  overflow also requires investigation and restart.
* **Alert on the internal events.** `sauron.stream.lost`,
  `sauron.queue.overflow`, `sauron.spool.full` and `sauron.audit.lost` are
  security events, not operational noise.
* **Alert on identity disagreement.** `source.reported.hostname` that does not
  match `source.vm`, or a `boot_id` that changes without a reboot you know
  about, is worth a look.
* **Think before turning `allow_unknown_cids` off.** `true` records an
  unmapped guest under a synthetic name with `known: false`, which is visible.
  `false` refuses it and attempts to publish `sauron.connection.rejected`,
  but the guest's audit stream is not collected.
* **Treat the collector's output as sensitive.** It contains the command lines
  of every audited process on every VM, which routinely include things that
  should never have been typed on a command line. `/var/log/sauronhost` is 0750
  for that reason; give a log shipper group membership, not write access.
* **Keep raw-record preservation enabled in `config.DefaultAgent`.** The
  normalized fields are an interpretation; the raw records are the evidence.
