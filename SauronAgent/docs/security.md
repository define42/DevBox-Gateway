# Security model

This document states what SauronAgent protects against and, at least as
importantly, what it does not. It is the material from DESIGN.md sections 27-28
written out honestly: a monitoring system whose limits are not written down
gets trusted for things it cannot do.

## 1. Trust boundaries

```text
+-------------------------------------------------------------+
|  Guest VM                        UNTRUSTED as a whole        |
|                                                              |
|   kernel audit subsystem                                     |
|        |  NETLINK_AUDIT                                      |
|   sauronagent  (uid sauronagent)                              |
|     CAP_AUDIT_READ + CAP_AUDIT_CONTROL                         |
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

**Loss is visible.** Every place an event can be lost is counted and reported
as an event in the same stream: `sauron.queue.overflow` and
`sauron.spool.full` name the exact range of missing sequence numbers,
`sauron.audit.lost` reports records the kernel dropped before the agent saw
them, `sauron.parse.failure` carries the text that could not be parsed. A gap
in the sequence numbers with no such event next to it is a finding, not a
tuning problem.

**The host's attack surface is small.** The collector has no TCP listener, no
IP address it reaches, no capabilities, and no writable filesystem outside its
log directory. A guest can reach exactly one thing on the hypervisor: a vsock
port that speaks a 20-byte-header protocol which is bounded, fuzz-tested, and
allocates nothing from a length field it has not validated.

**Auditing keeps working alongside auditd.** The agent is a consumer on the
audit multicast group. It never registers as the audit daemon, so deploying it
does not displace an existing `auditd`. By default it enables auditing and
ensures execution rules at startup, preserving unrelated rules. Set
`audit.manage_rules: false` when the complete policy is managed externally.

## 3. What the design does not protect against

**A fully compromised guest kernel can stop the truth at its source.** With
root and kernel control in the guest an attacker can:

* disable auditing (`auditctl -e 0`), delete audit rules, or set the audit
  backlog so small that records are dropped;
* kill, `SIGSTOP`, `ptrace`, patch or replace the agent process and its binary;
* start the agent on a configuration of their own (a unit drop-in adding
  `-config`), for example to exclude the record types their next action would
  produce;
* delete or rewrite `/var/lib/sauronagent/spool` -- everything not yet
  acknowledged by the host is still inside the guest and is still theirs;
* unload `vmw_vsock_virtio_transport` or otherwise break the path to the host;
* inject fabricated user-space audit records (`AUDIT_USER_*` needs only
  `CAP_AUDIT_WRITE`), producing events that look genuine and carry whatever
  the attacker chose;
* run a kernel module or rootkit that suppresses specific records before the
  audit subsystem ever emits them.

None of that is defended against, and no agent running inside the guest could
defend against it. What the design offers is that **each of those actions
either leaves the already-delivered record untouched or makes the stream go
missing, and the host notices a missing stream.** That is a detective control
with a bounded blind spot, not a preventive one.

**Event contents are guest-controlled data.** There is no signature on an
event and no cryptography in the protocol. An attacker with root in a guest can
make the agent send, or can send directly, any event they like, and it will
arrive correctly attributed to that guest's CID. Attribution is trustworthy;
content is not. A SIEM rule must never treat `uid`, `exe` or `command` from a
guest as authenticated -- only as what that guest reported.

**The window before acknowledgement is lost on a guest compromise.** Events in
the queue or spool that the host has not yet acknowledged can be destroyed by
an attacker who reaches root in that moment. `spool.sync_on_write: true` and a
short `limits.ack_max_delay` narrow the window; nothing closes it.

**There is no confidentiality boundary on the wire.** vsock traffic is carried
by the host kernel. Anyone with root on the hypervisor can read it -- but they
can also read guest memory, so this is not a meaningful additional exposure.
It does mean the hypervisor must be treated as a high-value asset: it holds
every guest's audit trail.

**The agent is not a boundary against the hypervisor.** SauronAgent tells you
what happened inside VMs. It says nothing about the host they run on, and an
attacker who owns the hypervisor owns the collector too.

**Absence of events is not proof of absence of activity.** Delivery is
at-least-once with explicit, reported gaps. If a burst overflowed the queue,
some events did not happen to be recorded; the overflow event says exactly
which sequence numbers those were, and that is the whole of the guarantee.

**Guest timestamps can be wrong.** Event timestamps come from the guest kernel.
The collector stamps `received_at` from its own clock, and `PONG` carries the
host's clock so drift is detectable. Correlation across VMs should use
`received_at`.

## 4. Capability model

| Component | Runs as | Capabilities | Why |
|---|---|---|---|
| `sauronagent` | `sauronagent` (system user) | `CAP_AUDIT_READ` and `CAP_AUDIT_CONTROL`, ambient and bounded | joining the audit multicast group and configuring execution auditing |
| `sauronhost` | `sauronhost` (system user) | none; empty bounding set | it parses hostile input and needs no privilege to do so |

`CAP_AUDIT_READ` permits receiving audit events. `CAP_AUDIT_CONTROL` permits
enabling auditing and installing execution rules without a separate audit
service. Both capabilities remain available throughout the process lifetime.
A compromise of the agent therefore exposes audit contents and also grants
the ability to change rules or disable auditing when policy is mutable.

For externally managed policy, `audit.manage_rules: false` disables automatic
setup. Also override `AmbientCapabilities` and `CapabilityBoundingSet` to
`CAP_AUDIT_READ` to remove control privilege; changing the configuration alone
does not remove a capability. See the deployment guide for the drop-in.

The service does not get:

* `CAP_AUDIT_WRITE` -- it cannot inject user-space audit records.
* `CAP_NET_ADMIN` -- which means `SO_RCVBUFFORCE` on the netlink socket falls
  back to `SO_RCVBUF`, clamped by `net.core.rmem_max`. That is a deliberate
  trade: see `audit.socket_receive_buffer` in the deployment guide.
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

Configuration is parsed strictly: an unknown YAML key is a startup failure, not
a warning. A typo in `preserve_raw` must not silently disable forensic
evidence.

## 6. Hardening in the unit files

Both units are in `packaging/systemd/` and every directive there is commented
with why it is present. The security-relevant ones:

| Directive | Effect |
|---|---|
| `User=` / `Group=` | neither component ever runs as root |
| `CapabilityBoundingSet=` | a ceiling on what a successful exploit can acquire: audit read and control for the agent, none for the collector |
| `NoNewPrivileges=true` | no path to more privilege through setuid or file capabilities |
| `ProtectSystem=strict`, `ProtectHome=true` | the filesystem is read-only except the one state or log directory |
| `StateDirectory=` / `LogsDirectory=` | the only writable path, owned by the service user, mode 0700 / 0750 |
| `PrivateDevices=true` | no device nodes: the vsock socket is a socket, not `/dev/vsock` |
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

* **Keep `vms:` accurate and mark production VMs `expected: true`.** The
  stream-loss alert is the design's only detection for an agent killed inside a
  compromised guest.
* **Alert on the internal events.** `sauron.stream.lost`,
  `sauron.queue.overflow`, `sauron.spool.full` and `sauron.audit.lost` are
  security events, not operational noise.
* **Alert on identity disagreement.** `source.reported.hostname` that does not
  match `source.vm`, or a `boot_id` that changes without a reboot you know
  about, is worth a look.
* **Think before turning `allow_unknown_cids` off.** `true` records an
  unmapped guest under a synthetic name with `known: false`, which is visible.
  `false` refuses it -- and then the only trace of that VM is a rejection
  counter.
* **Treat the collector's output as sensitive.** It contains the command lines
  of every audited process on every VM, which routinely include things that
  should never have been typed on a command line. `/var/log/sauronhost` is 0750
  for that reason; give a log shipper group membership, not write access.
* **Keep `preserve_raw: true` unless you have measured that you cannot
  afford it.** The normalized fields are an interpretation; the raw records are
  the evidence.
