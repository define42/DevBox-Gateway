# SauronAgent

## Linux Guest Audit and Security Telemetry Agent over Virtio-VSOCK

**SauronAgent** is a lightweight Linux security auditing component designed to run inside virtual machines.

Its primary purpose is to collect security-relevant events directly from the Linux kernel, normalize and correlate those events, and securely forward them to the virtualization host using **virtio-vsock**.

SauronAgent does not require ordinary IP networking between the VM and the host.

The primary data path is:

```text
Linux kernel
     |
     | NETLINK_AUDIT
     v
SauronAgent
     |
     | virtio-vsock
     v
QEMU/KVM host
     |
     v
Sauron host collector
     |
     +-- rsyslog
     +-- Splunk
     +-- SIEM
     +-- central audit storage
```

# 1. Objectives

* Linux audit-event collection
* process execution auditing
* user and authentication auditing
* file access/change auditing
* privilege-change auditing
* audit configuration monitoring
* Netfilter/firewall configuration auditing
* SELinux audit events
* event correlation
* normalized structured events
* guest-to-host forwarding
* operation without guest-to-host IP connectivity
* reliable buffering during temporary host outages
* low resource usage
* minimal dependencies
* a small attack surface

# 4. NETLINK_AUDIT

The primary event source is `NETLINK_AUDIT`. Linux provides `CAP_AUDIT_READ`
specifically for reading the audit stream through a multicast Netlink socket.
SauronAgent subscribes to that multicast stream without claiming the audit
daemon PID, so it can coexist with `auditd`. At startup it also enables kernel
auditing and ensures a managed baseline of process-execution rules and
identity/credential file watches through netlink when it starts. This makes
command execution and account database changes visible when SauronAgent is the
only audit service.

# 5. Linux Capabilities

The guest service holds `CAP_AUDIT_READ` for collection and `CAP_AUDIT_CONTROL`
for automatic managed-rule setup. Both remain available while it runs. The
agent's audit policy is compiled into `config.DefaultAgent`; there is no
guest-side configuration file or reduced-capability operating mode. The
collector needs no capabilities, and neither service receives `CAP_SYS_ADMIN`.

# 6. Audit Events

Initially understand at least: AUDIT_SYSCALL, AUDIT_EXECVE, AUDIT_PATH,
AUDIT_CWD, AUDIT_PROCTITLE, AUDIT_USER_AUTH, AUDIT_USER_LOGIN,
AUDIT_USER_LOGOUT, AUDIT_LOGIN, AUDIT_USER_CMD, AUDIT_AVC,
AUDIT_NETFILTER_CFG, AUDIT_CONFIG_CHANGE.

# 7. Event Correlation

A single Linux operation often produces several audit records sharing one audit
event identifier, e.g. `audit(1789752345.312:8421)` -> serial 8421. They must be
combined into one logical event:

```json
{
  "type": "process.exec",
  "audit_id": "1789752345.312:8421",
  "pid": 4821,
  "ppid": 4702,
  "uid": 0,
  "auid": 1000,
  "exe": "/usr/bin/cat",
  "command": "cat /etc/shadow",
  "cwd": "/home/user",
  "paths": ["/etc/shadow"]
}
```

# 9. Event Categories

```text
process.exec / process.exit
file.access / file.create / file.modify / file.delete
authentication.login / authentication.logout / authentication.failure
user.command
privilege.change
audit.configuration
firewall.configuration
selinux.denial
system.security
```

# 10. Preserve Raw Events

Normalization must NOT destroy the original audit information. Each normalized
event should optionally contain its original records, for forensic
investigation, troubleshooting, future parser improvements, verification
against kernel-generated data and compliance.

# 11-12. VSOCK Transport and Addressing

AF_VSOCK SOCK_STREAM, CID + port instead of IP + TCP port. Linux reserves CID 2
as VMADDR_CID_HOST. The agent connects to CID 2, port 9000. No host IP address,
guest-to-host route, DNS, gateway, management VLAN or TCP listener on the VM
network is required.

# 13. VM Identity

The VM must never be trusted to declare its own authoritative identity.
SauronHost identifies the connection from its VSOCK CID and maps CID -> VM.
The guest may still supply hostname, machine-id, boot-id, kernel version and
agent version, but those are informational rather than authoritative.

# 14. Sauron Protocol

Explicit binary message framing, JSON payload:

```text
+------------------+
| Magic "SAUR"     | 4 bytes
| Version          | 1 byte
| Type             | 1 byte
| Flags            | 2 bytes
| Sequence         | 8 bytes
| Payload length   | 4 bytes
| Payload          | N bytes
+------------------+
```

# 15-17. Messages, HELLO, Sequence Numbers

Message types: HELLO, READY, EVENT, ACK, PING, PONG, ERROR, SHUTDOWN.
Every event receives an increasing sequence number, scoped against the guest
boot identifier. boot-id + sequence gives a unique stream identity, letting the
host detect duplicates, missing events, reconnections and replayed buffered
events.

# 18-22. Reliability

The audit reader must not block indefinitely waiting for the host. Collection
and transport are separate goroutines:

```text
Audit reader -> Correlator -> Event queue -> Spool -> VSOCK sender
```

Bounded in-memory queue (10,000 events in `config.DefaultAgent`). Explicit
behavior for queue exhaustion; never silently lose events; generate
`sauron.queue.overflow` with events_dropped, first_missing_sequence,
last_missing_sequence.

Disk-backed spool at /var/lib/sauronagent/spool:
receive -> normalize -> assign sequence -> write spool -> send -> receive ACK ->
delete acknowledged data.

Delivery guarantee is at-least-once. The host deduplicates on
(source CID, boot ID, sequence).

Reconnection uses exponential backoff with a compiled maximum, e.g.
100ms, 250ms, 500ms, 1s, 2s, 5s, 10s. The agent continues reading and spooling
during the outage.

# 24-26. SauronHost

Listen for VSOCK connections; identify peer CID; map CID -> VM identity;
protocol negotiation; receive events; validate frames; acknowledge events; add
trusted host metadata; send events onward.

Host enrichment example:

```json
{
  "source": {"cid": 102, "vm": "transfer-vm-03", "host": "hypervisor-01"},
  "event": {"type": "process.exec", "uid": 1000, "exe": "/usr/bin/ssh"}
}
```

Initial outputs: JSON file, stdout, syslog.

# 27-28. Security Model and Threats

A VM can potentially become compromised; SauronAgent must not be considered a
trusted security boundary simply because it runs inside the VM. A fully
compromised guest kernel could disable auditing, interfere with or modify
SauronAgent, block VSOCK or generate false information. Therefore the host must
monitor the health of each stream: a missing audit stream is itself a security
event.

# 29. Heartbeats

Periodic PING carrying uptime, events_received, events_sent, events_spooled,
audit_enabled, so the host can detect a stopped agent, a disabled audit
subsystem, a hung guest, broken transport or a growing queue.

# 30. Audit Configuration Monitoring

High-priority events when Linux auditing itself changes: audit disabled, rules
changed, configuration changed, backlog problems, events lost. Never ordinary
informational events.

# 31. Firewall Auditing

AUDIT_NETFILTER_CFG translates to `firewall.configuration`.

# 33. Internal Architecture

```text
cmd/sauronagent, cmd/sauronhost
internal/{audit,event,protocol,transport,spool,queue,identity,config,logging}
```

# 39. Performance

Never perform slow disk/network operations inside the Netlink receive loop.
Receive, copy/parse the minimum required data, enqueue, continue.

Metrics: audit_messages_received_total, events_created_total, events_sent_total,
events_acknowledged_total, events_dropped_total, queue_depth, spool_bytes,
vsock_reconnects_total, parse_errors_total.

# 40. Failure Philosophy

Failure must be visible. Never silently discard an event. Generate
`sauron.parse.failure`, `sauron.queue.overflow`, `sauron.spool.full`,
`sauron.transport.disconnected`. The host generates an event when a VM's audit
stream disappears.

# 41. Initial Version

SauronAgent v1: NETLINK_AUDIT receiver, audit record parser, event-ID
correlation, normalized JSON event model, raw record preservation, AF_VSOCK
SOCK_STREAM client, SAUR framing protocol, sequence numbers, HELLO/READY,
EVENT/ACK, memory queue, reconnection, systemd service.

SauronHost v1: AF_VSOCK listener, CID identification, protocol parser, event
validation, ACK responses, CID -> VM mapping, JSON output.
