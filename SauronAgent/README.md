# SauronAgent

Linux guest audit and security telemetry, delivered to the hypervisor over
virtio-vsock.

SauronAgent runs inside a virtual machine, reads security-relevant events
straight from the Linux kernel's audit subsystem, correlates and normalizes
them, and forwards them to a collector on the KVM host. It needs no IP
connectivity between the guest and the host: no address, no route, no gateway,
no DNS, and no listening socket on the VM's network.

Two programs:

| Program | Runs on | Needs | Does |
|---|---|---|---|
| `sauronagent` | inside each guest | `CAP_AUDIT_READ`, `CAP_AUDIT_CONTROL`, `CAP_DAC_READ_SEARCH`, a virtio-vsock device | discovers watched paths, configures the managed audit baseline, reads `NETLINK_AUDIT`, correlates, normalizes, spools, sends |
| `sauronhost` | the hypervisor | no capabilities at all | accepts VSOCK connections, identifies each guest by its CID, enriches, writes events onward |

## Data path

```text
Linux kernel
     |
     | NETLINK_AUDIT  (multicast, read-only, CAP_AUDIT_READ)
     v
SauronAgent
     |
     | virtio-vsock   (SAUR framing, CID 2 port 9000)
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

Inside the agent the stages are separate goroutines, so that nothing slow ever
runs in the netlink receive loop:

```text
netlink reader -> correlator -> normalizer -> assign sequence -> queue -> spool -> sender
```

A sequence number is assigned immediately after normalization and before the
queue. That ordering is what lets an overflow name the exact events it lost
instead of reporting that "some" were dropped.

## Why VSOCK and not IP

Sending audit events over the guest's network would make the security
monitoring depend on the thing being monitored, and would add attack surface
to both ends:

* **No guest network configuration.** The agent works on a VM with no IP
  address at all, before DHCP, on a broken network, and on an isolated VLAN.
  There is no management interface to secure and no route to maintain.
* **No collector listener on the guest IP network.** The production collector
  listens on VSOCK. Other guests with VSOCK access can also connect to it under
  their own CIDs, so the collector still enforces connection and payload limits.
* **Nothing to firewall wrong.** Audit delivery cannot be broken by a change to
  the guest's iptables/nftables rules, its routing table, or its resolver --
  which matters because those are exactly the things an intruder changes.
* **The transport carries identity.** See below. An IP address is a claim; a
  CID is assigned by the hypervisor.

A TCP transport implementation exists for development and integration tests.
The production agent is compiled to use VSOCK: TCP would reintroduce every
dependency above and gives the collector no trustworthy way to identify a VM.

## The CID is the identity

Linux assigns each VM with a virtio-vsock device a **context ID (CID)**, and
writes it into the address of every connection that VM makes. The guest cannot
choose it, change it, or forge another VM's.

So the collector identifies a guest by the CID its connection arrived on, and
maps CID to VM name with the `vms:` list in its own configuration:

```yaml
vms:
  - cid: 102
    name: transfer-vm-03
    environment: production
    expected: true
```

The agent still sends its hostname, machine-id, boot-id, kernel version and
agent version in the HELLO message. That data is recorded under
`source.reported` and is explicitly **untrusted**: it is there to make host-side
logs readable and to let you alert on a guest whose self-description disagrees
with the CID mapping. It is never used to decide which VM an event came from.

## Getting started

Run the source-install commands below from the DevBox-Gateway repository root.
Building requires the Go version in [`go.mod`](../go.mod), GNU Make, and Linux.
Installation and the systemd commands require root. `make install` builds for
Linux amd64 by default; set `GOARCH=arm64` when targeting an ARM64 machine.

### On the hypervisor

On a DevBox Gateway host, use the gateway's always-on collector on AF_VSOCK
port 9000 and leave `sauronhost` disabled to avoid a port conflict. The gateway
adds vsock devices to new VMs and resolves their CIDs through libvirt; existing
VMs without a vsock device are not automatically migrated. See the
[gateway guest-event guide](../page/docs/operations/guest-events.md).

For a hypervisor without DevBox Gateway, install the standalone collector:

```sh
make -C SauronAgent install PREFIX=/usr  # or install the package
systemd-sysusers && systemd-tmpfiles --create
cp /etc/sauronhost/sauronhost.yaml.example /etc/sauronhost/sauronhost.yaml
$EDITOR /etc/sauronhost/sauronhost.yaml  # fill in the vms: CID map
systemctl daemon-reload
systemctl enable --now sauronhost
journalctl -u sauronhost -f              # events arrive here by default
```

### Give the VM a vsock device

```sh
qemu-system-x86_64 ... -device vhost-vsock-pci,guest-cid=102
```

or, with libvirt:

```xml
<devices>
  <vsock model='virtio'>
    <cid auto='no' address='102'/>
  </vsock>
</devices>
```

CIDs 0, 1 and 2 are reserved; guest CIDs start at 3. See
[examples/qemu-vsock.md](examples/qemu-vsock.md) for the full procedure,
including how to keep CIDs unique across a fleet and how to verify the path end
to end.

### In the guest

```sh
make -C SauronAgent install PREFIX=/usr  # or install the package
systemd-sysusers && systemd-tmpfiles --create
systemctl daemon-reload
systemctl enable --now sauronagent
```

The agent accepts no configuration file. All guest-agent settings are compiled
into `config.DefaultAgent`: it dials `CID 2` (`VMADDR_CID_HOST`) port 9000 and
spools to `/var/lib/sauronagent/spool`. Run `sauronagent -check-config` to
validate and inspect those built-in settings without starting collection.

On startup, the agent enables kernel auditing and installs its built-in rules
for execution, permissions, ownership, extended attributes, privileges, kernel
modules, kernel replacement, hostname/time changes, and mounts. On x86_64 the
syscall rules include the 32-bit compatibility ABI. It retains the five
identity/credential file watches and adds configuration and persistence paths,
escalation-tool execution, and existing local users' `.ssh` directories,
including root's. The startup journal reports skipped paths and discovery
counts; restart after adding a user or a directory that was absent at startup.

Commands such as `nmap` produce process execution events, while account
database changes produce file events. Setup uses netlink directly; no rules
file, `auditd`, or audit tools are required. The RPM and DEB install both
components without starting them, so enable the guest unit as shown above.
Every subsequent start reapplies the managed baseline as needed. See
[guest audit rules](docs/deployment.md#guest-audit-rules) for the complete paths,
syscalls, keys, overlap precedence, and discovery limitations.

## The normalized event

One Linux operation produces several audit records sharing an event id --
`audit(1789752345.312:8421)`. Forwarding them as five unrelated events would
make the stream almost unusable, so the correlator collects them and the
normalizer emits exactly one event per operation.

Categories: `process.exec`, `process.exit`, `file.access`, `file.create`,
`file.modify`, `file.delete`, `authentication.login`, `authentication.logout`,
`authentication.failure`, `user.command`, `privilege.change`,
`audit.configuration`, `firewall.configuration`, `selinux.denial`,
`system.security`.

`cat /etc/shadow`, with the built-in raw-record array omitted here for
readability:

```json
{
  "version": 1,
  "sequence": 184213,
  "timestamp": "2026-09-18T17:25:45.312Z",
  "type": "process.exec",
  "severity": "info",
  "audit_id": "1789752345.312:8421",
  "boot_id": "5f1c7d2a-1f7e-4f41-9c33-2a5bd2c0b0e7",
  "pid": 4821,
  "ppid": 4702,
  "uid": 0,
  "gid": 0,
  "auid": 1000,
  "exe": "/usr/bin/cat",
  "command": "cat /etc/shadow",
  "cwd": "/home/user",
  "paths": ["/usr/bin/cat"],
  "result": "success",
  "record_types": ["SYSCALL", "EXECVE", "CWD", "PATH", "PROCTITLE"],
  "fields": {
    "arch": "c000003e",
    "syscall": "59",
    "syscall_name": "execve",
    "exit": 0,
    "argv": ["cat", "/etc/shadow"],
    "proctitle": "cat /etc/shadow",
    "comm": "cat",
    "tty": "pts0",
    "ses": "7",
    "key": "exec",
    "euid": "0", "suid": "0", "fsuid": "0",
    "egid": "0", "sgid": "0", "fsgid": "0",
    "items": "3",
    "a0": "55f1c2a4e2c0", "a1": "55f1c2a4e340",
    "a2": "55f1c2a4d0b0", "a3": "8",
    "subj": "unconfined_u:unconfined_r:unconfined_t:s0",
    "path_details": [
      {
        "item": 0,
        "name": "/usr/bin/cat",
        "nametype": "NORMAL",
        "inode": 1969,
        "dev": "fd:00",
        "mode": "0100755",
        "ouid": 0,
        "ogid": 0,
        "rdev": "00:00",
        "cap_fp": "0", "cap_fi": "0", "cap_fe": "0", "cap_fver": "0"
      }
    ]
  }
}
```

Three properties of that document are deliberate:

* **Nothing is dropped.** Every field of every source record is either a typed
  field or an entry in `fields`. A normalizer that quietly forgets a field is
  indistinguishable from an attacker suppressing it.
* **The kernel's own words survive.** Where the agent interprets a value it
  stores the interpretation *next to* the literal: `syscall: "59"` keeps its
  company in `syscall_name: "execve"`. The built-in policy additionally carries
  a `raw` array with the original record text verbatim, which is what forensic
  review and parser regressions are checked against.
* **`uid: 0` is not the same as "no uid".** The identity fields are omitted
  when the records do not carry them and are present when they do, so the most
  security-relevant value in the model cannot be confused with a default.

### What the collector adds

The host wraps each event in an envelope with its own trusted view of where it
came from:

```json
{
  "received_at": "2026-09-18T17:25:45.318Z",
  "source": {
    "cid": 102,
    "vm": "transfer-vm-03",
    "host": "hypervisor-01",
    "uuid": "b1c4e0d2-55a7-42c9-8f31-9d0e4c6a7b18",
    "environment": "production",
    "security_domain": "restricted",
    "vlan": "310",
    "labels": {"compliance": "pci", "owner": "data-team"},
    "known": true,
    "reported": {
      "hostname": "transfer03",
      "machine_id": "9d1f0a6c4f2b41d8a0b7c3e5d6f78901",
      "boot_id": "5f1c7d2a-1f7e-4f41-9c33-2a5bd2c0b0e7",
      "kernel": "6.8.0-45-generic",
      "agent_version": "1.0.0"
    }
  },
  "event": { "…": "the event above, nested unchanged" }
}
```

`received_at` is the host's clock. Fields in `source` outside `source.reported`
come from the connection and host configuration. The nested `event`, including
its timestamp, remains guest-supplied data.

## Loss and stream monitoring

The agent reports detected queue, spool, parsing, and kernel losses in the
event stream. These reports share the same delivery path and can themselves
be lost if the guest or its storage fails. The standalone collector monitors
VMs marked `expected: true` in its static configuration. DevBox Gateway supplies
a dynamic expected set from running managed VMs:

| Event | Meaning |
|---|---|
| `sauron.queue.overflow` | the in-memory queue discarded events; names the exact missing sequence range |
| `sauron.spool.full` | the disk spool hit `max_size` and discarded the oldest unsent events |
| `sauron.audit.lost` | the kernel dropped records before the agent could read them |
| `sauron.parse.failure` | a record could not be interpreted; carries the record text |
| `sauron.transport.disconnected` / `.connected` | the link to the collector went away and came back |
| `sauron.stream.lost` / `.resumed` | **host-generated**: an expected VM is overdue for first contact or stopped sending, then resumed |

```json
{"version":1,"type":"sauron.queue.overflow","severity":"critical","boot_id":"5f1c7d2a-…","fields":{"events_dropped":1842,"first_missing_sequence":184213,"last_missing_sequence":186054}}
```

DevBox Gateway checks the expected inventory every 15 seconds. Its defaults
allow five minutes for first contact and 90 seconds of later silence; configure
`SAURON_AGENT_STARTUP_GRACE` and `SAURON_AGENT_TIMEOUT` on the gateway. Missing
agents, inventory failures, stale snapshots and pending stream alerts affect
the gateway's `/api/ready` probe. The standalone collector uses `monitor.timeout`
for both first contact and later silence (90 seconds by default).

An unresolved gateway connection reconnects on its next valid event or heartbeat
once fresh inventory can identify its CID completely. The collector resolves
the new connection's identity; prior records keep their original attribution.

Failed stream-alert writes are retried in order, including after a VM resumes
or leaves the expected set. Up to 4096 alerts remain in memory; overflow is
logged and keeps readiness unhealthy until operator recovery and restart.
These pending alerts do not survive a collector restart. See
[deployment monitoring](docs/deployment.md#6-what-to-monitor).

DevBox Gateway also retains rejected guest records and retries them every second
until every output accepts them. Retries preserve the original record and source
even after the guest disconnects or its identity resolves. Matching guest replay
can clear the same failure; heartbeats and unrelated events cannot. The retry
store holds at most 4096 records and 64 MiB of encoded data in memory. Overflow
or failure to retain a copy requires investigation and restart. Restart discards
pending copies and health state without proving delivery. See
[output failure recovery](docs/deployment.md#output-failure-recovery).

Unreported sequence gaps also keep the collector unready. A separate worker
retries their loss reports every second without requiring guest traffic or
inventory progress. Accepting a gap report records the loss, rather than
delivery of the missing events. Event acceptance across concurrent sessions
sharing a peer or trusted VM UUID is serialized through deduplication and output
commit. Originals are registered before waiting for output, preventing a
concurrent gap report from acknowledging an event still awaiting storage.
Reports that cannot fit the bounded loss accounting wait for capacity before
another output attempt, while other streams continue.

Only traffic matching the expected VM's trusted vsock identity refreshes its
deadline. A compromised guest can keep sending heartbeats while suppressing
audit data; stream liveness does not prove collection completeness. An embedded
collector must supply `ExpectedVMs` separately from its CID resolver to monitor
dynamic VMs.

## Privilege model

The agent runs as the `sauronagent` system user with `CAP_AUDIT_READ`,
`CAP_AUDIT_CONTROL`, and `CAP_DAC_READ_SEARCH`, granted ambiently and bounded by
its systemd unit. They permit reading audit records, configuring the managed
baseline, and discovering watched paths inside private directories. All three
remain available for the process lifetime. `CAP_DAC_READ_SEARCH` also permits
reading protected files visible in the service sandbox; see the
[security model](docs/security.md#4-capability-model). The agent never registers
as the audit daemon and can coexist with `auditd`. It has no `CAP_SYS_ADMIN` and the service
never runs as root.

The collector runs with an empty capability bounding set. It parses frames sent
by guests that must be assumed hostile, so the process doing that parsing is
given nothing to escalate with.

Both units are hardened further (`ProtectSystem=strict`, `PrivateDevices`,
`MemoryDenyWriteExecute`, a `RestrictAddressFamilies` list of exactly the
socket families each one uses, a `SystemCallFilter`). Every directive is
commented with why it is there and what breaks if it is removed --
see [packaging/systemd/](packaging/systemd/).

## Reliability

* Collection and sending use separate goroutines. A bounded queue drops its
  oldest events under overload and records the lost sequence range.
* Events reach `/var/lib/sauronagent/spool` before transmission. A host outage
  retains the backlog until acknowledgements or the spool size limit remove
  it. An abrupt agent exit can lose records still in memory; guest power loss
  can also lose unsynced spool writes; guest spools use periodic fsync by default.
* An acknowledgement checkpoint must be persisted before acknowledged records
  are discarded. Storage errors retain those records for retry and preserve
  sequence continuity after restart; cleanup failures can be retried with the
  same acknowledgement.
* Acknowledgements are cumulative and follow sink acceptance. The standalone
  collector's file sink keeps `sync_on_write` configurable (false by default);
  stdout and syslog rely on the downstream logger for durability. Those defaults
  do not guarantee that acknowledged records survive host power loss.
* The embedded `collector.NewFileSink`, used by DevBox-Gateway, always fsyncs
  event data and file creation/rotation metadata before acceptance, including
  file-only deployments. Its ACKs follow the filesystem's fsync durability
  guarantees. Per-event fsync adds storage latency and limits throughput;
  configured rotation still limits retention. This does not change the guest
  source spool's periodic-sync defaults or its limits before delivery.
* Retained events are replayed after reconnect. The host deduplicates using
  `(CID, HELLO boot id, sequence)` while its in-memory state remains available.
  A collector restart or state eviction can produce duplicates.
* Reconnection uses exponential backoff with jitter; collection and spooling
  continue during an outage within the configured queue and spool limits.

See [deployment limits and restart behavior](docs/deployment.md#7-restarts-upgrades-and-reboots).

## Building

SauronAgent is part of the DevBox-Gateway Go module. Its dependencies and Go
version are defined in the repository's root [`go.mod`](../go.mod). Run these
commands from the repository root:

```sh
make -C SauronAgent build      # SauronAgent/bin/sauronagent and sauronhost, CGO_ENABLED=0
make -C SauronAgent test       # SauronAgent tests
make -C SauronAgent test-race  # the same with the race detector
make -C SauronAgent vet        # go vet (also "lint"; no external linters)
make -C SauronAgent fuzz       # a short run of every SauronAgent fuzz target
make -C SauronAgent cover      # SauronAgent coverage summary
make -C SauronAgent install    # binaries, units, sysusers/tmpfiles, collector example config
```

The root `make test` and `go test ./...` also include all SauronAgent packages.
The root `make lint` runs SauronAgent's `go vet` check alongside the gateway's
golangci-lint checks.

`VERSION` is compiled in and reported to the collector in HELLO, so the host
can tell which build each guest is running:

```sh
make -C SauronAgent build VERSION=1.0.0
```

SauronAgent targets Linux. Its direct dependencies are `golang.org/x/sys`,
`github.com/mdlayher/vsock`, and `gopkg.in/yaml.v3`; their versions are managed
alongside the gateway's dependencies in the root module.

## Documentation

With the default installation prefix, installed guides share one directory:
`/usr/share/doc/sauronagent`. Relative links below follow the source-tree layout
and are intended for a checkout. Package users can browse the
[repository documentation](https://github.com/define42/DevBox-Gateway/tree/main/SauronAgent)
for working links between guides and source files.

| Document | Contents |
|---|---|
| [docs/DESIGN.md](docs/DESIGN.md) | design objectives and implementation limits |
| [docs/protocol.md](docs/protocol.md) | the SAUR wire protocol, precisely enough to reimplement |
| [docs/security.md](docs/security.md) | threat model, stated honestly: what this does and does not protect against |
| [docs/deployment.md](docs/deployment.md) | installing, sizing, monitoring and troubleshooting |
| [examples/qemu-vsock.md](examples/qemu-vsock.md) | giving a VM a vsock device and verifying it |
| [examples/sauronhost.yaml](examples/sauronhost.yaml) | collector settings with sample host and VM identities |

## Contributing

Follow the [repository contribution guide](../CONTRIBUTING.md). Changes to the
agent's compiled settings also need updates to the deployment guide and any
configuration summaries or examples they affect.

## License

The SauronAgent subtree retains its [Apache License 2.0](LICENSE). The gateway
has its own [license](../LICENSE).
