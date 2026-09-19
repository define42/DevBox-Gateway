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
| `sauronagent` | inside each guest | `CAP_AUDIT_READ`, `CAP_AUDIT_CONTROL`, a virtio-vsock device | configures execution auditing, reads `NETLINK_AUDIT`, correlates, normalizes, spools, sends |
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
* **Nothing to reach from the guest network.** The collector does not listen on
  a TCP port. A neighbouring VM cannot connect to it, scan it, or flood it; a
  guest can only reach it through its own virtio-vsock device.
* **Nothing to firewall wrong.** Audit delivery cannot be broken by a change to
  the guest's iptables/nftables rules, its routing table, or its resolver --
  which matters because those are exactly the things an intruder changes.
* **The transport carries identity.** See below. An IP address is a claim; a
  CID is assigned by the hypervisor.

`transport.kind: tcp` exists for development and integration tests. It is
never the right choice in a deployment: it reintroduces every dependency above
and it gives the collector no trustworthy way to say which VM it is talking to.

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

## Quick start

### On the hypervisor

```sh
make install PREFIX=/usr                 # or install the package
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
make install PREFIX=/usr                 # or install the package
systemd-sysusers && systemd-tmpfiles --create
systemctl daemon-reload
systemctl enable --now sauronagent
```

The agent needs no configuration file. Its built-in defaults dial `CID 2`
(`VMADDR_CID_HOST`) port 9000 and spool to `/var/lib/sauronagent/spool`, which
is what a guest needs. To change a setting, see
[docs/deployment.md](docs/deployment.md#changing-an-agent-setting).

On startup, the agent enables kernel auditing and ensures `execve`/`execveat`
rules are loaded, including the 32-bit compatibility ABI on x86_64. Commands
such as `nmap` then produce process execution events. Setup uses netlink
directly; no rules file, `auditd`, or audit tools are required. The RPM and DEB
install both components without starting them, so enable the guest unit as
shown above. Every subsequent start reapplies the execution baseline as needed.
See [guest audit rules](docs/deployment.md#guest-audit-rules) for conflicting
policy and the `audit.manage_rules: false` option for external rule management.

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

`cat /etc/shadow`, as the agent emits it (real output, `preserve_raw: false`):

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
    "key": "exec-watch",
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
  company in `syscall_name: "execve"`. With the default `preserve_raw: true`
  the event additionally carries a `raw` array with the original record text
  verbatim, which is what forensic review and parser regressions are checked
  against.
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

`received_at` is the host's clock, which is independent of a guest clock that
may be wrong or manipulated. Everything outside `source.reported` is
configured on the hypervisor and cannot be influenced by the guest.

## Failure is an event, not a log line

A security agent that quietly stops delivering is worse than one that is
plainly down. Every way an event can be lost produces an event of its own, in
the same stream as the audit data:

| Event | Meaning |
|---|---|
| `sauron.queue.overflow` | the in-memory queue discarded events; names the exact missing sequence range |
| `sauron.spool.full` | the disk spool hit `max_size` and discarded the oldest unsent events |
| `sauron.audit.lost` | the kernel dropped records before the agent could read them |
| `sauron.parse.failure` | a record could not be interpreted; carries the record text |
| `sauron.transport.disconnected` / `.connected` | the link to the collector went away and came back |
| `sauron.stream.lost` / `.resumed` | **host-generated**: an `expected: true` VM stopped sending |

```json
{"version":1,"type":"sauron.queue.overflow","severity":"critical","boot_id":"5f1c7d2a-…","fields":{"events_dropped":1842,"first_missing_sequence":184213,"last_missing_sequence":186054}}
```

`sauron.stream.lost` is the one the design exists for: an intruder's first move
inside a guest is to silence its telemetry, and only the host can notice that.

## Privilege model

The agent runs as the `sauronagent` system user with `CAP_AUDIT_READ` and
`CAP_AUDIT_CONTROL`, granted ambiently and bounded by its systemd unit.
`CAP_AUDIT_READ` permits joining the `NETLINK_AUDIT` read-log multicast group;
`CAP_AUDIT_CONTROL` permits enabling auditing and installing execution rules.
Both capabilities remain available for the process lifetime. The agent never
registers as the audit daemon and can coexist with `auditd`. It has no
`CAP_SYS_ADMIN` and the service never runs as root.

For externally managed audit policy, set `audit.manage_rules: false` and
restrict the unit to `CAP_AUDIT_READ`; see the deployment guide. This mode
collects the events produced by the existing policy without changing it.

The collector runs with an empty capability bounding set. It parses frames sent
by guests that must be assumed hostile, so the process doing that parsing is
given nothing to escalate with.

Both units are hardened further (`ProtectSystem=strict`, `PrivateDevices`,
`MemoryDenyWriteExecute`, a `RestrictAddressFamilies` list of exactly the
socket families each one uses, a `SystemCallFilter`). Every directive is
commented with why it is there and what breaks if it is removed --
see [packaging/systemd/](packaging/systemd/).

## Reliability

* The netlink reader never blocks on the host. Under sustained overload events
  are dropped from a bounded queue on purpose -- and accounted for, never
  silently.
* Events are written to a disk spool at `/var/lib/sauronagent/spool` before
  they are sent, and are deleted only once the host acknowledges them, so an
  agent restart or a host outage does not lose the backlog.
* Acknowledgement is cumulative and delivery is at-least-once. The host
  deduplicates on `(CID, boot id, sequence)`.
* Reconnection uses exponential backoff with jitter; collection and spooling
  continue throughout an outage.

## Building

```sh
make build           # ./bin/sauronagent and ./bin/sauronhost, CGO_ENABLED=0
make test            # unit tests
make test-race       # the same with the race detector
make vet             # go vet (also "make lint"; no external linters)
make fuzz            # a short run of every fuzz target
make cover           # coverage summary
make install         # binaries, units, sysusers/tmpfiles, example configs
```

`VERSION` is compiled in and reported to the collector in HELLO, so the host
can tell which build each guest is running:

```sh
make build VERSION=1.0.0
```

Go 1.27 or newer, Linux. Dependencies: `golang.org/x/sys`,
`github.com/mdlayher/vsock`, `gopkg.in/yaml.v3` -- everything else is the
standard library.

## Documentation

| Document | Contents |
|---|---|
| [docs/DESIGN.md](docs/DESIGN.md) | the design specification this implements |
| [docs/protocol.md](docs/protocol.md) | the SAUR wire protocol, precisely enough to reimplement |
| [docs/security.md](docs/security.md) | threat model, stated honestly: what this does and does not protect against |
| [docs/deployment.md](docs/deployment.md) | installing, sizing, monitoring and troubleshooting |
| [examples/qemu-vsock.md](examples/qemu-vsock.md) | giving a VM a vsock device and verifying it |
| [examples/sauronagent.yaml](examples/sauronagent.yaml), [examples/sauronhost.yaml](examples/sauronhost.yaml) | every setting, commented, at its default |
