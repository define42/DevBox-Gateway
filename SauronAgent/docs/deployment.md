# Deployment guide

Installing, sizing, monitoring and troubleshooting SauronAgent and SauronHost.

## 1. What goes where

| | Hypervisor | Each guest |
|---|---|---|
| Binary | `/usr/bin/sauronhost` | `/usr/bin/sauronagent` |
| Config | `/etc/sauronhost/sauronhost.yaml` | none (built-in defaults) |
| Unit | `sauronhost.service` | `sauronagent.service` |
| User | `sauronhost` | `sauronagent` |
| State | `/var/log/sauronhost` (if the file output is enabled) | `/var/lib/sauronagent/spool` |
| Privilege | none | `CAP_AUDIT_READ`, `CAP_AUDIT_CONTROL` |

### Requirements

* Linux 4.8 or newer on both ends for virtio-vsock (`vhost_vsock` on the host,
  `vmw_vsock_virtio_transport` in the guest).
* `CAP_AUDIT_READ` and the audit read-log multicast group: Linux 3.16 or newer.
* `CAP_AUDIT_CONTROL` for the default automatic execution-rule setup. No
  `auditd` or audit command-line tools are required.
* systemd 247 or newer for the units as shipped. Older systemd ignores the
  directives it does not know (`ProtectProc=`, `ProcSubset=`) with a warning;
  everything else applies.
* Go 1.27 or newer to build. Nothing at runtime: the binaries are built with
  `CGO_ENABLED=0`.

## 2. Install the collector (hypervisor)

```sh
make install PREFIX=/usr
systemd-sysusers
systemd-tmpfiles --create
cp /etc/sauronhost/sauronhost.yaml.example /etc/sauronhost/sauronhost.yaml
```

Edit `/etc/sauronhost/sauronhost.yaml`. The only part that must be right is the
CID map:

```yaml
host:
  name: hypervisor-01
vms:
  - cid: 102
    name: transfer-vm-03
    environment: production
    expected: true
```

Everything else has a working default. Then:

```sh
systemctl daemon-reload
systemctl enable --now sauronhost
journalctl -u sauronhost -f
```

With the default output the collector writes newline-delimited JSON to stdout,
which systemd captures into the journal. To hand events to a log shipper
instead, enable the file sink (`output.file`) or the syslog sink
(`output.syslog`); several sinks can be enabled at once, and an event is
acknowledged to the guest only once **every** enabled sink has accepted it.

## 3. Give each VM a vsock device

Assign a CID and add the device -- `-device vhost-vsock-pci,guest-cid=102`, or
the libvirt `<vsock>` element. Guest CIDs start at 3; 0, 1 and 2 are reserved.
The full procedure, the fleet-wide allocation discipline and the end-to-end
verification steps are in
[../examples/qemu-vsock.md](../examples/qemu-vsock.md).

Every CID you assign must appear in the collector's `vms:` list, or its events
arrive with `"known": false` and a synthetic name.

## 4. Install the agent (guest)

```sh
make install PREFIX=/usr
systemd-sysusers
systemd-tmpfiles --create
systemctl daemon-reload
systemctl enable --now sauronagent
journalctl -u sauronagent -n 50
```

The agent needs no configuration file. The shipped unit runs it on the built-in
defaults, which dial CID 2 port 9000 and spool to `/var/lib/sauronagent/spool`.
Most guests never need anything else.

### Changing an agent setting

Write only the keys that change to a file --
[../examples/sauronagent.yaml](../examples/sauronagent.yaml) lists every key at
its default -- and point the agent at it with a drop-in:

```sh
mkdir -p /etc/sauronagent
printf 'spool:\n  sync_on_write: true\n' > /etc/sauronagent/sauronagent.yaml
sauronagent -check-config -config /etc/sauronagent/sauronagent.yaml
systemctl edit sauronagent
#   [Service]
#   ExecStart=
#   ExecStart=/usr/bin/sauronagent -config /etc/sauronagent/sauronagent.yaml
systemctl restart sauronagent
```

The startup line in the journal names the configuration in force
(`config=/etc/sauronagent/sauronagent.yaml`, or
`config="the built-in default configuration"`).

### Guest audit rules

With the defaults `audit.enabled: true` and `audit.manage_rules: true`, the
agent enables kernel auditing and ensures `execve`/`execveat` rules through
`NETLINK_AUDIT` when it starts. On x86_64 these cover both native 64-bit and
32-bit compatibility execution, without filtering by user or success. Other
supported architectures use their native ABI. Unsupported architectures report
a startup error; externally managed rules can be used instead.

Commands such as `nmap` produce execution events containing the executable and
arguments. These events do not contain terminal output or a port-scan detection
alert. The agent preserves unrelated rules, does not lock policy, and never
claims the audit daemon PID. Repeated starts do not duplicate its rules. The
rules remain active when the agent stops and are reapplied as needed on the
next start, including after reboot.

The package installs both guest and collector components without enabling or
starting either unit. In each guest, `systemctl enable --now sauronagent`
activates collection and automatic rule setup. There is no packaged audit rules
file and no dependency on `auditd`, `auditctl`, or `augenrules`.

Startup fails with an actionable error if the agent cannot establish its
execution baseline: for example, missing `CAP_AUDIT_CONTROL`, immutable policy
without the required rules, or a conflicting `never,task` rule. Resolve the
existing policy rather than having the agent delete unrelated rules. Immutable
policy changes require a reboot. After removing `never,task`, start a new login
session or reboot so newly created processes receive syscall auditing.

Optional diagnostics, if audit tools are already installed:

```sh
sudo auditctl -s
sudo auditctl -l
```

`enabled 1` means auditing is enabled; `enabled 2` means policy is immutable.
Use `journalctl -u sauronagent` to inspect startup failures without audit tools.
If the kernel was booted with `audit=0` and `NETLINK_AUDIT` is unavailable,
remove that boot argument and reboot. Runtime setup can enable an initialized
audit subsystem, but cannot restore one disabled during kernel initialization.

#### Externally managed policy

To collect an existing policy without configuring the kernel, set:

```yaml
audit:
  manage_rules: false
```

Load that configuration using the service drop-in described above. To also
remove rule-management privilege, add this to the drop-in:

```ini
[Service]
AmbientCapabilities=
AmbientCapabilities=CAP_AUDIT_READ
CapabilityBoundingSet=
CapabilityBoundingSet=CAP_AUDIT_READ
```

Restart the agent after changing the unit. This mode requires the external
policy to enable auditing and supply the execution rules. With
`audit.enabled: false`, the agent performs neither rule setup nor collection.

#### Optional broader coverage

The agent manages execution rules only. If your detection needs file and
privilege activity, manage additional rules separately with your audit policy
tools. For example, an existing `augenrules` deployment can load rules such as
these from `/etc/audit/rules.d/sauron-local.rules`. If its reload clears active
rules, restart SauronAgent afterwards to restore the execution baseline:

```text
## identity and privilege files
-w /etc/passwd     -p wa -k identity
-w /etc/shadow     -p wa -k identity
-w /etc/group      -p wa -k identity
-w /etc/sudoers    -p wa -k identity
-w /etc/sudoers.d/ -p wa -k identity

## remote access configuration
-w /etc/ssh/sshd_config -p wa -k sshd

## privilege escalation by ordinary users
-a always,exit -F arch=b64 -S setuid,setreuid,setresuid -F auid>=1000 -F auid!=4294967295 -k privilege

## the audit configuration itself
-w /etc/audit/ -p wa -k audit-config
```

Syscall rules are not free. `-S execve` on a build server is a large volume of
records; start with the execution baseline, then add what your detection
actually uses.

## 5. Sizing

Measured on the `cat /etc/shadow` example in the README, a normalized exec
event is about **1.0 KiB** of JSON, or about **1.8 KiB** with
`preserve_raw: true`. Events with long argument vectors or many PATH records
are larger; a frame is capped at `transport.max_payload_size` (1 MiB).

### Queue

`queue.capacity` (default 10,000) bounds the events held in memory between the
netlink reader and the sender. Worst-case memory is roughly
`capacity x event size`: 10,000 x 1.8 KiB is about 18 MiB.

The queue exists to absorb **bursts**, not outages -- a package upgrade, a
build, a fork storm. When it fills, the oldest events are dropped and a
`sauron.queue.overflow` event names exactly which sequence numbers went. Size
it so that a normal burst fits; if overflows happen while the host is up and
acknowledging, the queue is too small (or the audit rules are too broad).

### Spool

`spool.max_size` (default 1 GiB) is what carries you through a **host outage**:

```text
max_size  >=  outage seconds  x  events per second  x  event size  x  1.3
```

At 50 events/second with raw preserved, an hour of collector downtime is about
`3600 x 50 x 1.8 KiB ~= 310 MiB`. The 1 GiB default covers most of a working
day at that rate. On reaching the limit the agent emits `sauron.spool.full`
and discards the oldest unsent data, with the sequence range.

`spool.segment_size` (default 16 MiB) is the granularity at which acknowledged
data is reclaimed: smaller segments return disk space sooner and use more file
handles.

`spool.sync_on_write: false` (the default) survives an agent crash;
`true` survives a guest power loss, at a large cost in throughput. Consider
`true` for guests whose last seconds of audit trail are the interesting part --
which, after an attacker triggers a reboot, they are.

### Netlink receive buffer

`audit.socket_receive_buffer` (default 8 MiB) is the kernel's queue for this
socket. Records that do not fit are **dropped by the kernel**, not queued, and
the agent can only count them (`sauron.audit.lost`). The agent does not hold
`CAP_NET_ADMIN`, so the request is clamped by `net.core.rmem_max`:

```sh
sysctl net.core.rmem_max                 # must be >= audit.socket_receive_buffer
sysctl -w net.core.rmem_max=16777216     # persist in /etc/sysctl.d/
```

Raise the kernel's own audit backlog too if `auditctl -s` shows a non-zero
`lost`:

```sh
auditctl -b 16384
```

### Collector

`limits.max_connections` (1024) and `limits.max_connections_per_cid` (4) bound
what the guests can consume. `limits.dedup_window` (65536 sequence numbers per
(CID, boot id)) must stay well above the agent's `transport.max_unacked`
(1024), or a replay after a long outage will be written twice.

## 6. What to monitor

### From the event stream

These are security events, not operational noise. Alert on all of them:

| Event | Generated by | Meaning |
|---|---|---|
| `sauron.stream.lost` | host | an `expected: true` VM stopped sending. **The most important alert in the system.** |
| `sauron.stream.resumed` | host | it came back; correlate the gap |
| `sauron.queue.overflow` | agent | events were destroyed in memory; the range says which |
| `sauron.spool.full` | agent | events were destroyed on disk; the range says which |
| `sauron.audit.lost` | agent | the kernel dropped records before the agent saw them |
| `sauron.parse.failure` | agent | a record could not be parsed; the text is attached |
| `sauron.transport.disconnected` | agent | the link dropped; expect a matching `connected` |
| `sauron.protocol.violation` | either | the peer sent something the protocol does not allow |
| `audit.configuration` | guest kernel | auditing was disabled, or rules were changed |

Also worth a rule: `source.reported.hostname` that disagrees with `source.vm`,
and a `boot_id` that changes without a reboot you scheduled.

### Counters

`internal/metrics` maintains the counters DESIGN section 39 requires:

```text
agent:  audit_messages_received_total  audit_messages_dropped_total
        kernel_records_lost_total      parse_errors_total
        events_created_total           events_sent_total
        events_acknowledged_total      events_dropped_total
        events_resent_total            queue_depth
        spool_bytes                    spool_events
        vsock_reconnects_total         send_errors_total

host:   connections_accepted_total     connections_rejected_total
        connections_active             frames_received_total
        frame_errors_total             events_received_total
        events_duplicate_total         events_output_total
        output_errors_total            streams_lost_total
```

In v1 there is no scrape endpoint. The agent's counters reach the hypervisor in
every heartbeat -- `uptime`, `events_received`, `events_sent`,
`events_spooled`, `events_dropped`, `audit_enabled`, `queue_depth`,
`spool_bytes` -- which is deliberate: a counter that can only be read from
inside the guest is a counter an intruder can edit. Watch for

* `audit_enabled: false` on a VM that should be auditing,
* `events_dropped` rising at all,
* `queue_depth` or `spool_bytes` that grow and never fall (the host is not
  acknowledging, or is slower than the guest),
* a heartbeat that stops (which is what `sauron.stream.lost` is built on).

## 7. Restarts, upgrades and reboots

* Restarting the **agent** loses nothing: unacknowledged events are in the
  spool, and the sequence continues from `LastSequence` within the same boot.
* Restarting the **collector** loses nothing: the agents reconnect with backoff
  and re-send from their spools. Duplicates are expected and suppressed.
* Rebooting a **guest** starts a new boot id, and sequence numbers restart.
  That is not a gap; it is a new stream.
* An orderly stop sends `SHUTDOWN`, so a maintenance window looks different in
  the host logs from a VM that simply went quiet. Use that distinction in your
  alerting.

## 8. Troubleshooting

### "no AF_VSOCK transport on this system"

```text
vsock dial host(2):9000: no AF_VSOCK transport on this system: load the vsock
kernel modules (guest: vmw_vsock_virtio_transport, host: vhost_vsock) and give
the VM a virtio-vsock device (qemu: -device vhost-vsock-pci,guest-cid=N)
```

In order:

1. `lspci | grep -i vsock` in the guest -- if there is no device, the VM was
   started without one. Adding it to a libvirt domain requires a full stop and
   start, not a reboot from inside.
2. `lsmod | grep vsock`, then `modprobe vmw_vsock_virtio_transport`.
3. `ls -l /dev/vsock` -- absent means the transport is not loaded.
4. On the hypervisor, `lsmod | grep vhost_vsock` and `ls -l /dev/vhost-vsock`.
5. If all of that is present and it still fails, check
   `RestrictAddressFamilies=` in the unit: a unit that does not list `AF_VSOCK`
   produces `EAFNOSUPPORT`, which is exactly what a missing device looks like.
   This is the one case where the error message points away from the cause.

### EPERM from netlink

```text
audit: opening NETLINK_AUDIT socket: operation not permitted (the process needs
CAP_AUDIT_READ (for example AmbientCapabilities=CAP_AUDIT_READ in the systemd
unit))
```

* `systemctl show sauronagent -p AmbientCapabilities -p CapabilityBoundingSet`
  must show `cap_audit_read` and, for automatic rule setup, `cap_audit_control`
  in both. `AmbientCapabilities=` without the capability in
  `CapabilityBoundingSet=` grants nothing.
* Do not add `PrivateUsers=yes`: inside a user namespace `CAP_AUDIT_READ`
  applies to that namespace, and the kernel checks audit access against the
  initial one. The agent starts and receives nothing.
* Running the binary by hand needs root, or
  `setcap cap_audit_read,cap_audit_control+ep /usr/bin/sauronagent`.
* A container needs the capabilities granted to the container itself
  (`--cap-add=AUDIT_READ --cap-add=AUDIT_CONTROL`) and a non-user-namespaced
  runtime. With `audit.manage_rules: false`, only `AUDIT_READ` is needed.

### The agent runs but there are no audit events

`journalctl -u sauronagent` shows a connection and heartbeats; the host sees
`sauron.*` events but nothing about the guest.

* Check `audit.enabled` and `audit.manage_rules` in the active configuration.
  Automatic setup is performed on startup; an external policy reload can later
  disable auditing or remove rules. Restart the agent to restore its baseline.
* If audit tools are installed, `auditctl -s` shows whether auditing is enabled
  and `auditctl -l` lists active rules. `No rules` means no syscall auditing.
  Also check for `never,task`, which suppresses syscall events despite loaded
  execution rules. See section 4 for policy conflicts and external management.
* `auditctl -s` showing a rising `lost` means the kernel is dropping records
  before anyone reads them: raise `-b` and `net.core.rmem_max`.

### Coexisting with auditd

They can coexist because the agent subscribes to the audit **read-log multicast
group**; it never sends
`AUDIT_SET` with an audit pid, so it never becomes the audit daemon and never
displaces one. `auditctl -s` continues to show auditd's pid.

By default, the agent also enables auditing and adds execution rules. If
`auditd`'s policy should control all rules, set `audit.manage_rules: false` and
provide the desired execution rules there. If an external reload clears the
agent's rules, restart SauronAgent to restore them.

Consequences worth knowing:

* Both `auditd` and the agent see every record. Rules are global -- there is no
  such thing as a rule "for SauronAgent" -- so tuning rules changes what both
  of them log.
* Stopping `auditd` does not stop the agent: multicast delivery depends on
  auditing being enabled in the kernel, not on a daemon being registered.
  `auditctl -e 0` does stop it, and produces a `CONFIG_CHANGE` record on the
  way out, which the agent forwards as an `audit.configuration` event.
* Other multicast readers (`systemd-journald` with audit reading enabled, for
  example) are unaffected: each socket gets its own copy, with its own receive
  buffer and its own drops.

### The host is not receiving a stream

Work down the path:

1. Guest: `systemctl status sauronagent`, then `journalctl -u sauronagent` for
   `sauron.transport.connected` / `disconnected`.
2. Guest: is the spool growing? `du -sh /var/lib/sauronagent/spool`. Growth
   means the agent is collecting but not delivering.
3. Hypervisor: `systemctl status sauronhost`. Is it listening on the port the
   guest dials (`listen.port` vs `vsock.port`, both 9000 by default)?
4. Hypervisor: `listen.cid` must be `4294967295` (`VMADDR_CID_ANY`). Bound to a
   specific CID, the collector is deaf to every other guest.
5. Hypervisor: check the unit's `RestrictAddressFamilies=` lists `AF_VSOCK`.
6. Test the raw path with `socat`, as in
   [../examples/qemu-vsock.md](../examples/qemu-vsock.md) -- stop the collector
   first, since only one listener can hold the port.
7. If events arrive but with `"known": false`, the CID has no entry in `vms:`.
   The stream is fine; the map is not.

### Events are being dropped

| Symptom | Cause | Response |
|---|---|---|
| `sauron.queue.overflow` while the host is up | burst larger than `queue.capacity` | raise capacity, or narrow the audit rules |
| `sauron.queue.overflow` while the host is down | the spool is not keeping up or is disabled | enable the spool; check disk throughput |
| `sauron.spool.full` | the outage outlasted `spool.max_size` | raise it, or fix the outage faster |
| `sauron.audit.lost` | the kernel dropped records | raise `audit.socket_receive_buffer` **and** `net.core.rmem_max`, and `auditctl -b` |
| `sauron.parse.failure` | a record the parser does not understand | the text is in the event; it is a bug report |

### "payload exceeds maximum size"

One event exceeded `transport.max_payload_size` or the host's
`limits.max_payload_size` -- usually a process with an enormous argument
vector. Raise both (they are independent limits and the smaller one wins), or
accept the loss knowingly. The agent fails such a send locally rather than
emitting a frame the host is certain to reject.

### The configuration is rejected at startup

```text
parsing agent config /etc/sauronagent/sauronagent.yaml: yaml: unmarshal errors:
  line 12: field preserv_raw not found in type config.AuditSection
```

Unknown keys are refused on purpose: a typo in a security-relevant setting must
not silently leave the default in place. Check the spelling against
[../examples/sauronagent.yaml](../examples/sauronagent.yaml), which lists every
key at its default value.

Two more startup failures worth recognising:

```text
invalid agent config ...: transport.kind must be "vsock" or "tcp", got "quic"
invalid host config ...: vms[1]: CID 100 is already mapped to "a"; a CID identifies exactly one VM
```

The second one is a safety net, not a nuisance: two VMs sharing a CID would
make every event from either of them unattributable, so the collector refuses
to start rather than mislabel an audit trail.
