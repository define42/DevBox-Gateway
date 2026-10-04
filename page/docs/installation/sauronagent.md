# Installing SauronAgent

[SauronAgent](https://github.com/define42/DevBox-Gateway/blob/main/SauronAgent/README.md) streams Linux audit events from inside the
guest VMs to the hypervisor over virtio-vsock. Each tagged
[release](https://github.com/define42/DevBox-Gateway/releases) also publishes
a `sauronagent-<version>-1.x86_64.rpm` and a `sauronagent_<version>_amd64.deb`
built from [`SauronAgent/`](https://github.com/define42/DevBox-Gateway/blob/main/SauronAgent), with the same version as the gateway
packages (the version is also compiled into the binaries, so a guest reports the
release it runs).

The [prebuilt VM images](../vm-images.md#downloading-vm-images) already include SauronAgent
with its guest service enabled.

## Package contents

One package carries both components, laid out like
`make -C SauronAgent install PREFIX=/usr`. Install it in guests that need the
agent, or on a hypervisor that needs the standalone collector, then enable
only the component that machine runs:

| Path                                               | Purpose                                                   |
|----------------------------------------------------|-----------------------------------------------------------|
| `/usr/bin/sauronagent`, `sauronagent.service`     | Guest audit agent (run it inside each VM).                |
| `/usr/bin/sauronhost`, `sauronhost.service`       | Hypervisor collector (run it on the KVM host).            |
| `/etc/sauronhost/sauronhost.yaml.example`         | Example collector config; copy to `sauronhost.yaml` and fill in the `vms:` CID map. |
| `/usr/lib/sysusers.d/sauronagent.conf`, `/usr/lib/tmpfiles.d/sauronagent.conf` | The `sauronagent` / `sauronhost` system users and their directories. |
| `/usr/share/doc/sauronagent/`                     | README, deployment, protocol, security, and vsock docs.   |

The binaries are static, so the packages have no dependencies. Installing
creates the users and directories (`systemd-sysusers`, `systemd-tmpfiles`) but
enables and starts **neither** unit: only you know whether a machine is a guest
or the hypervisor. Upgrades restart whichever unit is running; removal stops and
disables both but never deletes the agent spool or the collector's output.
The guest agent enables kernel auditing and installs its built-in execution,
privilege, configuration, persistence, and system-change rules when it starts.
No audit rules file, `auditd`, or audit tools are needed.

## Collector on a gateway host

On a DevBox Gateway host the gateway itself always runs the collector on
AF_VSOCK port 9000 (see [SauronAgent guest events](../operations/guest-events.md#sauronagent-guest-events)).
No separate SauronAgent package is needed on that host. If it is installed,
leave `sauronhost` disabled — the two would compete for the same vsock port.
The gateway gives every new VM its vsock device and maps each connection to its
VM from libvirt, so there is no `vms:` CID map to maintain. The standalone
`sauronhost` is for hypervisors that do not run the gateway.

## Install in a guest

Inside the guests — typically baked into the base images — install the package
and enable the agent. It accepts no configuration file: its settings are
compiled into the binary and dial the host (CID 2) on port 9000:

```sh
sudo dnf install ./sauronagent-<version>-1.x86_64.rpm    # or: sudo apt install ./sauronagent_<version>_amd64.deb
sudo systemctl enable --now sauronagent
```

Starting the agent automatically applies its built-in audit baseline, including
execution, access rights, privilege changes, identity/credential files,
security configuration, persistence, kernel modules, network configuration,
time changes, and mounts. It discovers existing local users' `.ssh` directories
at startup, including root's; restart after adding a user or SSH directory.
Commands such as `nmap` produce execution events, while account database writes
produce file events. The agent checks and applies the baseline on every start,
including after reboot. It preserves unrelated rules, reports unavailable
optional paths, and fails startup if an immutable or conflicting policy prevents
setup. See the
[SauronAgent deployment guide](https://github.com/define42/DevBox-Gateway/blob/main/SauronAgent/docs/deployment.md#guest-audit-rules)
for the complete paths and keys, discovery behavior, and policy-conflict handling.

## Remove the package

To remove it: `sudo apt remove sauronagent` or `sudo dnf remove sauronagent`.
Package removal leaves the guest spool intact.

> To build either package yourself, see
> [Building the SauronAgent packages](../development/building.md#building-the-sauronagent-packages).
