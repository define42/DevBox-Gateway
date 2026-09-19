# DevBox Gateway

[![codecov](https://codecov.io/gh/define42/devbox-gateway/graph/badge.svg?token=HS2KD8YHNG)](https://codecov.io/gh/define42/devbox-gateway)

`devbox-gateway` is a self-hosted gateway that publishes libvirt-managed virtual
desktops over a single HTTPS port. It combines three things on TCP `:443`:

1. An **RDP-over-TLS reverse proxy** that terminates TLS from the client, picks
   a backend VM based on the client's TLS SNI, and re-establishes TLS to that
   backend. The proxy speaks raw RDP (X.224 / TPKT), not the Microsoft RD
   Gateway HTTP/UDP transports.
2. An **HTTPS web dashboard** for end users to create, start, stop, restart and
   delete their own virtual machines, download an `.rdp` connection file, and
   open an in-browser serial console or noVNC session.
3. **LDAP-backed authentication** so the same credentials gate both the
   dashboard and any RDP session that traverses the gateway.

Connections are demultiplexed by sniffing the first byte on the accepted TCP
socket: a TLS handshake record (`0x16`) is routed to the HTTPS handler, anything
else is treated as an RDP X.224 Connection Request.

> ⚠️ This is **not** Microsoft RD Gateway. It is a TLS-to-TLS RDP proxy plus a
> companion management UI. There is no HTTP- or UDP-tunneled RDP transport.

---

## Table of contents

- [Features](#features)
- [Architecture](#architecture)
- [Quick start (Docker Compose)](#quick-start-docker-compose)
- [Installing the RPM](#installing-the-rpm)
- [Installing the deb](#installing-the-deb)
- [Installing SauronAgent](#installing-sauronagent)
- [Login flow](#login-flow)
- [Connecting an RDP client](#connecting-an-rdp-client)
- [Configuration](#configuration)
  - [Audit logs and Splunk](#audit-logs-and-splunk)
    - [Forwarding to Splunk HEC](#forwarding-to-splunk-hec)
  - [SauronAgent guest events](#sauronagent-guest-events)
  - [TLS certificates](#tls-certificates)
  - [LDAP](#ldap)
  - [Libvirt and VM storage](#libvirt-and-vm-storage)
- [Building from source](#building-from-source)
- [Testing and linting](#testing-and-linting)
- [Repository layout](#repository-layout)
- [Security notes](#security-notes)
- [License](#license)

---

## Features

- **RDP-over-TLS reverse proxy** with SNI-based backend routing.
- **HTTPS dashboard** for self-service VM lifecycle management (create, start,
  restart, shutdown, remove). VM CPU and RAM are fixed by the gateway
  configuration (`VM_VCPU_COUNT` / `VM_MEMORY_MIB`), not chosen by users.
- **In-browser consoles**: serial console and noVNC streamed over WebSocket.
- **LDAP authentication** with optional StartTLS and optional certificate
  verification.
- **ACME / Let's Encrypt** support for automatic public TLS certificates, with
  a self-signed fallback for local development.
- **Libvirt integration** for managing QEMU/KVM virtual machines from a
  configurable storage pool, with base image auto-download.
- **Single port** (`:443`) for everything: dashboard, websockets, and RDP.
- **JSON Lines audit trail** for authentication, VM lifecycle, console/RDP
  connections, and administrator actions, ready for file-based ingestion.

## Architecture

```
                  ┌──────────────────────── TCP :443 ────────────────────────┐
client ──TLS──►   │  byte-sniff: 0x16 → HTTPS, else → RDP X.224              │
                  └──────────────┬──────────────────────────┬────────────────┘
                                 │                          │
                       HTTPS / WebSocket                 RDP / TLS
                                 │                          │
                ┌────────────────▼─────────────┐  ┌─────────▼─────────────────┐
                │ chi router + Huma API        │  │ TLS terminate, read SNI   │
                │  /login, /logout             │  │ → dial backend VM         │
                │  /api/dashboard/*            │  │ → new RDP TLS handshake   │
                │  /api/dashboard/console/...  │  │ → bidirectional proxy     │
                │  /api/dashboard/vnc/...      │  └─────────┬─────────────────┘
                │  static assets               │            │
                └────────────────┬─────────────┘            │
                                 │                          │
                       LDAP bind / session                  │
                                 │                          │
                  ┌──────────────▼──────────────────────────▼────────────────┐
                  │              libvirt (QEMU/KVM) on the host              │
                  └──────────────────────────────────────────────────────────┘
```

The RDP flow on the front side is:

1. Read the client's X.224 Connection Request (TPKT).
2. Reply with an X.224 Connection Confirm selecting `PROTOCOL_SSL` (TLS).
3. Complete the TLS handshake with the client and read SNI.
4. Authorize the VM owner and consume the single-use Connect grant.
5. Load the VM's host-assigned address and provisioned certificate identity,
   then TCP-connect to the backend.
6. Send a fresh Connection Request to the backend requesting TLS only.
7. Read the backend's Connection Confirm and require `PROTOCOL_SSL`.
8. Verify the backend certificate and its provisioned server name during TLS.
9. Splice bytes between client TLS and backend TLS for the rest of the session.

On shutdown, the gateway stops accepting HTTP requests and gives active handlers
up to 5 seconds to finish. It then cancels remaining requests and closes their
connections, allowing up to another 5 seconds for cleanup before closing the
audit sink. Cancelled VM creation rolls back its partially created resources;
interrupted image uploads remove their temporary files. RDP and WebSocket
sessions are drained separately.

## Quick start (Docker Compose)

Requirements on the host:

- Docker and Docker Compose v2.
- A libvirt daemon reachable at `/var/run/libvirt` (the compose file
  bind-mounts it into the gateway container).
- Libvirt's network-filter driver and its firewall tools on the host. The
  gateway creates its dedicated `devbox` NAT network and `virbr-devbox` bridge
  during startup; no pre-existing bridge or macvlan is needed.
- Write access to `/data/` on the host (used for ACME data, VM images, serial /
  VNC sockets, and the persistent audit log at `/data/logs/audit.jsonl`).
- At least one QCOW2 base disk image in `/data/baseimages`, named with an
  `.img`, `.qcow2`, or `.raw` extension. The gateway will not start without a
  valid QCOW2 image — see
  [Libvirt and VM storage](#libvirt-and-vm-storage) for a download example.

Start the stack:

```sh
make run
```

This stops any previous stack, rebuilds the images, and starts:

- `gateway` — the Go binary, using host networking and listening on
  `https://localhost` (port `443`).
- `ldap` — a `glauth/glauth` LDAP server pre-populated from
  `testldap/default-config.cfg` for local development.
- `splunk` — a `splunk/splunk` Splunk Enterprise instance that receives every
  audit event from the gateway over HEC (see
  [Forwarding to Splunk HEC](#forwarding-to-splunk-hec)), and every SauronAgent
  event from inside the VMs (see
  [SauronAgent guest events](#sauronagent-guest-events)). Starting it accepts
  the [Splunk General Terms](https://www.splunk.com/en_us/legal/splunk-general-terms.html).

The first Splunk start takes a few minutes; the gateway queues and retries
audit events until HEC is reachable. Then open Splunk Web at
`http://localhost:8000` (user `admin`, password `devbox-splunk`) and search
`index=devbox_audit`, or `index=devbox_sauron` for the guest events of VMs whose
base image runs SauronAgent. The admin password and the shared HEC token are
development-only defaults; override them with `SPLUNK_PASSWORD` and
`SPLUNK_HEC_TOKEN` in the environment or a `.env` file. Both indexes are created
by `testsplunk/create_index.yml`, and Splunk's configuration and indexed data
persist in the `splunk-etc` and `splunk-var` Docker volumes. The gateway
container runs with `seccomp=unconfined` because Docker's default seccomp
profile blocks the AF_VSOCK socket the SauronAgent collector listens on.

To stop everything: `docker compose stop`.

## Installing the RPM

For a native (non-container) deployment on Rocky Linux 9 (x86_64), each tagged
release publishes a `devbox-gateway-<version>-1.x86_64.rpm` artifact on the
[GitHub Releases](https://github.com/define42/devbox-gateway/releases) page. The
RPM version matches the container image tag for the same release. Packages are
built and installation-tested against the current Rocky Linux 9 repositories;
other RPM distributions are not part of the native compatibility baseline.

The package installs its binary, unit, and config; the service creates the
audit file at runtime:

| Path                                            | Purpose                                              |
|-------------------------------------------------|------------------------------------------------------|
| `/usr/bin/devbox-gateway`                        | The gateway binary.                                  |
| `/usr/lib/systemd/system/devbox-gateway.service` | systemd unit (runs as root, binds `:443`).           |
| `/etc/devbox-gateway/devbox-gateway.conf`        | Config file (installed `0640 root:root` as it may hold credential digests), marked `%config(noreplace)` so your edits survive upgrades. |
| `/var/log/devbox-gateway/audit.jsonl`             | Append-only JSON Lines audit log, created when the gateway starts. |

It requires `libvirt-libs`, `ca-certificates`, `libvirt-daemon-kvm`,
`libvirt-daemon-driver-nwfilter`, and `qemu-kvm`. The nwfilter driver supplies
mandatory host-side guest traffic enforcement; its dependencies provide the
firewall tools. The package also declares the shared-library and versioned
symbol requirements detected in its binary, so `dnf` rejects an installation
when the available libraries cannot load it. The modular daemons include
`virtqemud`, `virtnetworkd`, `virtstoraged`, and `virtnwfilterd`. Package
installation does not open the public gateway port; allow it yourself (`443/tcp`
by default, or your custom
`LISTEN_ADDR` port). The gateway installs its VM network filter at startup.

1. **Install** (let `dnf` pull in the dependencies):

   ```sh
   sudo dnf install ./devbox-gateway-<version>-1.x86_64.rpm
   ```

2. **Satisfy the runtime prerequisites** — the same ones as the Docker quick
   start: a running libvirt daemon, a storage pool, write access to
   `DATA_ROOT_DIR` (native default `/var/lib/libvirt/devbox-gateway`), and at
   least one base image in `<DATA_ROOT_DIR>/baseimages` (the gateway refuses to
   start with an empty library). The default lives under `/var/lib/libvirt` so
   images and sockets sit in a tree QEMU can use under SELinux without
   relabeling. See [Libvirt and VM storage](#libvirt-and-vm-storage).

   Make sure libvirt itself is enabled — the gateway's unit only *wants*
   `libvirtd.service`, it does not enable libvirt for you. On Fedora / RHEL 9+
   (and recent Debian/Ubuntu) libvirt ships as modular, socket-activated daemons,
   so enable the sockets the gateway uses:

   ```sh
   sudo systemctl enable --now virtqemud.socket virtnetworkd.socket virtstoraged.socket virtnwfilterd.socket
   ```

   On older distributions with the classic monolithic daemon, use instead:

   ```sh
   sudo systemctl enable --now libvirtd
   ```

   If you get `Unit file libvirtd.service does not exist`, your system uses the
   modular daemons above. Verify libvirt is reachable with
   `virsh -c qemu:///system version`.

3. **Configure** the gateway by editing the config file (every setting is
   documented inline; see [Configuration](#configuration)):

   ```sh
   sudo nano /etc/devbox-gateway/devbox-gateway.conf
   ```

4. **Enable and start** the service (installation does not start it
   automatically):

   ```sh
   sudo systemctl enable --now devbox-gateway
   ```

5. **Check status and logs**:

   ```sh
   systemctl status devbox-gateway
   journalctl -u devbox-gateway -f
   ```

To upgrade, install the newer RPM (`sudo dnf upgrade ./devbox-gateway-*.rpm`);
your config file is preserved and the service is restarted automatically. To
remove it: `sudo dnf remove devbox-gateway`.

> Building the RPM yourself instead of downloading it is covered under
> [Building from source](#building-from-source).

## Installing the deb

For a native deployment on Debian 12 (amd64), each tagged release also publishes
a `devbox-gateway_<version>_amd64.deb` artifact on the
[GitHub Releases](https://github.com/define42/devbox-gateway/releases) page,
built and installation-tested against Debian 12 (Bookworm). It uses the same
source version as the RPM and container, with a separate binary linked against
Debian 12 libraries. Other Debian-based distributions are not part of the
native compatibility baseline.

The package installs its binary, unit, and config; the service creates the
audit file at runtime:

| Path                                            | Purpose                                              |
|-------------------------------------------------|------------------------------------------------------|
| `/usr/bin/devbox-gateway`                     | The gateway binary.                                  |
| `/lib/systemd/system/devbox-gateway.service`  | systemd unit (runs as root, binds `:443`).           |
| `/etc/devbox-gateway/devbox-gateway.conf`     | Config file (installed `0640 root:root` as it may hold credential digests), registered as a `conffile` so your edits survive upgrades. |
| `/var/log/devbox-gateway/audit.jsonl`          | Append-only JSON Lines audit log, created when the gateway starts. |

It depends on `libvirt0`, `ca-certificates`, `libvirt-daemon-system`,
`libvirt-daemon-config-nwfilter`, `iptables`, and `qemu-system-x86`. On Debian
releases with split drivers, the nwfilter config package pulls in
`libvirt-daemon-driver-nwfilter`; older releases include that driver in the
main daemon. `iptables` supplies the ebtables frontend needed for guest traffic
enforcement. Minimum shared-library package versions, including `libvirt0` and
`libc6`, are generated from the binary by `dpkg-shlibdeps`, so `apt` rejects an
installation when the available libraries cannot load it.

1. **Install** (let `apt` pull in the dependencies):

   ```sh
   sudo apt install ./devbox-gateway_<version>_amd64.deb
   ```

2. Then follow the same steps as the RPM install above — satisfy the libvirt/KVM
   runtime prerequisites, edit `/etc/devbox-gateway/devbox-gateway.conf`, and
   `sudo systemctl enable --now devbox-gateway`. Installation enables the unit
   per systemd preset policy but does not start it; an upgrade preserves your
   config and restarts the service.

## Installing SauronAgent

[SauronAgent](SauronAgent/README.md) streams Linux audit events from inside the
guest VMs to the hypervisor over virtio-vsock. Each tagged release also publishes
a `sauronagent-<version>-1.x86_64.rpm` and a `sauronagent_<version>_amd64.deb`
built from [`SauronAgent/`](SauronAgent), with the same version as the gateway
packages (the version is also compiled into the binaries, so a guest reports the
release it runs).

One package carries both components, laid out like SauronAgent's own
`make install PREFIX=/usr`. Install it on the hypervisor and in each guest, then
enable the component that machine runs:

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
The guest agent enables kernel auditing and installs its execution rules when
it starts. No audit rules file, `auditd`, or audit tools are needed.

On a DevBox Gateway host the gateway itself is the collector: set
`SAURON_ENABLE=true` (see [SauronAgent guest events](#sauronagent-guest-events))
and leave `sauronhost` disabled — the two would compete for the same vsock port.
The gateway gives every new VM its vsock device and maps each connection to its
VM from libvirt, so there is no `vms:` CID map to maintain. The standalone
`sauronhost` is for hypervisors that do not run the gateway.

Inside the guests — typically baked into the base images — install the package
and enable the agent. It needs no configuration file: its built-in defaults
already dial the host (CID 2) on port 9000:

```sh
sudo dnf install ./sauronagent-<version>-1.x86_64.rpm    # or: sudo apt install ./sauronagent_<version>_amd64.deb
sudo systemctl enable --now sauronagent
```

Starting the agent automatically enables `execve`/`execveat` auditing, including
64-bit and 32-bit process execution on x86_64 guests, so commands such as `nmap`
produce execution events. The agent checks and applies the rules on every
start, including after reboot. It preserves unrelated rules and reports a
startup error if an immutable or conflicting policy prevents setup. See the
[SauronAgent deployment guide](SauronAgent/docs/deployment.md#guest-audit-rules)
for externally managed policy and optional broader coverage.

To remove it: `sudo apt remove devbox-gateway` (add `--purge` to also delete the
config file).

> Building the deb yourself instead of downloading it is covered under
> [Building from source](#building-from-source).

## Login flow

Open `https://localhost` in a browser. If the gateway generated a self-signed
certificate (the default for local runs without `CERT_FILE` / `KEY_FILE`), the
browser will warn — choose **Advanced** → **Proceed to localhost (unsafe)**.

Sign in with the seeded test account:

- username: `johndoe`
- password: `dogood`

A successful login redirects to `/api/dashboard`, where you can:

- Create a new VM (name, base image, guest username). The guest account is
  provisioned with the password you logged in to the gateway with: only its
  salted sha512_crypt hash is kept in the in-memory session at login and
  embedded in the VM's cloud-init seed — the cleartext is never stored. Every
  VM gets the operator-configured CPU and memory (`VM_VCPU_COUNT` /
  `VM_MEMORY_MIB`); users cannot pick or change them.
- Start / restart / shutdown / remove existing VMs that you own.
- Open a serial console or noVNC session in the browser.
- Download an `.rdp` file (named after the VM, e.g. `alice-desktop.rdp`)
  preconfigured for the gateway.

The same `johndoe` / `dogood` credentials are exercised by the LDAP
integration tests, so they are also the recommended local smoke-test account.
To exercise the administrator inventory in the Docker Compose environment, use
the seeded `admin` / `dogood` account; it belongs to the `devbox-admins` group
configured through `ADMIN_GROUP`.

## Connecting an RDP client

Always connect by downloading the per-VM `.rdp` file from the dashboard — do
**not** try to point a client at the gateway by hand. Click the VM's **RDP**
button to get a ready-to-use file (named after the VM, e.g.
`alice-desktop.rdp`) and open it in any standard RDP client (mstsc, FreeRDP,
Remmina, …). The file already targets the gateway on port `443` with the
correct server name and TLS settings; there is nothing to configure manually.

**The download is single-use and expires in 2 minutes.** Clicking **RDP** is
both the download action *and* an explicit authorization: it asks the gateway
to admit a **single** RDP connection for that VM from your current IP, valid for
at most **2 minutes**, then hands you the file. Open it in your RDP client
within that window. The grant is **single-use and consumed at connection
time** — a standing dashboard login no longer implicitly authorizes RDP — so
**any reconnect, or even a first attempt that fails before the session is up,
requires clicking RDP again** to re-authorize and download a fresh file.

You cannot build the connection by hand because the **server name** in the
`.rdp` file is an opaque routing label of the form `<label>.<FRONT_DOMAIN>`
(for example `a1b2c3d4….desktop.local.gd`). The label is
`HMAC-SHA256(SNI_HASH_SECRET, vmName)` truncated to a DNS-safe length, so the VM
name (which embeds the username) is never sent in cleartext in the TLS
ClientHello, and because it is one-way and keyed you cannot construct it
yourself. (DNS is unaffected: a wildcard `*.<FRONT_DOMAIN>` record still points
every label at the gateway.)

The gateway requires TLS-protected RDP (`PROTOCOL_SSL`); clients and backends
that only offer the legacy Standard RDP Security will be rejected. Backend TLS
connections require TLS 1.2 or newer.

## Configuration

All runtime configuration is registered in
[`internal/config/config.go`](internal/config/config.go). On start-up the
gateway loads a config file, then applies any matching environment variables on
top, and prints a table of every setting and its effective value.

**Config file.** The gateway reads a `KEY=VALUE` config file on start-up
(default `/etc/devbox-gateway/devbox-gateway.conf`, overridable with the
`CONFIG_FILE` environment variable). Blank lines and `#` comments are ignored,
an optional leading `export` is stripped, and values may be wrapped in single or
double quotes. A missing file is not an error — the gateway then runs purely on
environment variables and built-in defaults. The RPM ships a fully commented
template at this path. Each key below is both a config-file key and an
environment variable; **an explicit environment variable always overrides the
file**, which keeps container and development overrides working.

| Variable                  | Default                                                                                                          | Description                                                                                       |
|---------------------------|------------------------------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------|
| `LISTEN_ADDR`             | `:443`                                                                                                           | Address the gateway listens on (HTTPS + RDP multiplexed).                                         |
| `RDP_PORT`                | _(empty)_ | Public TCP port advertised in downloaded `.rdp` files. Empty follows the port in `LISTEN_ADDR` (443 for an ephemeral listener). Set a value from 1 to 65535 when a proxy or port mapping exposes a different port; for example, `LISTEN_ADDR=:8443` with `RDP_PORT=443`. |
| `PPROF_LISTEN_ADDR`       | _(empty)_                                                                                                        | Optional separate Go runtime-profiler listener. The host must be a literal loopback IP (for example `127.0.0.1:6060` or `[::1]:6060`); wildcard, hostname, and non-loopback binds are rejected. pprof is never registered on the public `LISTEN_ADDR` handler. |
| `TIMEOUT`                 | `10s`                                                                                                            | Handshake / dial / read timeout for connection setup and HTTP response writes. Long-running creation/upload responses renew the write deadline for each write; HTTP writes use 10s when this setting is non-positive. |
| `CERT_FILE`               | _(empty)_                                                                                                        | PEM-encoded TLS certificate for the front side. Empty → self-signed cert is generated.            |
| `KEY_FILE`                | _(empty)_                                                                                                        | PEM-encoded unencrypted private key matching `CERT_FILE`.                                         |
| `ACME_ENABLE`             | `false`                                                                                                          | Enable ACME (Let's Encrypt) certificate management via certmagic on the front side.               |
| `ACME_EMAIL`              | _(empty)_                                                                                                        | ACME account contact email (recommended when `ACME_ENABLE=true`).                                 |
| `ACME_CA`                 | _(empty)_                                                                                                        | ACME directory URL, or `staging` for the Let's Encrypt staging endpoint.                          |
| `FRONT_DOMAIN`            | `desktop.local.gd`                                                                                               | Domain served by the dashboard and used as the suffix for VM SNI routing labels.                  |
| `SNI_HASH_SECRET`         | _(empty)_                                                                                                        | Secret keying the HMAC that turns VM names into opaque SNI labels. Empty → auto-generated once and persisted to `<DATA_ROOT_DIR>/sni_hash.secret` so labels stay stable across restarts. |
| `AUDIT_LOG_FILE`          | `/var/log/devbox-gateway/audit.jsonl`                                                                            | Append-only audit destination. Every event is one complete JSON object followed by a newline, suitable for Splunk file monitoring. The Docker Compose setup overrides this to `/data/logs/audit.jsonl`. |
| `SPLUNK_HEC_ENDPOINT`     | _(empty)_                                                                                                        | Splunk HTTP Event Collector URL that also receives every audit event, e.g. `https://splunk.example.com:8088`. A URL without a path uses `/services/collector/event`. Empty disables HEC forwarding. See [Forwarding to Splunk HEC](#forwarding-to-splunk-hec). |
| `SPLUNK_HEC_TOKEN`        | _(empty)_                                                                                                        | HEC token. Required when `SPLUNK_HEC_ENDPOINT` is set. Masked in the startup settings table.      |
| `SPLUNK_HEC_INDEX`        | _(empty)_                                                                                                        | Destination index for forwarded events. Empty → the token's default index.                       |
| `SPLUNK_HEC_SKIP_TLS_VERIFY` | `false`                                                                                                       | When `true`, skip TLS certificate verification against the HEC endpoint.                          |
| `SAURON_ENABLE`           | `false`                                                                                                          | Collect SauronAgent guest audit events: new VMs get a virtio-vsock device and the gateway accepts the agents over AF_VSOCK. See [SauronAgent guest events](#sauronagent-guest-events). |
| `SAURON_VSOCK_PORT`       | `9000`                                                                                                           | AF_VSOCK port the agents dial on the host (CID 2). Must match the agents' configuration.          |
| `SAURON_EVENT_LOG_FILE`   | `/var/log/devbox-gateway/sauron.jsonl`                                                                           | JSON Lines file receiving every guest event, rotated at 256 MiB with 8 files kept. Empty disables it, which then requires `SAURON_SPLUNK_HEC_ENDPOINT`. |
| `SAURON_SPLUNK_HEC_ENDPOINT` | _(empty)_                                                                                                     | Splunk HTTP Event Collector URL that also receives every guest event, delivered from the gateway's spool. A URL without a path uses `/services/collector/event`. Empty disables HEC forwarding. |
| `SAURON_SPLUNK_HEC_TOKEN` | _(empty)_                                                                                                        | HEC token for guest events. Required when `SAURON_SPLUNK_HEC_ENDPOINT` is set. Masked in the startup settings table. |
| `SAURON_SPLUNK_HEC_INDEX` | _(empty)_                                                                                                        | Destination index for guest events. Empty → the token's default index.                           |
| `SAURON_SPLUNK_HEC_SKIP_TLS_VERIFY` | `false`                                                                                                | When `true`, skip TLS certificate verification against `SAURON_SPLUNK_HEC_ENDPOINT`.              |
| `SAURON_SPOOL_DIR`        | _(empty → `<DATA_ROOT_DIR>/sauron-spool`)_                                                                       | Where guest events wait, durably and across gateway restarts, until Splunk HEC accepts them.      |
| `SAURON_SPOOL_MAX_MIB`    | `10240`                                                                                                          | Disk space the spool may use. Size it for the longest Splunk outage to ride out. `<=0` → the default. |
| `DATA_ROOT_DIR`           | `/var/lib/libvirt/devbox-gateway`                                                                               | Root directory for gateway-managed state (ACME data, images, serial sockets, VNC sockets). Under `/var/lib/libvirt` so QEMU can use it under SELinux. The bundled `docker-compose.yml` overrides this to `/data`. |
| `VIRT_STORAGE_POOL_NAME`  | `desktop`                                                                                                        | Libvirt storage pool to allocate VM volumes in.                                                   |
| `BASE_IMAGE_DIR`          | _(empty → `<DATA_ROOT_DIR>/baseimages`)_                                                                          | Directory of selectable QCOW2 base VDI images named `.img`, `.qcow2`, or `.raw`. Users pick one per VM in the dashboard. The gateway refuses to start if it contains no valid QCOW2 image. |
| `MAX_VDI_PER_USER`        | `10`                                                                                                             | Maximum number of VDIs (VMs) each user may own at once. Creating another VM is refused once the user owns this many. Set `<=0` to disable the per-user limit. |
| `VDI_AUTO_SHUTDOWN_HOURS` | `0`                                                                                                              | Shut down a running VDI after this many hours without use. Creation, start, and opening RDP, serial, or noVNC count as use. Open connections through the gateway prevent auto-shutdown, even without keyboard or mouse input; the full idle window starts when the last connection ends. Last use is persisted on connection changes and checkpointed each minute while connected so recent activity survives gateway restarts. Connections bypassing the gateway are not tracked. The guest is first asked to power off (ACPI power button) and is force-stopped if still running 5 minutes later. Set `<=0` to disable auto-shutdown (the default). |
| `VM_VCPU_COUNT`           | `4`                                                                                                              | Number of virtual CPUs assigned to every VM. Users cannot choose or change this per VM. Set `<=0` to fall back to the default. |
| `VM_MEMORY_MIB`           | `4096`                                                                                                           | Memory in MiB assigned to every VM. Users cannot choose or change this per VM. Set `<=0` to fall back to the default. |
| `LDAP_URL`                | `ldaps://ldap:389`                                                                                               | Required LDAP server URL. The gateway refuses to start when empty.                                |
| `LDAP_AUTH_TIMEOUT`       | `10s` | Maximum total time for LDAP connection setup, TLS, bind, and search. Request cancellation also aborts authentication. Values `<=0` use the default. |
| `LDAP_BASE_DN`            | `dc=glauth,dc=com`                                                                                               | LDAP search base.                                                                                 |
| `LDAP_USER_FILTER`        | `(mail=%s)`                                                                                                      | LDAP search filter; `%s` is replaced with `<username>@LDAP_USER_DOMAIN`.                          |
| `LDAP_USER_DOMAIN`        | `@example.com`                                                                                                   | Domain appended to bare usernames before they are substituted into `LDAP_USER_FILTER`.            |
| `LDAP_REQUIRED_GROUPS`    | _(empty)_                                                                                                        | Groups a user must belong to (any one of them) for LDAP login. Bare group names may be `,`- or `;`-delimited; full group DNs must be `;`-delimited because DNs contain commas. Matched case-insensitively against the user's `memberOf` attribute (full DN or its first RDN value). Empty allows every authenticated user. |
| `ADMIN_GROUP`             | _(empty)_                                                                                                        | Single LDAP group whose direct members receive administrator access at login. Accepts a bare name or full DN and matches `memberOf` case-insensitively. Empty disables administrator access. |
| `LDAP_STARTTLS`           | `false`                                                                                                          | When `true`, upgrade plain LDAP connections with StartTLS.                                        |
| `LDAP_SKIP_TLS_VERIFY`    | `false`                                                                                                          | When `true`, skip TLS certificate verification against the LDAP server.                           |
| `LOGIN_RATE_LIMIT_MAX_ATTEMPTS` | `5`                                                                                                      | Maximum failed attempts per username-and-client-IP pair within `LOGIN_RATE_LIMIT_WINDOW`. Set `<=0` to disable login throttling. |
| `LOGIN_RATE_LIMIT_IP_MAX_ATTEMPTS` | `50`                                                                                                  | Higher password-spray limit across all usernames from one client IP. Set `<=0` to disable only the IP-wide limit. |
| `LOGIN_RATE_LIMIT_WINDOW` | `5m`                                                                                                             | Rolling window for failed login attempt counting.                                                 |
| `LOGIN_RATE_LIMIT_LOCKOUT` | `15m`                                                                                                           | How long matching login attempts are rejected after either failure limit is reached.              |
| `DEBUG_CONNECTIONS`       | `false`                                                                                                          | When `true`, log every accepted front connection (HTTPS vs RDP, with source address) and every HTTP/WebSocket request (type, source address, method, path). Useful for tracing connectivity; noisy, so leave off in normal operation. |

Booleans accept anything `strconv.ParseBool` recognises (`true`, `false`,
`1`, `0`, `yes`, `no`, …). Durations accept Go's `time.ParseDuration`
syntax (e.g. `15s`, `2m`, `500ms`).

### Audit logs and Splunk

Security-relevant activity is appended to `AUDIT_LOG_FILE` as JSON Lines
(NDJSON): each physical line is an independently parseable JSON event. The
native packages default to `/var/log/devbox-gateway/audit.jsonl`; systemd
creates its parent directory before starting the gateway. Docker Compose writes
the same stream to `/data/logs/audit.jsonl`, which is visible at that path on
the host through the existing `/data` bind mount.

Configure the Splunk Universal Forwarder with a file monitor for the selected
path and set the source type to `_json`. For example:

```ini
[monitor:///var/log/devbox-gateway/audit.jsonl]
disabled = false
sourcetype = _json
index = main
```

The audit file is deliberately not a credential store, but it contains user,
source-address, VM, resource, result, protocol, and duration metadata. Keep it
access-controlled. If the forwarder runs as a dedicated `splunk` user, grant
that account read/traverse access after the service has created the path:

```sh
sudo setfacl -m u:splunk:rx /var/log/devbox-gateway
sudo setfacl -m u:splunk:r /var/log/devbox-gateway/audit.jsonl
```

Ordinary process diagnostics remain available through `journalctl` (or Docker
logs); `AUDIT_LOG_FILE` is the dedicated security-event stream.

#### Forwarding to Splunk HEC

As an alternative to a Universal Forwarder, the gateway can send every audit
event directly to a Splunk HTTP Event Collector. Set the endpoint and token
(and optionally the index):

```ini
SPLUNK_HEC_ENDPOINT=https://splunk.example.com:8088
SPLUNK_HEC_TOKEN=11111111-2222-3333-4444-555555555555
SPLUNK_HEC_INDEX=devbox_audit
```

- `AUDIT_LOG_FILE` is still written; HEC is an additional destination, so the
  local file remains the complete record if Splunk is unreachable.
- Each event arrives on the JSON event endpoint with `source=devbox-gateway`,
  `sourcetype=devbox-gateway:audit`, the gateway's hostname as `host`, and the
  same JSON object that is written to the file as the event body. The token
  must be allowed to write to `SPLUNK_HEC_INDEX`, and must have indexer
  acknowledgement disabled (otherwise Splunk rejects every request with
  "Data channel is missing").
- Configure the collector's direct URL: redirects are not followed. Delivery
  succeeds only when a `2xx` response contains valid HEC JSON with `code: 0`.
  Redirects, incomplete or invalid responses, and nonzero codes in `2xx`
  responses are retried without discarding the batch.
- Delivery happens in the background and never slows down or fails a user
  action. Events are batched, and network errors, `5xx`, `429`, `401`, and
  `403` responses are retried with backoff (up to 30s between attempts). Other
  `4xx` responses drop that batch. Up to 10,000 events are held in memory while
  the collector is unavailable; beyond that, new events are dropped. Drops and
  failures are reported in the process log (`journalctl` / Docker logs).
- On shutdown the gateway waits up to 5s for queued events to be delivered.
- The gateway refuses to start when `SPLUNK_HEC_ENDPOINT` is set without
  `SPLUNK_HEC_TOKEN`, or when a token or index is set without an endpoint.
- Splunk's default HEC certificate is self-signed. Prefer installing the CA
  that signed it into the host (or container) trust store; set
  `SPLUNK_HEC_SKIP_TLS_VERIFY=true` only as a stopgap. A plain `http://`
  endpoint is accepted but sends the token unencrypted and logs a warning.

A search such as `index=devbox_audit sourcetype="devbox-gateway:audit"
action=user.login result=failure` then works without any additional props
configuration: Splunk extracts the JSON fields at search time.

### SauronAgent guest events

[SauronAgent](SauronAgent/README.md), running inside the VMs, reads the guest
kernel's audit stream (process executions, logins, privilege changes, audit and
firewall configuration changes, …) and streams it to the hypervisor over
virtio-vsock — no guest networking involved. With `SAURON_ENABLE=true` the
gateway embeds SauronAgent's host collector and receives those events itself:

```ini
SAURON_ENABLE=true
SAURON_SPLUNK_HEC_ENDPOINT=https://splunk.example.com:8088
SAURON_SPLUNK_HEC_TOKEN=11111111-2222-3333-4444-555555555555
SAURON_SPLUNK_HEC_INDEX=devbox_sauron
```

- Every VM created from then on gets a virtio-vsock device, for which libvirt
  picks a CID that is unique among the running domains. VMs created while the
  setting was off have no such device; recreate them to collect their events.
- The gateway listens on AF_VSOCK port `SAURON_VSOCK_PORT` and attributes each
  connection to the running VM libvirt assigned its CID to. The CID is set by the
  hypervisor, so a guest cannot pass its events off as another VM's; what the
  guest says about itself (hostname, machine-id, …) is recorded under
  `source.reported` and never used for attribution.
- Each event is written as a collector envelope: the gateway's receive time
  (`received_at`), the trusted `source` (`vm`, `uuid`, `cid`, `host`, and
  `labels.owner` — the gateway user who owns the VM), and the guest's normalized
  `event` unchanged. The collector's own `sauron.*` events (protocol violations,
  sequence gaps, refused connections, output failures) go to the same stream.
- Events go to `SAURON_EVENT_LOG_FILE` and, when configured, to Splunk HEC, using
  their own endpoint, token, and index so guest telemetry can land in a different
  index than the gateway audit log. In Splunk they arrive with
  `source=sauronagent`, `sourcetype=devbox-gateway:sauron`, the VM name as
  `host`, and the gateway's receive time as `_time` (a guest controls its own
  clock; its timestamp stays in `event.timestamp`).
- Delivery to Splunk is store and forward. The gateway acknowledges an event to
  its guest — which then deletes its own copy — as soon as the event is written
  and fsynced to the gateway's spool (`SAURON_SPOOL_DIR`). A guest never waits
  for Splunk, and a VM deleted while Splunk is down loses nothing. A background
  forwarder delivers the spool to Splunk in order, in batches, retrying with
  backoff (at most 30s apart) for however long Splunk is unreachable — days if
  need be — and resumes from its checkpoint after a gateway restart. A long
  outage is reported in the process log every 5 minutes with the spool's size.
- The spool is bounded by `SAURON_SPOOL_MAX_MIB` (10 GiB by default). Should an
  outage outlast it, the gateway stops acknowledging new events rather than
  discarding any: they then wait in the guests' own spools (1 GiB each by
  default) until the backlog drains.
- Delivery is at-least-once. After a crash or restart, events that were
  delivered just before it can reach Splunk twice. An event Splunk rejects as
  invalid on its own (HEC codes 6, 12, 13, 15, or too large) is dropped with a
  log line, so it cannot block the backlog; every other refusal — an index the
  token may not write to, an unhealthy or unreachable Splunk — keeps the events
  spooled. Redirects and unconfirmed `2xx` replies keep the checkpoint unchanged;
  successful delivery requires HEC JSON with `code: 0`. The same HEC token
  requirement applies as above: indexer acknowledgement must be disabled.
- The gateway refuses to start when `SAURON_SPLUNK_HEC_*` is set without
  `SAURON_ENABLE=true`, when the endpoint lacks a token (or a token or index
  lacks an endpoint), or when neither the file nor HEC is configured. It also
  refuses to start when it cannot open the vsock listener: the host needs the
  `vhost_vsock` kernel module, and must not run `sauronhost` on the same port.
  The shipped systemd unit allows the `AF_VSOCK` socket family; in Docker, see
  the seccomp note under [Quick start](#quick-start-docker-compose).
- The collector's stream-loss alert (`sauron.stream.lost`) only watches VMs
  listed in a static `sauronhost` configuration, so it is not active for the
  gateway's VMs: a VM whose agent is stopped or was never installed is not
  reported.

For example, `index=devbox_sauron sourcetype="devbox-gateway:sauron"
event.type=process.exec source.labels.owner=alice` lists every program alice's
VMs ran.

### TLS certificates

There are three supported modes for the front-side certificate:

1. **Self-signed (default for local dev).** Leave `CERT_FILE`, `KEY_FILE` and
   `ACME_ENABLE` empty. A self-signed certificate is generated in-memory on
   start.
2. **Static PEM files.** Set `CERT_FILE` and `KEY_FILE` to readable PEM files
   inside the container/process.
3. **ACME.** Set `ACME_ENABLE=true`, set `FRONT_DOMAIN` to the public hostname,
   and set `ACME_EMAIL`. Optionally set `ACME_CA=staging` while testing. ACME
   state is persisted under `$DATA_ROOT_DIR/acme`.

Each new VM receives a unique backend certificate and private key through its
cloud-init seed ISO. Libvirt metadata stores the public certificate, its internal
server name, and the domain UUID. The gateway validates certificate trust,
server name, validity, and the exact leaf certificate before forwarding RDP
traffic. The public routing SNI is separate from this backend identity. Backend
TLS session resumption is disabled so every connection verifies the current
provisioned identity. Certificates are valid for ten years; recreating a VM
generates a new key and certificate.

The seed configures xrdp to use `/etc/xrdp/devbox-cert.pem` and
`/etc/xrdp/devbox-key.pem`; the key is installed as `0640 root:xrdp`. Base images
must include cloud-init, Python 3, xrdp with its `xrdp` group, and a working
`xrdp.service`. Provisioning forces TLS 1.2 or newer and restarts xrdp. A missing
identity or a guest that presents a different certificate is rejected without
forwarding client credentials. See [Libvirt and VM storage](#libvirt-and-vm-storage)
for the required network isolation and the recreation policy for older VMs.

### LDAP

For local development, the bundled `glauth` container is configured in
`testldap/default-config.cfg` and is reachable from the gateway container at
`ldaps://127.0.0.1:389` (a host-loopback published port). For production, point
`LDAP_URL` at your own directory and adjust `LDAP_BASE_DN`, `LDAP_USER_FILTER`,
and `LDAP_USER_DOMAIN` to match.
Prefer `ldaps://` or `LDAP_STARTTLS=true`. Certificate verification is on by
default; only set `LDAP_SKIP_TLS_VERIFY=true` as a stopgap for a directory
whose CA chain is not yet trusted (the bundled glauth container uses a
self-signed certificate, which is why the Docker Compose dev setup sets it).

To restrict login to members of specific directory groups, set
`LDAP_REQUIRED_GROUPS`. A user is allowed when their `memberOf` attribute
contains **at least one** of the listed groups; when the variable is empty,
every user found by `LDAP_USER_FILTER` may log in. Entries can be bare group
names or full group DNs:

```bash
# Bare names, ','- or ';'-delimited — matched against the group DN's first RDN
# value (e.g. the cn), case-insensitively:
LDAP_REQUIRED_GROUPS="vdi-users, admins"

# Full DNs contain commas, so they must be ';'-delimited:
LDAP_REQUIRED_GROUPS="cn=vdi-users,ou=groups,dc=example,dc=com;cn=admins,ou=groups,dc=example,dc=com"
```

When `LDAP_REQUIRED_GROUPS` is set, the login page shows an informational box
below the sign-in form listing the groups that give access (full DNs are
shortened to their first RDN value, e.g. the `cn`).

To grant administrator access, set `ADMIN_GROUP` to exactly one bare group name
or full group DN. This grants a role only: the user must still pass the normal
LDAP login checks, including `LDAP_REQUIRED_GROUPS` when configured. The role is
determined from `memberOf` at login and retained for that session, so directory
membership changes take effect after the user logs in again or the current
session expires.

Administrators get an **Admin** button on their dashboard. It opens an inventory
of every persistent VM known to the gateway, grouped by its recorded owner. VMs
without owner metadata appear under **Unowned**. Administrators can start, stop,
restart, and remove any VM in this inventory, including **Unowned** entries.
RDP, serial-console, and noVNC access to another user's VM remain owner-only.
The administrator page also has a **Base Images** button. Its modal lists the
current image library and lets administrators upload QCOW2 images named `.img`,
`.qcow2`, or `.raw` and delete existing images. Uploads are streamed, validated
using the QCOW2 magic header, never overwrite a file with the same name, and are
limited to the configured `VM_DISK_SIZE_GB` capacity. The modal also shows the
filesystem space currently available in the configured base-image directory.

Both access and administrator group checks use direct membership only — nested
group membership is not resolved, so the group must appear directly in the
user's `memberOf`. Directories where `memberOf` is an operational attribute
(e.g. OpenLDAP's `memberof` overlay) are supported; the gateway requests the
attribute explicitly.

### Libvirt and VM storage

The dashboard manages VMs through libvirt. The gateway expects:

- A libvirt socket bind-mounted at `/var/run/libvirt` (already wired up in
  `docker-compose.yml`).
- A storage pool named by `VIRT_STORAGE_POOL_NAME` (default `desktop`) backed
  by `$DATA_ROOT_DIR/image` on the host. The gateway defines and starts this
  pool automatically if it is missing.
- The dedicated libvirt `devbox` NAT network (`virbr-devbox`,
  `192.168.123.0/24`, host gateway `192.168.123.1`). The gateway defines, starts,
  and enables autostart for it. Reserve this subnet for the gateway and attach
  only gateway-managed VMs to this bridge.
- A base image library directory (`BASE_IMAGE_DIR`, default
  `$DATA_ROOT_DIR/baseimages`) containing at least one QCOW2 disk image named
  `.img`, `.qcow2`, or `.raw`.
- Host-side libvirt network filtering. The gateway installs the mandatory
  `devbox-isolated-ipv4` filter and supplies a fixed, persisted MAC/IPv4 binding
  for every VM. DHCP reservations match these assignments; addresses are never
  learned from guest traffic. The filter rejects forged MAC/IP/ARP identities,
  guest DHCP servers, guest-to-guest IPv4 traffic, IPv6, VLAN tags, and unsupported
  Ethernet protocols. Bridge port isolation remains enabled as an extra layer.
- Network reachability from the gateway to the VM bridge. Docker Compose uses
  host networking, so the gateway reaches `virbr-devbox` directly. LDAP and
  Splunk HEC use their host-loopback published ports.

The gateway fails closed if the required network configuration, filter, or VM
identity is unavailable or inconsistent. **Recreate VMs created before this
protection was introduced.** There is no migration or insecure fallback for old
VM definitions, dynamic address assignments, or unprovisioned RDP certificates.
Recreation deletes a VM's disk through the normal dashboard removal flow, so
copy any development files you want to keep before removing it. Existing
unrelated libvirt networks are not adopted as the gateway network.

Base images can be supplied by placing QCOW2 images in `BASE_IMAGE_DIR` or by
uploading them from the administrator's **Base Images** modal. The filename may
end in `.img`, `.qcow2`, or `.raw`; content is accepted only when its first four
bytes match the QCOW2 magic header (`51 46 49 fb`). The dashboard create form
lets each user pick which image to clone for a new VM. **If the directory
contains no valid QCOW2 image at startup, the gateway fails to boot** with a
clear error, so populate it first. An administrator can delete the final image
at runtime, but VM creation then remains unavailable and another image must be
uploaded before the gateway can restart successfully.

Before the first run, populate the library, for example (Docker Compose, which
uses `/data`):

```sh
mkdir -p /data/baseimages
curl -L -o /data/baseimages/resolute-desktop-cloudimg-amd64-v0.0.9.img \
  https://github.com/define42/ubuntu-resolute-desktop-cloud-image/releases/download/v0.0.9/resolute-desktop-cloudimg-amd64-v0.0.9.img
```

Because `docker-compose.yml` already bind-mounts `/data/`, files dropped in
`/data/baseimages` on the host are visible to the gateway container.

For a native (RPM) install the data root defaults to
`/var/lib/libvirt/devbox-gateway`, so populate
`/var/lib/libvirt/devbox-gateway/baseimages` instead (or set `DATA_ROOT_DIR` /
`BASE_IMAGE_DIR` to wherever you keep images).

## Building from source

Requirements for a local development binary:

- Go (see `go.mod` for the minimum version).
- A C toolchain and `libvirt-dev` headers (the binary is built with
  `CGO_ENABLED=1`).
- Node.js + TypeScript 5.5.4 for the dashboard bundle.

Build the dashboard bundle and the binary locally:

```sh
tsc -p tsconfig.json          # compile ui/dashboard.ts → internal/webassets/dashboard.js
CGO_ENABLED=1 go build -o devbox-gateway ./cmd/devbox-gateway
```

`make build` performs both steps and writes the binary to `dist/devbox-gateway`.
This binary links against the build host's libraries. Use the native package
targets below to build distributable packages against their supported baselines.

Or build the production container image:

```sh
docker compose build
```

The multi-stage `Dockerfile` compiles the TypeScript UI and the Go binary in a
`golang:1.26-alpine` builder (pinned via the `GO_VERSION` build arg) and ships
only the resulting binary plus `libvirt-libs` and `ca-certificates` in the
runtime image.

### Building the RPM

Gateway native package builds require Docker with Buildx on the host. Go, the
C toolchain, libvirt headers, and TypeScript 5.5.4 run inside
[`Dockerfile.native`](Dockerfile.native); the Go version comes from `go.mod`.
Both package formats currently support Linux amd64 only (`ARCH=x86_64` and
`DEB_ARCH=amd64`). Other architecture overrides are rejected.

To produce the same RPM the [release workflow](#installing-the-rpm) publishes,
run (overriding `VERSION` as needed):

```sh
make rpm VERSION=1.4.0
```

This compiles the UI and a `CGO_ENABLED=1` binary against Rocky Linux 9's
libraries, then packages it together with the systemd unit and
`devbox-gateway.conf` into `dist/devbox-gateway-<version>-1.x86_64.rpm`. The
[`cmd/mkrpm`](cmd/mkrpm) command uses RPM's `elfdeps` scanner to declare the
binary's actual ABI requirements and the pure-Go [`internal/rpm`](internal/rpm)
writer to create the archive. The container build installs the package with
`dnf` and checks dynamic linking and process startup before exporting it.

### Building the deb

To produce the same `.deb` the [release workflow](#installing-the-deb) publishes,
run (overriding `VERSION` as needed):

```sh
make deb VERSION=1.4.0
```

This builds a separate binary against Debian 12's libraries and writes
`dist/devbox-gateway_<version>_amd64.deb`. The [`cmd/mkdeb`](cmd/mkdeb) command
uses `dpkg-shlibdeps` to derive minimum library package versions and the
pure-Go [`internal/deb`](internal/deb) writer to create the archive. The
container build installs the package with `apt` and checks dynamic linking and
process startup before exporting it. Neither native package target reuses a
binary built on the host. CI runs both builds for pull requests and releases.

### Building the SauronAgent packages

To produce the same SauronAgent packages the
[release workflow](#installing-sauronagent) publishes, run (overriding `VERSION`
as needed):

```sh
make sauron-rpm VERSION=1.4.0
make sauron-deb VERSION=1.4.0
```

This builds the static `sauronagent` and `sauronhost` binaries with
SauronAgent's own Makefile into separate directories under `SauronAgent/bin/`
for each package format and architecture, then packages them into
`dist/sauronagent-<version>-1.x86_64.rpm` / `dist/sauronagent_<version>_amd64.deb`
through the [`cmd/mksauronagent`](cmd/mksauronagent) command, which reuses the
pure-Go `internal/rpm` and `internal/deb` writers. SauronAgent is a separate Go
module; the gateway also compiles in its host collector (package
`SauronAgent/collector`, through a `replace` directive in `go.mod`), so both need
Go 1.27.1 or newer. With an older local toolchain, prefix the commands with
`GOTOOLCHAIN=auto` as the release workflow does.

For ARM64, use `make sauron-rpm ARCH=aarch64` or
`make sauron-deb DEB_ARCH=arm64`. The package targets select the matching Go
architecture automatically. The packaging command checks both executable ELF
headers and rejects binaries that do not match the requested architecture.

### UI (TypeScript)

The dashboard UI source lives in `ui/dashboard.ts`. Rebuild the embedded asset
with:

```sh
tsc -p tsconfig.json
```

The compiled output is `internal/webassets/dashboard.js` and is embedded into the binary
via Go's `embed` package.

## Testing and linting

```sh
make test     # go test ./... with coverage; writes coverage.out and coverage.html
make lint     # run golangci-lint
make gosec    # run gosec security scanner
go test -race ./...
```

Some integration tests (e.g. `ldap_integration_test.go`,
`dashboard_vm_integration_test.go`) start temporary services via
`testcontainers-go`, so Docker needs to be available locally to run them.

## Repository layout

```
.
├── cmd/
│   ├── devbox-gateway/  Minimal gateway process entrypoint.
│   ├── mkdeb/           Debian packaging CLI adapter.
│   ├── mkrpm/           RPM packaging CLI adapter.
│   └── mksauronagent/   SauronAgent RPM/deb packaging CLI adapter.
├── internal/
│   ├── cert/        TLS certificate management (self-signed + ACME via certmagic).
│   ├── cloudinit/   NoCloud document and seed ISO generation.
│   ├── config/      Environment-backed settings registry (the only place env
│   │                vars may be read from).
│   ├── console/     Serial console and noVNC WebSocket handlers.
│   ├── dashboard/   Dashboard HTML / JSON rendering and VM listing.
│   ├── deb/         Debian package construction and archive writing.
│   ├── gateway/     Application lifecycle, HTTP handlers, TLS dispatch, and listeners.
│   ├── hash/        Password/credential hashing helpers.
│   ├── ldap/        LDAP login authentication.
│   ├── rdp/         RDP/X.224/MCS parsing, TLS-to-TLS proxy.
│   ├── rpm/         RPM package construction and manifests.
│   ├── sauron/      Embedded SauronAgent collector: vsock listener, event log, Splunk HEC sink.
│   ├── sauronpkg/   SauronAgent package manifest and maintainer scripts.
│   ├── session/     Cookie session manager and middleware.
│   ├── splunkhec/   Splunk HTTP Event Collector client shared by audit and sauron.
│   ├── types/       Shared types (e.g. authenticated user).
│   ├── virt/        Libvirt VM lifecycle (create/start/stop/remove/resize).
│   ├── vmname/      VM name construction and validation.
│   └── webassets/   Embedded static assets, including the compiled dashboard.js.
├── SauronAgent/     Guest audit agent and hypervisor collector (separate Go module;
│                    the gateway embeds its collector package).
├── ui/              TypeScript sources for the dashboard.
├── testldap/        glauth config + cert/key used for local LDAP.
├── testsplunk/      Post-setup task creating the local Splunk's audit and SauronAgent indexes.
└── Dockerfile, docker-compose.yml, Makefile, tsconfig.json
```

## Security notes

- Do **not** commit real certificates, private keys, production LDAP
  endpoints, or real Splunk HEC tokens. The files under `testldap/` and
  `testsplunk/`, and the Splunk credentials in `docker-compose.yml`, are
  intended for local development only.
- Every VM has a host-enforced MAC/IPv4 binding and a unique pinned backend
  certificate. Network filtering rejects guest spoofing; TLS verification
  independently rejects a redirected connection to the wrong VM. Root access
  to the hypervisor and its libvirt socket remains a trusted administrative
  boundary. Keep unrelated guests off the gateway's dedicated bridge.
- RDP access is gated by an explicit, single-use authorization rather than a
  standing login: the gateway admits a proxied RDP connection only when the VM's
  owner clicked **Connect** for that VM, from the same client IP, within the last
  2 minutes (see `rdpConnectWindow` in `internal/session`), and each Connect
  authorizes exactly one connection (the grant is consumed on use — see
  `ConsumeRDPConnectGrant`). The VM's own RDP login still applies on top. Note the
  grant is keyed to the source IP, so on a shared NAT egress another host behind
  that IP could spend the grant during the window (still facing the VM's RDP
  login). Because consumption happens at connection time, a connection that fails
  after authorization spends the grant, and reconnecting requires clicking
  Connect again.
- Logout is user-wide within the running gateway process: a valid `POST
  /logout` destroys all active browser sessions for that username and closes
  tracked live RDP, serial-console, and VNC WebSocket connections. External
  directory revocation without a gateway logout is still enforced only for new
  logins or new connection setup; already-open streams are not continuously
  re-checked against LDAP.
- All environment-backed parameters must be defined in
  `internal/config/config.go`. Reading `os.Getenv` directly from feature code
  is not allowed and is enforced by `make lint`.
- The gateway listens on `:443` only. There is no plaintext HTTP listener.

## License

DevBox-Gateway is released under the [MIT License](LICENSE). The `LICENSE`
file is bundled into the RPM (`/usr/share/licenses/devbox-gateway/LICENSE`)
and Debian (`/usr/share/doc/devbox-gateway/copyright`) packages.
