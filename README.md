# DevBox Gateway

[![codecov](https://codecov.io/gh/define42/devbox-gateway/graph/badge.svg?token=HS2KD8YHNG)](https://codecov.io/gh/define42/devbox-gateway)

`devbox-gateway` is a self-hosted gateway that publishes libvirt-managed virtual
desktops over a single HTTPS port. It combines three things on TCP `:443`:

1. An **RDP-over-TLS reverse proxy** that terminates TLS from the client, picks
   a backend VM using its RDP routing token, and re-establishes TLS to that
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

- [Quick start (Docker Compose)](#quick-start-docker-compose)
- [Installing the RPM](#installing-the-rpm)
- [Installing the deb](#installing-the-deb)
- [Installing SauronAgent](#installing-sauronagent)
- [Features](#features)
- [Architecture](#architecture)
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
- [HTTP endpoints and health checks](#http-endpoints-and-health-checks)
- [Security notes](#security-notes)
- [Contributing](#contributing)
- [License](#license)

---

## Quick start (Docker Compose)

Requirements on the host:

- Docker and Docker Compose v2.
- Linux with KVM available to QEMU and the `vhost_vsock` kernel module loaded.
  The gateway's embedded guest-event collector requires AF_VSOCK even before
  a guest agent connects.
- A libvirt daemon version 6.2.0 or newer reachable at `/var/run/libvirt`
  (the compose file bind-mounts it into the gateway container).
- Libvirt's network-filter driver and its firewall tools on the host. The
  gateway creates its dedicated `devbox` NAT network and `virbr-devbox` bridge
  during startup; no pre-existing bridge or macvlan is needed.
- Write access to `/data/` on the host (used for ACME data, VM images, serial /
  VNC sockets, the application-audit HEC spool, and the separate SauronAgent
  guest log and forwarding spool).
- At least one QCOW2 base disk image in `/data/baseimages`, named with an
  `.img`, `.qcow2`, or `.raw` extension. The gateway will not start without a
  valid QCOW2 image — see
  [Libvirt and VM storage](#libvirt-and-vm-storage) for a download example.

Start the stack:

```sh
git clone https://github.com/define42/DevBox-Gateway.git
cd DevBox-Gateway
make run
```

Open `https://localhost`, accept the local self-signed certificate, and sign
in with `johndoe` / `dogood`. See [Login flow](#login-flow) for the dashboard
and the seeded administrator account. This Compose configuration is a local
development setup with test credentials and certificate verification disabled
for LDAP and Splunk.

This stops any previous stack, rebuilds the images, and starts:

- `gateway` — the Go binary, using host networking and listening on
  `https://localhost` (port `443`).
- `ldap` — a `glauth/glauth` LDAP server pre-populated from
  `testldap/default-config.cfg` for local development.
- `splunk` — a `splunk/splunk` Splunk Enterprise instance that receives
  application audit events from the gateway over HEC (see
  [Forwarding to Splunk HEC](#forwarding-to-splunk-hec)), and every SauronAgent
  event from inside the VMs (see
  [SauronAgent guest events](#sauronagent-guest-events)). Starting it accepts
  the [Splunk General Terms](https://www.splunk.com/en_us/legal/splunk-general-terms.html).

The first Splunk start takes a few minutes. Application audit events are fsynced
to `/data/audit-spool` before the delivery sink accepts them, then retried in the
background and replayed after a gateway restart. This Compose setup reserves up
to 10 GiB for that spool, uses HEC-only application logging, and does not write
`/data/logs/audit.jsonl`. Guest events keep their separate local log and spool.
Then open Splunk Web at
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
application audit file at runtime only when `SPLUNK_HEC_ENDPOINT` is unset:

| Path                                            | Purpose                                              |
|-------------------------------------------------|------------------------------------------------------|
| `/usr/bin/devbox-gateway`                        | The gateway binary.                                  |
| `/usr/lib/systemd/system/devbox-gateway.service` | systemd unit (runs as root, binds `:443`).           |
| `/etc/devbox-gateway/devbox-gateway.conf`        | Config file (installed `0640 root:root` as it may hold credential digests), marked `%config(noreplace)` so your edits survive upgrades. |
| `/var/log/devbox-gateway/audit.jsonl`             | Default JSON Lines application audit log, created when HEC forwarding is disabled. |
| `/var/lib/libvirt/devbox-gateway/audit-spool`     | Application-audit HEC delivery spool, created under `DATA_ROOT_DIR` when HEC forwarding is enabled. |

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
application audit file at runtime only when `SPLUNK_HEC_ENDPOINT` is unset:

| Path                                            | Purpose                                              |
|-------------------------------------------------|------------------------------------------------------|
| `/usr/bin/devbox-gateway`                     | The gateway binary.                                  |
| `/lib/systemd/system/devbox-gateway.service`  | systemd unit (runs as root, binds `:443`).           |
| `/etc/devbox-gateway/devbox-gateway.conf`     | Config file (installed `0640 root:root` as it may hold credential digests), registered as a `conffile` so your edits survive upgrades. |
| `/var/log/devbox-gateway/audit.jsonl`          | Default JSON Lines application audit log, created when HEC forwarding is disabled. |

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

One package carries both components, laid out like
`make -C SauronAgent install PREFIX=/usr`. Install it on the hypervisor and in
each guest, then enable the component that machine runs:

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

On a DevBox Gateway host the gateway itself always runs the collector on
AF_VSOCK port 9000 (see [SauronAgent guest events](#sauronagent-guest-events)).
Leave `sauronhost` disabled — the two would compete for the same vsock port.
The gateway gives every new VM its vsock device and maps each connection to its
VM from libvirt, so there is no `vms:` CID map to maintain. The standalone
`sauronhost` is for hypervisors that do not run the gateway.

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
[SauronAgent deployment guide](SauronAgent/docs/deployment.md#guest-audit-rules)
for the complete paths and keys, discovery behavior, and policy-conflict handling.

To remove it: `sudo apt remove sauronagent` or `sudo dnf remove sauronagent`.
Package removal leaves the guest spool intact.

> Building the deb yourself instead of downloading it is covered under
> [Building from source](#building-from-source).

## Features

- **RDP-over-TLS reverse proxy** with short-lived, single-use random tokens.
- **HTTPS dashboard** for self-service VM lifecycle management (create, start,
  restart, shutdown, remove). VM CPU and RAM are fixed by the gateway
  configuration (`VM_VCPU_COUNT` / `VM_MEMORY_MIB`), not chosen by users.
- **In-browser consoles**: serial console and noVNC streamed over WebSocket.
- **LDAP authentication** with optional StartTLS and optional certificate
  verification.
- **ACME / Let's Encrypt** support for automatic public TLS certificates, with
  a self-signed fallback for local development.
- **Libvirt integration** for managing QEMU/KVM virtual machines from a
  configurable storage pool and an administrator-managed base image library.
- **Single hostname and port** (`:443`) for everything: dashboard, websockets,
  and RDP.
- **Structured JSON audit events** for authentication, VM lifecycle,
  console/RDP connections, and administrator actions, sent directly to Splunk
  HEC when configured or written as JSON Lines to a local file otherwise.

## Architecture

```
                  ┌──────────────────────── TCP :443 ────────────────────────┐
client ──TLS──►   │  byte-sniff: 0x16 → HTTPS, else → RDP X.224              │
                  └──────────────┬──────────────────────────┬────────────────┘
                                 │                          │
                       HTTPS / WebSocket                 RDP / TLS
                                 │                          │
                ┌────────────────▼─────────────┐  ┌─────────▼─────────────────┐
                │ chi router + Huma API        │  │ Read token, terminate TLS │
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

1. Read the client's X.224 Connection Request (TPKT) and its routing token.
2. Reply with an X.224 Connection Confirm selecting `PROTOCOL_SSL` (TLS).
3. Complete the TLS handshake and resolve the required token to a VM. Missing,
   invalid, and unknown routing tokens are rejected.
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
  embedded in the VM's cloud-init seed. The cleartext password is not kept in
  the session or seed. Every VM gets the operator-configured CPU and memory
  (`VM_VCPU_COUNT` / `VM_MEMORY_MIB`); users cannot pick or change them.
- Start / restart / shutdown / remove existing VMs that you own.
- Open a serial console or noVNC session in the browser.
- Download an `.rdp` file (named after the VM, e.g. `alice-desktop.rdp`)
  preconfigured for the gateway.

**Stop** asks the guest to shut down gracefully through its ACPI power button.
The request returns before shutdown completes; the VM stays running if the
guest does not respond. **Force power off** immediately cuts power after a
confirmation and can lose unsaved work or damage files. Use it when the guest
cannot shut down normally. Manual Stop does not automatically escalate; the
optional idle-shutdown policy has its own escalation timer (see
`VDI_AUTO_SHUTDOWN_HOURS`).

If **Remove** fails during storage or network cleanup, the VM remains listed
with its ownership intact. Restore the failing dependency and retry Remove.
Start and restart are refused once deletion has begun, including after a
gateway restart, because some VM resources may already have been removed.

The same `johndoe` / `dogood` credentials are exercised by the LDAP
integration tests, so they are also the recommended local smoke-test account.
To exercise the administrator inventory in the Docker Compose environment, use
the seeded `admin` / `dogood` account; it belongs to the `devbox-admins` group
configured through `ADMIN_GROUP`.

## Connecting an RDP client

Always connect by downloading the per-VM `.rdp` file from the dashboard — do
**not** try to point a client at the gateway by hand. Click the VM's **RDP**
button to get a ready-to-use file (named after the VM, e.g.
`alice-desktop.rdp`) and open it in an RDP client (mstsc, FreeRDP,
Remmina, …). The file targets `FRONT_DOMAIN` and the public port selected by
`RDP_PORT` or `LISTEN_ADDR` (`443` by default), with the routing token and TLS
settings included.

**Each downloaded file contains a new, single-use token valid for 2 minutes.**
Clicking **RDP** authorizes one connection for that VM and downloads its file.
Open the file in your RDP client within that window. The token is consumed
atomically after the frontend TLS handshake succeeds and before the gateway
connects to the VM. A consumed token cannot be reused, including after a failed
backend connection; click **RDP** again to reconnect.

Downloaded files use the shared `FRONT_DOMAIN` hostname and carry the token in
`loadbalanceinfo`:

```ini
full address:s:desktop.example.com:443
loadbalanceinfo:s:0123456789abcdef0123456789abcdef
```

Each token contains 16 cryptographically random bytes encoded as 32 lowercase
hexadecimal characters. The gateway stores its association with the VM, the
issuing browser session, the owner, the client's IP, and the expiry time. It
checks these conditions when admitting the connection. Clicking **RDP** again
for the same VM in the same browser session replaces that session's previous
token for the VM. Logging out or losing the issuing session invalidates its
unused tokens, and a gateway restart invalidates all outstanding tokens.
The two-minute limit applies to starting a connection; it does not disconnect
an active desktop session.

Configure DNS and a frontend certificate for the single `FRONT_DOMAIN` hostname.
ACME manages only this hostname. RDP routing requires the `loadbalanceinfo`
token; TLS SNI does not select a VM. VM subdomains and their wildcard DNS or
frontend certificates are unnecessary. **Older HMAC-token and SNI-only `.rdp`
files no longer work; download a fresh file for each connection.**
`SNI_HASH_SECRET` and the persisted `sni_hash.secret` file are no longer used.
Existing secret files are left untouched and can be removed by the operator.

The token travels in cleartext in the initial X.224 request before TLS. TLS
authenticates the shared gateway hostname but does not bind that pre-TLS token
to the connection. Randomness, a short expiry, and single use limit guessing
and replay, but do not prevent an active network intermediary from intercepting
or replacing a token. The gateway still enforces the issuing session, VM
ownership, and client IP checks, including for an intercepted token.

The gateway requires TLS-protected RDP (`PROTOCOL_SSL`); clients and backends
that only offer the legacy Standard RDP Security will be rejected. Backend TLS
connections require TLS 1.2 or newer.

## Configuration

All runtime configuration is registered in
[`internal/config/config.go`](internal/config/config.go). On start-up the
gateway combines built-in defaults, a config file, and environment overrides,
then prints the effective settings with registered secrets masked. The gateway
has no configuration command-line flags.

**Config file.** The gateway reads a `KEY=VALUE` config file on start-up
(default `/etc/devbox-gateway/devbox-gateway.conf`, overridable with the
`CONFIG_FILE` environment variable). Blank lines and `#` comments are ignored,
an optional leading `export` is stripped, and values may be wrapped in single or
double quotes. A missing file is not an error — the gateway then runs purely on
environment variables and built-in defaults. The RPM ships a fully commented
template at this path. Each key below is both a config-file key and an
environment variable; **an explicit environment variable always overrides the
file**, including an explicitly empty value. `CONFIG_FILE` itself is a bootstrap
environment variable: set it before starting the process, not inside the file.
The file parser does not expand shell variables, execute commands, or remove
inline comments; put comments on their own lines.

| Variable                  | Default                                                                                                          | Description                                                                                       |
|---------------------------|------------------------------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------|
| `LISTEN_ADDR`             | `:443`                                                                                                           | Address the gateway listens on (HTTPS + RDP multiplexed).                                         |
| `RDP_PORT`                | _(empty)_ | Public TCP port advertised in downloaded `.rdp` files. Empty follows the port in `LISTEN_ADDR` (443 for an ephemeral listener). Set a value from 1 to 65535 when a proxy or port mapping exposes a different port; for example, `LISTEN_ADDR=:8443` with `RDP_PORT=443`. |
| `MAX_CONCURRENT_CONNECTIONS` | `4096` | Maximum open frontend TCP connections across HTTPS, WebSockets, and RDP. Excess connections are immediately closed. Set `<=0` to disable the limit. |
| `MAX_CONNECTIONS_PER_SOURCE` | `256` | Maximum open frontend connections per IPv4 address or IPv6 /64, enforced before TLS and authentication. Account for users sharing a NAT or proxy. Set `<=0` to disable the limit. |
| `MAX_CONNECTIONS_PER_USER` | `32` | Maximum concurrent authenticated dashboard, serial, and VNC WebSockets plus proxied RDP sessions per user. Set `<=0` to disable the limit. |
| `PPROF_LISTEN_ADDR`       | _(empty)_                                                                                                        | Optional separate Go runtime-profiler listener. The host must be a literal loopback IP (for example `127.0.0.1:6060` or `[::1]:6060`); wildcard, hostname, and non-loopback binds are rejected. pprof is never registered on the public `LISTEN_ADDR` handler. |
| `TIMEOUT`                 | `10s`                                                                                                            | Handshake / dial / read timeout for connection setup and HTTP response writes. Long-running creation/upload responses renew the write deadline for each write; HTTP writes use 10s when this setting is non-positive. |
| `CERT_FILE`               | _(empty)_                                                                                                        | PEM-encoded TLS certificate for the front side. Empty → self-signed cert is generated.            |
| `KEY_FILE`                | _(empty)_                                                                                                        | PEM-encoded unencrypted private key matching `CERT_FILE`.                                         |
| `ACME_ENABLE`             | `false`                                                                                                          | Enable ACME (Let's Encrypt) certificate management via certmagic on the front side.               |
| `ACME_EMAIL`              | _(empty)_                                                                                                        | ACME account contact email (recommended when `ACME_ENABLE=true`).                                 |
| `ACME_CA`                 | _(empty)_                                                                                                        | ACME directory URL, or `staging` for the Let's Encrypt staging endpoint.                          |
| `FRONT_DOMAIN`            | `desktop.local.gd`                                                                                               | Single hostname for the dashboard, WebSockets, and downloaded RDP files. ACME manages only this hostname. |
| `AUDIT_LOG_FILE`          | `/var/log/devbox-gateway/audit.jsonl`                                                                            | Required JSON Lines application audit destination when `SPLUNK_HEC_ENDPOINT` is unset; ignored when HEC is configured. The Docker Compose value `/data/logs/audit.jsonl` is used only if application HEC is disabled. |
| `SPLUNK_HEC_ENDPOINT`     | _(empty)_                                                                                                        | Splunk HTTP Event Collector URL, e.g. `https://splunk.example.com:8088`. A nonblank value selects HEC as the sole application audit output and disables local audit-file writes. A URL without a path uses `/services/collector/event`. Empty selects `AUDIT_LOG_FILE`. See [Forwarding to Splunk HEC](#forwarding-to-splunk-hec). |
| `SPLUNK_HEC_TOKEN`        | _(empty)_                                                                                                        | HEC token. Required when `SPLUNK_HEC_ENDPOINT` is set. Masked in the startup settings table.      |
| `SPLUNK_HEC_INDEX`        | _(empty)_                                                                                                        | Destination index for forwarded events. Empty → the token's default index.                       |
| `SPLUNK_HEC_ACK_ENABLED`  | `false`                                                                                                          | Require indexer acknowledgement before advancing the application-audit spool. Requires its endpoint and an ACK-enabled HEC token; see [Forwarding to Splunk HEC](#forwarding-to-splunk-hec). |
| `SPLUNK_HEC_SKIP_TLS_VERIFY` | `false`                                                                                                       | When `true`, skip TLS certificate verification against the HEC endpoint.                          |
| `SPLUNK_HEC_STALL_TIMEOUT` | `1h`                                                                                                          | Make `/api/ready` return `503` once application-audit HEC delivery has kept failing this long. Recovers when delivery resumes. `<=0` disables the check. |
| `DEVBOX_GATEWAY_SPOOL_MAX_MIB` | `10240`                                                                                                    | Maximum disk space for the application-audit HEC delivery spool at `<DATA_ROOT_DIR>/audit-spool`. `<=0` → the default. At 90% usage, readiness fails and new audited activity is refused; writes fail promptly at the hard limit without evicting pending events. |
| `SAURON_EVENT_LOG_FILE`   | `/var/log/devbox-gateway/sauron.jsonl` | JSON Lines guest-event log, rotated at 256 MiB with eight rotated files plus the active file retained. Empty disables it, which then requires `SAURON_SPLUNK_HEC_ENDPOINT`. |
| `SAURON_SPLUNK_HEC_ENDPOINT` | _(empty)_                                                                                                     | Splunk HTTP Event Collector URL that also receives every guest event, delivered from the gateway's spool. A URL without a path uses `/services/collector/event`. Empty disables HEC forwarding. |
| `SAURON_SPLUNK_HEC_TOKEN` | _(empty)_                                                                                                        | HEC token for guest events. Required when `SAURON_SPLUNK_HEC_ENDPOINT` is set. Masked in the startup settings table. |
| `SAURON_SPLUNK_HEC_INDEX` | _(empty)_                                                                                                        | Destination index for guest events. Empty → the token's default index.                           |
| `SAURON_SPLUNK_HEC_ACK_ENABLED` | `false`                                                                                                     | Require indexer acknowledgement before advancing the guest-event spool, independently of the application-audit setting. Guest acknowledgements still mean local spool acceptance. Requires its endpoint and an ACK-enabled HEC token. |
| `SAURON_SPLUNK_HEC_SKIP_TLS_VERIFY` | `false`                                                                                                | When `true`, skip TLS certificate verification against `SAURON_SPLUNK_HEC_ENDPOINT`.              |
| `SAURON_SPOOL_DIR`        | _(empty → `<DATA_ROOT_DIR>/sauron-spool`)_                                                                       | Where guest events wait, durably and across gateway restarts, until Splunk HEC accepts them.      |
| `SAURON_SPOOL_MAX_MIB`    | `10240`                                                                                                          | Disk space the spool may use. Size it for the longest Splunk outage to ride out. `<=0` → the default. |
| `SAURON_AGENT_STARTUP_GRACE` | `5m` | Time allowed for a newly observed running managed VM to contact the collector. An overdue agent makes `/api/ready` return `503`. Must be positive. |
| `SAURON_AGENT_TIMEOUT` | `90s` | Maximum silence after an expected agent's first contact. Handshakes, events and heartbeats from its trusted vsock identity refresh this deadline. Must be positive. |
| `DATA_ROOT_DIR`           | `/var/lib/libvirt/devbox-gateway`                                                                               | Root directory for gateway-managed state (ACME data, images, serial sockets, VNC sockets). Under `/var/lib/libvirt` so QEMU can use it under SELinux. The bundled `docker-compose.yml` overrides this to `/data`. |
| `VIRT_STORAGE_POOL_NAME`  | `desktop`                                                                                                        | Libvirt storage pool to allocate VM volumes in.                                                   |
| `BASE_IMAGE_DIR`          | _(empty → `<DATA_ROOT_DIR>/baseimages`)_                                                                          | Directory of selectable QCOW2 base VDI images named `.img`, `.qcow2`, or `.raw`. Users pick one per VM in the dashboard. The gateway refuses to start if it contains no valid QCOW2 image. |
| `MAX_VDI_PER_USER`        | `10`                                                                                                             | Maximum number of VDIs (VMs) each user may own at once. Admission uses live libvirt ownership plus in-flight reservations, independent of dashboard cache freshness. Set `<=0` to disable the per-user limit. |
| `VDI_AUTO_SHUTDOWN_HOURS` | `0`                                                                                                              | Shut down a running VDI after this many hours without use. Creation, start, and opening RDP, serial, or noVNC count as use. Open connections through the gateway prevent auto-shutdown, even without keyboard or mouse input; the full idle window starts when the last connection ends. Last use is persisted on connection changes and checkpointed each minute while connected so recent activity survives gateway restarts. Connections bypassing the gateway are not tracked. The guest is first asked to power off (ACPI power button) and is force-stopped if still running 5 minutes later. Set `<=0` to disable auto-shutdown (the default). |
| `VM_VCPU_COUNT`           | `4`                                                                                                              | Number of virtual CPUs assigned to every VM. Users cannot choose or change this per VM. Set `<=0` to fall back to the default. |
| `VM_MEMORY_MIB`           | `4096`                                                                                                           | Memory in MiB assigned to every VM. Users cannot choose or change this per VM. Set `<=0` to fall back to the default. |
| `VM_DISK_SIZE_GB`         | `200` | Target virtual disk capacity in GiB for new VMs, and the maximum uploaded base-image file size. Smaller base disks are grown; larger ones are not shrunk. QCOW2 host storage grows as data is written. Set `<=0` to use the default. |
| `LDAP_URL`                | `ldaps://ldap:389`                                                                                               | Required LDAP server URL. The gateway refuses to start when empty.                                |
| `LDAP_AUTH_TIMEOUT`       | `10s` | Maximum total time for LDAP connection setup, TLS, bind, and search. Request cancellation also aborts authentication. Values `<=0` use the default. |
| `LDAP_BASE_DN`            | `dc=glauth,dc=com`                                                                                               | LDAP search base.                                                                                 |
| `LDAP_USER_FILTER`        | `(mail=%s)`                                                                                                      | LDAP search filter; `%s` is replaced with the submitted bare username plus `LDAP_USER_DOMAIN`.     |
| `LDAP_USERNAME_ATTRIBUTE` | `mail` | Single-valued directory attribute providing the canonical gateway username. Accepts a bare name or a name with `LDAP_USER_DOMAIN`; the domain suffix is removed. Set to `userPrincipalName`, `sAMAccountName`, or `uid` when appropriate for your directory. |
| `LDAP_USER_DOMAIN`        | `@example.com`                                                                                                   | Required domain suffix appended to every accepted username for LDAP bind and search. Login names containing `@` are rejected. |
| `LDAP_REQUIRED_GROUPS`    | _(empty)_                                                                                                        | Groups a user must belong to (any one of them) for LDAP login. Bare group names may be `,`- or `;`-delimited; full group DNs must be `;`-delimited because DNs contain commas. Matched case-insensitively against the user's `memberOf` attribute (full DN or its first RDN value). Empty allows every authenticated user. |
| `ADMIN_GROUP`             | _(empty)_                                                                                                        | Single LDAP group whose direct members receive administrator access at login. Accepts a bare name or full DN and matches `memberOf` case-insensitively. Empty disables administrator access. |
| `LDAP_STARTTLS`           | `false`                                                                                                          | When `true`, upgrade plain LDAP connections with StartTLS.                                        |
| `LDAP_SKIP_TLS_VERIFY`    | `false`                                                                                                          | When `true`, skip TLS certificate verification against the LDAP server.                           |
| `LOGIN_RATE_LIMIT_MAX_ATTEMPTS` | `5`                                                                                                      | Maximum failed attempts per username-and-client-IP pair within `LOGIN_RATE_LIMIT_WINDOW`. Set `<=0` to disable login throttling. |
| `LOGIN_RATE_LIMIT_IP_MAX_ATTEMPTS` | `50`                                                                                                  | Higher password-spray limit across all usernames from one client IP. Set `<=0` to disable only the IP-wide limit. |
| `LOGIN_RATE_LIMIT_WINDOW` | `5m`                                                                                                             | Rolling window for failed login attempt counting.                                                 |
| `LOGIN_RATE_LIMIT_LOCKOUT` | `15m`                                                                                                           | How long matching login attempts are rejected after either failure limit is reached.              |
| `DEBUG_CONNECTIONS`       | `false`                                                                                                          | When `true`, log every accepted front connection (HTTPS vs RDP, with source address) and every HTTP/WebSocket request (type, source address, method, path). Useful for tracing connectivity; noisy, so leave off in normal operation. |

Booleans accept `true`, `false`, `1`, `0`, `t`, `f`, `T`, `F`, `TRUE`, `FALSE`,
`True`, and `False`. `yes` and `no` are not accepted. Durations use Go duration
syntax such as `15s`, `2m`, or `500ms`. Invalid integer, boolean, or duration
values fall back to the setting's built-in default; check the startup table
when troubleshooting an override.

### Audit logs and Splunk

See [compliance.md](compliance.md) for the NATO AC/35-D/2003-REV5 §26.3.1
coverage comparison, audit-rule and event inventories, Splunk index routing,
JSON event examples and remaining compliance gaps.

Application audit events use one output: Splunk HEC when
`SPLUNK_HEC_ENDPOINT` is nonblank, or `AUDIT_LOG_FILE` when it is unset.
In HEC mode the file setting is ignored. Existing audit files remain on disk;
the gateway does not open or append to them.

With HEC disabled, events are appended to the required `AUDIT_LOG_FILE` as
JSON Lines (NDJSON): each physical line is an independently parseable JSON
event. The native packages default to `/var/log/devbox-gateway/audit.jsonl`;
systemd creates its parent directory before starting the gateway. Docker
Compose configures `/data/logs/audit.jsonl` for use if application HEC is
disabled, visible on the host through the `/data` bind mount. The supplied
Compose deployment enables HEC, so it does not write this application file.

With application HEC disabled, configure the Splunk Universal Forwarder with
a file monitor for the selected path and set the source type to `_json`.
For example:

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

File mode fsyncs each record and follows external rename-and-create rotation:
rename the old file and create a replacement at `AUDIT_LOG_FILE`. The next
write detects the replacement and reopens it; a write racing rotation may land
in the renamed file. Configure retention externally and preserve the gateway's
write permissions and any forwarder read permissions on replacement files.
`copytruncate` is unsupported because truncation can discard concurrent writes.

An application audit persistence error is logged to the operational log and
makes `/api/ready` return `503`. This state remains until restart, even if later
writes succeed: the failed record cannot be reconstructed automatically.
Investigate the failure, restore storage and account for the audit gap before
restarting. User actions are not rolled back when their audit write fails.

Ordinary process diagnostics remain available through `journalctl` (or Docker
logs); application audit events go to the selected audit output.

#### Forwarding to Splunk HEC

As an alternative to a Universal Forwarder, the gateway can send application
audit events directly to a Splunk HTTP Event Collector. Set the endpoint and token
(and optionally the index):

```ini
SPLUNK_HEC_ENDPOINT=https://splunk.example.com:8088
SPLUNK_HEC_TOKEN=11111111-2222-3333-4444-555555555555
SPLUNK_HEC_INDEX=devbox_audit
# Opt in only after enabling indexer acknowledgement on this HEC token.
SPLUNK_HEC_ACK_ENABLED=false
DEVBOX_GATEWAY_SPOOL_MAX_MIB=10240
```

- HEC is the sole application audit destination. `AUDIT_LOG_FILE` is ignored,
  even if empty or unwritable. Existing files are left in place, but no local
  application audit file is created, opened or appended in HEC mode.
- Each event arrives on the JSON event endpoint with `source=devbox-gateway`,
  `sourcetype=devbox-gateway:audit`, the gateway's hostname as `host`, and the
  same JSON schema used in file mode as the event body. The token
  must be allowed to write to `SPLUNK_HEC_INDEX`. When the token uses indexer
  acknowledgement, enable the corresponding gateway ACK setting below.
- Before the delivery sink accepts an event, it appends and fsyncs it under
  `<DATA_ROOT_DIR>/audit-spool`. A background worker sends persisted events in
  order and resumes from the spool after a gateway or Splunk restart. Pending
  events do not expire merely because an outage is long.
- Configure the collector's direct URL: redirects are not followed. With
  `SPLUNK_HEC_ACK_ENABLED=false` (the default), delivery succeeds when a `2xx`
  response contains valid HEC JSON with `code: 0`; no ACK request is made.
  Network failures, redirects, `400`, `403`, every other non-success status,
  invalid response bodies, and nonzero HEC codes retain the pending event and
  retry with backoff; no HEC rejection is treated as permission to drop it.
- The one exception is Splunk refusing the events themselves (`413`, or `400`
  with HEC code 6, 12, 13 or 15). The gateway then resends that batch one event
  at a time, so a batch that was only too large is still delivered whole. An
  event Splunk refuses on its own is appended and fsynced, as its complete HEC
  envelope, to `<DATA_ROOT_DIR>/audit-spool/rejected.jsonl` before delivery
  moves past it, and a process diagnostic names the file. Review that file and
  resubmit its envelopes once the cause is fixed; it is never rotated or
  truncated by the gateway. If it cannot be written, delivery pauses instead.
- Set `SPLUNK_HEC_ACK_ENABLED=true` to require indexer acknowledgement for
  application audits. The Splunk deployment must support HEC indexer
  acknowledgement and the token must have it enabled. The gateway sends a GUID
  in `X-Splunk-Request-Channel` on both event POSTs and ACK polls, using the same
  channel and token for each delivery. It polls `/services/collector/ack` with
  the returned `ackId`; only an explicit `true` for that exact ID advances the
  spool checkpoint. A `code: 0` event response alone is insufficient in this
  mode. Splunk documents a true ACK as confirmation of the desired replication
  factor; its parsing pipeline can still discard events, so ACK does not
  guarantee indexing or searchability. See [Splunk's indexer acknowledgement documentation](https://help.splunk.com/en/splunk-enterprise/get-data-in/collect-http-event-data/about-http-event-collector-indexer-acknowledgment).
- ACK polling keeps the event pending across `false` or missing status,
  malformed replies, transport/HTTP errors, and shutdown. Each delivery polls
  for at most five minutes before the forwarder retries the stored payload
  with backoff. The ACK URL uses the event URL's scheme and host, preserving
  any proxy prefix before `/services/collector`. If a load balancer fronts
  multiple HEC instances, configure affinity so event POSTs and their ACK
  polls reach the same instance and channel. The client retains affinity
  cookies; see [Splunk's load-balancer guidance](https://help.splunk.com/en/splunk-cloud-platform/get-data-in/splunk-connect-for-kafka/2.2/configure/load-balancing-configurations-for-splunk-connect-for-kafka).
  A lost ACK response, timeout or restart can cause a payload to be resent even
  if Splunk already processed it.
- ACK mode accepts standard `/services/collector`, `/services/collector/event`
  or `/services/collector/raw` paths, including `/1.0` variants of event/raw
  and optional proxy prefixes. A URL without a path uses the standard event
  endpoint. Other custom paths are rejected at startup when ACK is enabled.
- Delivery is at-least-once. A crash after Splunk accepts an event but before
  its local checkpoint advances can cause that event to be sent twice.
- Each spool directory is exclusively locked while open. Application and guest
  HEC spools must use separate directories, and a second gateway cannot open
  the same spool, including through a directory symlink.
- `DEVBOX_GATEWAY_SPOOL_MAX_MIB` bounds the spool (10 GiB by default). At 90%
  usage, `/api/ready` returns `503`; new HTTP mutations and WebSocket upgrades
  receive `503` with `Retry-After: 5`, and new RDP connections close before
  consuming a grant. Logout, ordinary reads and probes remain available.
  Admission resumes automatically when delivery frees enough capacity. The
  remaining 10% is headroom for work already admitted and disconnect events,
  not a guarantee that every concurrent operation can finish auditing.
  At the hard limit, new audit writes fail immediately without evicting pending
  events. Already-running actions are not rolled back: any event that cannot
  be persisted is reported in process diagnostics and latches readiness and
  new audited activity unhealthy until investigation and restart.
  Size a 48-hour objective from the measured encoded event rate:
  `bytes/second × 172800 × operational headroom`, converted to MiB. The default
  size is a byte limit, not a 48-hour guarantee.
- HEC remains the sole application audit output: acknowledged spool records are
  reclaimed, and the spool is not a permanent `audit.jsonl` copy or file
  fallback. SauronAgent guest logging and `SAURON_SPOOL_*` are separate.
- Disk failures, a single event too large for the spool, or writes attempted
  while the sink is closing are surfaced in process diagnostics and latch
  application audit readiness as unhealthy until restart. Monitor these errors
  and spool capacity through `journalctl` or Docker logs.
- Delivery that keeps failing for `SPLUNK_HEC_STALL_TIMEOUT` (one hour by
  default), such as a revoked token, a wrong index or a long outage, makes
  `/api/ready` return `503`. This delivery timeout alone does not reject new
  activity while local capacity remains available. Readiness recovers once a
  batch is delivered. Set it to `0` to disable this delivery-timeout check;
  capacity and persistence checks remain enabled.
- On shutdown, final worker events have a five-second acceptance window; full
  spools still reject immediately. Delivery gets a bounded drain period, and
  records already in the spool remain available for replay after restart.
- The gateway refuses to start when `SPLUNK_HEC_ENDPOINT` is set without
  `SPLUNK_HEC_TOKEN`, or when a token, index or enabled ACK setting lacks an
  endpoint. Leave ACK disabled in file mode.
  Invalid HEC configuration fails startup; it does not select file logging.
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
virtio-vsock — no guest networking involved. The gateway always runs
SauronAgent's host collector on fixed AF_VSOCK port 9000 and receives those
events itself. No enable switch or port setting is needed. To also forward
guest events to Splunk HEC, configure:

```ini
SAURON_SPLUNK_HEC_ENDPOINT=https://splunk.example.com:8088
SAURON_SPLUNK_HEC_TOKEN=11111111-2222-3333-4444-555555555555
SAURON_SPLUNK_HEC_INDEX=devbox_sauron
# Independent of SPLUNK_HEC_ACK_ENABLED; requires this token's ACK support.
SAURON_SPLUNK_HEC_ACK_ENABLED=false
```

- Every newly created VM gets a virtio-vsock device, for which libvirt picks a
  CID that is unique among the running domains. Existing VMs without a vsock
  device are not automatically migrated; recreate them or add the device
  through libvirt before collecting their events. SauronAgent must also be
  installed and running inside each guest.
- The gateway listens on AF_VSOCK port 9000 and attributes each
  connection to the running VM libvirt assigned its CID to. The CID is set by the
  hypervisor, so a guest cannot pass its events off as another VM's; what the
  guest says about itself (hostname, machine-id, …) is recorded under
  `source.reported` and never used for attribution.
- Each event is written as a collector envelope: the gateway's receive time
  (`received_at`), the trusted `source` (`vm`, `uuid`, `cid`, `host`, and
  `labels.owner` — the gateway user who owns the VM), and the guest's normalized
  `event` unchanged. The collector's own `sauron.*` events (protocol violations,
  sequence gaps, refused connections, output failures) go to the same stream.
  If CID lookup fails, the collector still records the event with
  `source.known=false` and a synthetic `unknown-cid-N` name; VM UUID and owner
  labels are then unavailable.
  Once fresh expected-VM inventory supplies a complete identity, the next valid
  event or heartbeat on that unresolved connection asks the agent to reconnect.
  The collector resolves the new connection's identity, and the agent replays
  unacknowledged records.
  Existing records keep their original attribution; a fully resolved connection
  keeps its pinned identity even if the CID is later reused.
- Events go to `SAURON_EVENT_LOG_FILE` and, when configured, to Splunk HEC, using
  their own endpoint, token, and index so guest telemetry can land in a different
  index than the gateway audit log. In Splunk they arrive with
  `source=sauronagent`, `sourcetype=devbox-gateway:sauron`, the VM name as
  `host`, and the gateway's receive time as `_time` (a guest controls its own
  clock; its timestamp stays in `event.timestamp`).
- Delivery to Splunk is store and forward. The gateway acknowledges an event to
  its guest — which then deletes its own copy — as soon as the event is written
  and fsynced to the gateway's spool (`SAURON_SPOOL_DIR`) and accepted by any
  other configured sink. This guest acknowledgement still means local
  acceptance when `SAURON_SPLUNK_HEC_ACK_ENABLED=true`; already-spooled records
  remain after VM deletion. A background forwarder delivers the spool to Splunk
  in order, in batches, retrying with
  backoff capped at 30s for however long Splunk is unreachable — days if
  need be — and resumes from its checkpoint after a gateway restart. A long
  outage is reported in the process log every 5 minutes with the spool's size.
  If saving an accepted batch's checkpoint fails, the forwarder retries that
  save before reading or sending more events. Recovery does not require a new
  append, even when the spool is full. A restart before the checkpoint is saved
  can replay the batch.
- The gateway spool is bounded by `SAURON_SPOOL_MAX_MIB` (10 GiB by default).
  When it fills, the gateway preserves pending records and stops acknowledging
  new events. Guests then retain events in their own spools (1 GiB by default).
  A full guest spool evicts its oldest unsent segments and reports the lost
  sequence range, so a sufficiently long outage can lose guest events. Guest
  spool writes also use periodic fsync by default; a power loss can lose recent
  unsynced writes.
- The embedded file sink fsyncs each event and file creation/rotation metadata
  before the guest ACK, including file-only collection. Acknowledged file
  records follow the filesystem's fsync durability guarantees; size-based
  rotation still limits retention. Per-event fsync adds storage latency and
  limits throughput. With HEC enabled, its gateway spool is also fsynced before
  acceptance.
- Retries can produce duplicate deliveries. After a crash or restart, events that were
  delivered just before it can reach Splunk twice. An event Splunk rejects as
  invalid on its own (HEC codes 6, 12, 13, 15, or too large) is dropped with a
  log line, so it cannot block the backlog; every other refusal — an index the
  token may not write to, an unhealthy or unreachable Splunk — keeps the events
  spooled. Redirects and unconfirmed `2xx` replies keep the checkpoint unchanged;
  successful delivery requires HEC JSON with `code: 0` by default. Set
  `SAURON_SPLUNK_HEC_ACK_ENABLED=true` to additionally require an explicit
  `true` ACK for the submitted batch's exact `ackId`, with the token, channel,
  endpoint affinity and five-minute polling limit described above. ACK errors
  and unconfirmed ACKs always retain the batch, including malformed ACK
  replies and shutdown; the permanent-event rejection policy only applies to
  the event submission. This switch is independent of `SPLUNK_HEC_ACK_ENABLED`.
  If both streams share an ACK-enabled token, enable both gateway switches;
  use separate tokens to configure different ACK modes.
  Concurrent sessions sharing a peer or trusted VM UUID serialize event
  acceptance through deduplication, output and commit. This prevents simultaneous
  copies on the same event stream from racing each other.
- The gateway refuses to start when the guest-event HEC endpoint lacks a token
  (or a token, index or enabled ACK setting lacks an endpoint), or when neither
  the file nor HEC is configured. It also refuses to start when it cannot open
  the vsock listener: the host needs the `vhost_vsock` kernel module, and must
  not run `sauronhost` on the same port.
  The shipped systemd unit allows the `AF_VSOCK` socket family; in Docker, see
  the seccomp note under [Quick start](#quick-start-docker-compose).
- Every 15 seconds the collector refreshes its expected agents from running,
  persistent VMs with gateway ownership metadata. A new VM gets
  `SAURON_AGENT_STARTUP_GRACE` to connect; after first contact,
  `SAURON_AGENT_TIMEOUT` bounds silence. Overdue agents emit
  `sauron.stream.lost` and make `/api/ready` return `503`; matching traffic emits
  `sauron.stream.resumed`. Only the current trusted CID, VM name and UUID can
  refresh that VM's deadline. Stopped or removed VMs leave the expected set on
  the next successful inventory refresh.
- Inventory errors retain the previous expectations and fail readiness. An
  inventory query that does not complete leaves readiness unhealthy once the
  snapshot is older than 45 seconds. Running managed VMs without an assigned
  vsock CID also fail the inventory check. Missing agents and inventory errors
  recover automatically after valid traffic or inventory returns; neither
  condition restarts the gateway. An unexpected collector exit terminates the
  gateway with exit status 1 so its service manager can restart it.
- Stream alerts wait for successful output acceptance and are retried after
  storage recovery. The in-memory alert queue holds at most 4096 entries;
  overflow logs an error and keeps readiness unhealthy until operator recovery
  and restart. Partial acceptance by multiple outputs can produce duplicate
  alerts. See [monitoring and recovery](SauronAgent/docs/deployment.md#6-what-to-monitor).
- Unreported sequence gaps also fail readiness, including while their output
  write is in progress. A separate worker retries pending gap reports every
  second, independently of guest traffic and inventory queries. A gap clears
  when its loss report is accepted or the missing events arrive. Accepted loss
  evidence does not prove those original events were delivered or clear a
  rejected guest record's health tracking. When loss accounting is full, a
  report waits for capacity before another output attempt; other streams can
  continue. Received originals are protected before waiting for output, so a
  concurrent loss report cannot acknowledge an original still awaiting storage.

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
   and set `ACME_EMAIL`. Only `FRONT_DOMAIN` is managed; creating or deleting VMs
   does not request public certificates. Optionally set `ACME_CA=staging` while
   testing. ACME state is persisted under `$DATA_ROOT_DIR/acme`.

Each new VM receives a unique backend certificate and private key through its
cloud-init seed ISO. Libvirt metadata stores the public certificate, its internal
server name, and the domain UUID. The gateway validates certificate trust,
server name, validity, and the exact leaf certificate before forwarding RDP
traffic. The public routing token is separate from this backend identity.
Backend TLS session resumption is disabled so every connection verifies the current
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
`LDAP_USERNAME_ATTRIBUTE`, and `LDAP_USER_DOMAIN` to match.
Users must enter only their bare username (for example, `alice`). The gateway
rejects domain-qualified input and always appends `LDAP_USER_DOMAIN` before the
LDAP bind and search; an empty or malformed `LDAP_USER_DOMAIN` is therefore a
startup error.

After authentication, the gateway takes the account name from
`LDAP_USERNAME_ATTRIBUTE` on the returned directory entry, preserving the
directory's spelling. With the default `mail`, `alice@example.com` becomes
`alice`. A login entered as `ALICE` that resolves to this entry therefore uses
the same sessions, VM ownership, connection limit and VM quota as `alice`.
For an AD filter such as `(userPrincipalName=%s)`, set
`LDAP_USERNAME_ATTRIBUTE=userPrincipalName` (or `sAMAccountName` for a bare
account name). The resulting bare name must identify one account uniquely
across the search base: for example, `alice` and `alice@example.com` both
produce `alice`. Missing, ambiguous, invalid or foreign-domain values reject login.

**Upgrading existing ownership:** previous versions used the submitted login
spelling as the VM owner. Before rollout, compare existing owner metadata with
the canonical directory values. A VM whose owner differs remains visible to
administrators but will not appear for the canonical user until an operator
migrates its owner. Follow [the ownership migration procedure](docs/ldap-identity-migration.md).
Keep the chosen identity attribute stable; changing it or renaming an account
requires the same ownership review.

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

VM creation first persists an incomplete libvirt domain carrying the operation's
UUID, owner and storage-pool identity, before allocating its network reservation
or disks. Startup and a same-name retry recover creations interrupted by a gateway
process crash by removing only resources covered by a matching incomplete
operation. A completed definition
is committed before its first start, so recovery preserves completed, stopped VMs.
Identity mismatches, disks used by another domain and cleanup failures stop
recovery for operator investigation; the operation record remains for retry.
Resources left by older versions without this record require manual inspection.
This operation tracking does not add a host-power-loss durability guarantee for
guest disk contents; volume I/O remains managed through libvirt.

VM quota admission counts live libvirt ownership and in-flight creations rather
than the dashboard's cached inventory. It fails closed if ownership cannot be
read. An in-flight VM already visible to libvirt can temporarily count twice,
so a request near the limit may need to be retried after the current creation
finishes.

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

You can also [build an Ubuntu or Rocky Linux XFCE image from this checkout](#building-vm-images),
including its matching SauronAgent package, and copy the resulting `.img` into
`BASE_IMAGE_DIR` or upload it through the administrator's **Base Images** modal.

Because `docker-compose.yml` already bind-mounts `/data/`, files dropped in
`/data/baseimages` on the host are visible to the gateway container.

For a native RPM or deb install the data root defaults to
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

The multi-stage [Dockerfile](Dockerfile) compiles the TypeScript UI and the Go
binary in a Go/Alpine builder. Its `GO_VERSION` and `ALPINE_VERSION` build
arguments select the image tags; the root `go.mod` specifies the required Go
version. The Alpine runtime contains the gateway binary, `libvirt-libs`, and
`ca-certificates`.

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
pure-Go `internal/rpm` and `internal/deb` writers. SauronAgent and the gateway
share the root Go module and its dependencies. The gateway also compiles in
the host collector from `SauronAgent/collector`. Both need the Go version
specified in the root `go.mod`. With an older local toolchain, prefix the
commands with `GOTOOLCHAIN=auto`.

For ARM64, use `make sauron-rpm ARCH=aarch64` or
`make sauron-deb DEB_ARCH=arm64`. The package targets select the matching Go
architecture automatically. The packaging command checks both executable ELF
headers and rejects binaries that do not match the requested architecture.
Recognized CPU aliases are normalized to the selected package format in metadata
and default filenames (for example, `-format deb -arch x86_64` produces `amd64`).

### Building VM images

VM image recipes live under [`images/`](images), with one directory per image
variant. The Ubuntu 26.04 XFCE and Rocky Linux 9 XFCE recipes build standalone
QCOW2 desktop disks and install SauronAgent from the same checkout, enabling its
guest service.
Image builds run separately from gateway and container builds.

GitHub Releases publish both images alongside the gateway and SauronAgent
packages under the same `vMAJOR.MINOR.PATCH` tag. Each image filename and its
installed SauronAgent use that gateway release version. Publication waits for
both images to build and pass their boot tests.

On a Linux x86_64 host with Docker access, Bash, curl, Python 3, `flock`,
`sha256sum`, Git, Make, and the Go version specified in `go.mod`, run:

```sh
make image-check IMAGE=ubuntu26.04-xfce
make image IMAGE=ubuntu26.04-xfce IMAGE_VERSION=0.0.0
make image-test IMAGE=ubuntu26.04-xfce IMAGE_VERSION=0.0.0

make image-check IMAGE=rocky9-xfce
make image IMAGE=rocky9-xfce IMAGE_VERSION=0.0.0
make image-test IMAGE=rocky9-xfce IMAGE_VERSION=0.0.0
```

The build downloads the selected distribution's source image and a container
with the image customization tools. KVM speeds up customization; software
emulation works when `/dev/kvm` is absent but is considerably slower. The smoke
test additionally requires host `qemu-system-x86_64`, `qemu-img`, `xorriso`, and
`timeout`; it boots a temporary overlay and leaves the base image unchanged.

Output goes to `dist/images/<variant>/` as
`<variant>-v0.0.0.img`, with `.img.sha256` and
`.img.manifest.json` sidecars. The manifest records the build commit, source
checksum, builder container, and SauronAgent version. Downloads are cached under
`.cache/images/`. Both directories are ignored by Git. See the
[Ubuntu image README](images/ubuntu26.04-xfce/README.md) and
[Rocky image README](images/rocky9-xfce/README.md) for contents, release
downloads, and gateway installation.

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
make lint     # golangci-lint for the gateway; go vet for SauronAgent
make gosec    # gosec security scanner for the gateway
go test -race -p=1 -timeout=15m ./...
```

The test commands include both the gateway and SauronAgent packages, with
combined coverage in `make test`. To run only the SauronAgent tests, use
`make -C SauronAgent test`. The gateway's strict lint and gosec checks cover
`./cmd/...` and `./internal/...`; SauronAgent uses `go vet` through `make lint`.
Run `go vet ./...` to vet the entire module.

Keep `-p=1` when running the full test suite because integration tests in
multiple packages share the system libvirt daemon. Allow extra time for VM
image copies when using the race detector.

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
│   ├── audit/       Application audit events and durable HEC delivery.
│   ├── backendidentity/ Per-VM backend TLS certificates and identity validation.
│   ├── cert/        TLS certificate management (self-signed + ACME via certmagic).
│   ├── cloudinit/   NoCloud document and seed ISO generation.
│   ├── config/      Environment-backed settings registry (the only place env
│   │                vars may be read from).
│   ├── console/     Serial console and noVNC WebSocket handlers.
│   ├── dashboard/   Dashboard HTML / JSON rendering and VM listing.
│   ├── deb/         Debian package construction and archive writing.
│   ├── gateway/     Application lifecycle, HTTP handlers, TLS dispatch, and listeners.
│   ├── hash/        Password hashing for cloud-init.
│   ├── identity/    Authenticated user identity and administrator role.
│   ├── ldap/        LDAP login authentication.
│   ├── rdp/         RDP/X.224/MCS parsing, TLS-to-TLS proxy.
│   ├── rpm/         RPM package construction and manifests.
│   ├── sauron/      Embedded SauronAgent collector: vsock listener, event log, Splunk HEC sink.
│   ├── sauronpkg/   SauronAgent package manifest and maintainer scripts.
│   ├── session/     Cookie session manager and middleware.
│   ├── splunkhec/   Splunk HTTP Event Collector client shared by audit and sauron.
│   ├── virt/        Libvirt VM lifecycle (create/start/stop/remove/resize).
│   ├── vmname/      VM name construction and validation.
│   └── webassets/   Embedded static assets, including the compiled dashboard.js.
├── SauronAgent/     Guest audit agent and hypervisor collector in the root Go module;
│                    the gateway embeds its collector package.
├── images/
│   ├── Makefile     Image build, recipe validation, and boot smoke-test targets.
│   ├── rocky9-xfce/  Rocky Linux 9 XFCE image recipe and desktop assets.
│   └── ubuntu26.04-xfce/  Build scripts, guest customization recipe, and desktop assets.
├── dist/images/     Generated QCOW2 images, checksums, and manifests (ignored).
├── .cache/images/   Downloaded base images and build workspaces (ignored).
├── ui/              TypeScript sources for the dashboard.
├── testldap/        glauth config + cert/key used for local LDAP.
├── testsplunk/      Post-setup task creating the local Splunk's audit and SauronAgent indexes.
├── docs/            HTTP endpoint reference.
├── CONTRIBUTING.md  Contributor setup, checks, and review guidance.
├── go.mod, go.sum   Shared dependencies for the gateway and SauronAgent.
└── Dockerfile, docker-compose.yml, Makefile, tsconfig.json
```

## HTTP endpoints and health checks

The [HTTP endpoint reference](docs/http-api.md) describes the dashboard routes,
authentication, request formats, and WebSocket endpoints. OpenAPI, schema, and
interactive API-documentation routes are disabled in the gateway.

Both probes are public and return plain text:

| Probe | Response | Meaning |
| --- | --- | --- |
| `GET /api/health` | `200` with `ok\n` | HTTP listener liveness. |
| `GET /api/ready` | `200` with `ready\n`, or `503` with `not ready\n` | Application audit persistence, capacity and delivery status, plus guest collector readiness including expected agents, inventory freshness, pending stream alerts and unreported sequence gaps. |

Readiness responses contain no VM identities, storage paths or backend errors.
The probe reports known failures; it does not test LDAP, free disk space or
whether Splunk events are searchable. A remote HEC outage leaves readiness
healthy while events queue durably below 90% spool usage, until application-audit
delivery has kept failing for `SPLUNK_HEC_STALL_TIMEOUT`. A rejected guest record keeps readiness
unhealthy until the record is accepted by every configured output. The gateway
retains copies of rejected records and retries them every second, preserving
their original attribution even after a guest disconnects or its identity
resolves. Guest replay can also recover a matching failure; unrelated events
and heartbeats cannot clear it. Generic collector write/flush failures can clear
after a later successful write to every output. Retained retries are bounded at
4096 records and 64 MiB of encoded data. Overflow or failure to retain a copy
requires operator recovery and restart. These copies and their health state
are lost on restart, so investigate delivery before restarting. Application
audit persistence errors also require investigation and
restart to clear. See [output recovery](SauronAgent/docs/deployment.md#output-failure-recovery)
for the matching and recovery rules.
Application-audit capacity pressure and persistence failures also refuse new
mutations and streams; logout, ordinary reads and probes remain available.
Other readiness failures do not themselves block dashboard or RDP access.

For the local Compose setup with a self-signed certificate:

```sh
curl --insecure --fail https://localhost/api/health
curl --insecure --fail https://localhost/api/ready
```

Use certificate verification when probing a deployment with a trusted certificate.

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
  owner clicked **RDP** for that VM, from the same client IP, within the last
  2 minutes (see `rdpConnectWindow` in `internal/session`), and each click
  authorizes exactly one connection (the grant is consumed on use — see
  `ConsumeRDPConnectGrant`). The VM's own RDP login still applies on top. Note the
  token is bound to the source IP. A host behind the same NAT could spend it
  during the window only if it also obtains the random token, for example by
  intercepting the pre-TLS request (and would still face the VM's RDP login).
  Because consumption happens at connection time, a connection that fails
  after authorization spends the grant, and reconnecting requires clicking
  **RDP** again.
- Logout is user-wide within the running gateway process: a valid `POST
  /logout` destroys all active browser sessions for that username and closes
  tracked live RDP, serial-console, and VNC WebSocket connections. External
  directory changes are checked at the next LDAP login. Existing browser
  sessions retain their cached identity and role until logout or expiry, and
  can authorize new connections during that time. Already-open streams are
  not continuously re-checked against LDAP.
- All environment-backed parameters must be defined in
  `internal/config/config.go`. Reading `os.Getenv` directly from feature code
  is not allowed and is enforced by `make lint`.
- The public listener defaults to `:443` and is configurable with `LISTEN_ADDR`.
  There is no public plaintext HTTP listener. An optional profiler listener,
  configured with `PPROF_LISTEN_ADDR`, uses HTTP on a literal loopback IP.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for prerequisites, focused test commands,
the shared Go module layout, and pull-request guidance. Release notes and
packaged builds are published through [GitHub Releases](https://github.com/define42/DevBox-Gateway/releases).
The [documentation index](llms.txt) lists the main guides and source references
for automated tooling.

## License

DevBox-Gateway is released under the [MIT License](LICENSE). The `LICENSE`
file is bundled into the RPM (`/usr/share/licenses/devbox-gateway/LICENSE`)
and Debian (`/usr/share/doc/devbox-gateway/copyright`) packages.

The bundled SauronAgent code has its own [Apache-2.0 license](SauronAgent/LICENSE).
The embedded noVNC assets retain their [license notices](internal/webassets/novnc/LICENSE.txt),
including notices for bundled dependencies. Sharing a Go module does not replace
these component licenses.
