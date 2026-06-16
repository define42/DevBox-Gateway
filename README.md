# RDP-TLS-Gateway

[![codecov](https://codecov.io/gh/define42/rdp-tls-gateway/graph/badge.svg?token=HS2KD8YHNG)](https://codecov.io/gh/define42/rdp-tls-gateway)

`rdp-tls-gateway` is a self-hosted gateway that publishes libvirt-managed virtual
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
- [Login flow](#login-flow)
- [Connecting an RDP client](#connecting-an-rdp-client)
- [Configuration](#configuration)
  - [Disabling clipboard and drive redirection](#disabling-clipboard-and-drive-redirection)
  - [SSH reverse tunnel (publish behind NAT)](#ssh-reverse-tunnel-publish-behind-nat)
  - [TLS certificates](#tls-certificates)
  - [LDAP](#ldap)
  - [Local users](#local-users)
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
  restart, shutdown, remove, resize CPU/RAM).
- **In-browser consoles**: serial console and noVNC streamed over WebSocket.
- **LDAP authentication** with optional StartTLS and optional certificate
  verification.
- **ACME / Let's Encrypt** support for automatic public TLS certificates, with
  a self-signed fallback for local development.
- **Per-session RDP hardening**: optionally strip the `cliprdr` (clipboard) and
  `rdpdr` (drive/printer/smart-card redirection) static virtual channels from
  every proxied session, regardless of client or VM Group Policy.
- **Libvirt integration** for managing QEMU/KVM virtual machines from a
  configurable storage pool, with base image auto-download.
- **Single port** (`:443`) for everything: dashboard, websockets, and RDP.

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
                │  /api/dashboard/vnc/...      │  │ (with optional channel    │
                │  static assets               │  │  stripping for cliprdr /  │
                └────────────────┬─────────────┘  │  rdpdr in MCS Connect)    │
                                 │                └─────────┬─────────────────┘
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
4. TCP-connect to the chosen backend.
5. Send a fresh Connection Request to the backend requesting TLS only.
6. Read the backend's Connection Confirm and require `PROTOCOL_SSL`.
7. Complete the backend TLS handshake (backend cert verification is skipped).
8. Splice bytes between client TLS and backend TLS for the rest of the session.

## Quick start (Docker Compose)

Requirements on the host:

- Docker and Docker Compose v2.
- A libvirt daemon reachable at `/var/run/libvirt` (the compose file
  bind-mounts it into the gateway container).
- A `virbr0` bridge for the macvlan network (the default libvirt NAT bridge).
- Write access to `/data/` on the host (used for ACME data, VM images, and
  serial / VNC sockets).
- At least one base disk image in `/data/baseimages` (`.img`, `.qcow2`, or
  `.raw`). The gateway will not start with an empty library — see
  [Libvirt and VM storage](#libvirt-and-vm-storage) for a download example.

Start the stack:

```sh
make run
```

This stops any previous stack, rebuilds the images, and starts:

- `gateway` — the Go binary, listening on `https://localhost` (port `443`).
- `ldap` — a `glauth/glauth` LDAP server pre-populated from
  `testldap/default-config.cfg` for local development.

To stop everything: `docker compose stop`.

## Installing the RPM

For a native (non-container) deployment on an RPM-based distribution
(Fedora / RHEL / Rocky / Alma / openSUSE …), each tagged release publishes a
`rdp-tls-gateway-<version>-1.x86_64.rpm` artifact on the
[GitHub Releases](https://github.com/define42/rdp-tls-gateway/releases) page. The
RPM version matches the container image tag for the same release.

The package installs:

| Path                                            | Purpose                                              |
|-------------------------------------------------|------------------------------------------------------|
| `/usr/bin/rdp-tls-gateway`                       | The gateway binary.                                  |
| `/usr/lib/systemd/system/rdp-tls-gateway.service`| systemd unit (runs as root, binds `:443`).          |
| `/etc/rdp-tls-gateway/rdp-tls-gateway.conf`      | Config file, marked `%config(noreplace)` so your edits survive upgrades. |

It requires `libvirt-libs` and `ca-certificates`, plus `libvirt-daemon-kvm` and
`qemu-kvm` — the local libvirt/KVM stack that hosts the virtual desktops.
`libvirt-daemon-kvm` pulls in the modular libvirt daemons
(`virtqemud`/`virtnetworkd`/`virtstoraged`), so `dnf` installs everything needed
to provision VMs. The package does not configure firewall rules; open the
gateway port yourself (`443/tcp` by default, or your custom `LISTEN_ADDR` port).

1. **Install** (let `dnf` pull in the dependencies):

   ```sh
   sudo dnf install ./rdp-tls-gateway-<version>-1.x86_64.rpm
   ```

2. **Satisfy the runtime prerequisites** — the same ones as the Docker quick
   start: a running libvirt daemon, a storage pool, write access to
   `DATA_ROOT_DIR` (native default `/var/lib/libvirt/rdp-tls-gateway`), and at
   least one base image in `<DATA_ROOT_DIR>/baseimages` (the gateway refuses to
   start with an empty library). The default lives under `/var/lib/libvirt` so
   images and sockets sit in a tree QEMU can use under SELinux without
   relabeling. See [Libvirt and VM storage](#libvirt-and-vm-storage).

   Make sure libvirt itself is enabled — the gateway's unit only *wants*
   `libvirtd.service`, it does not enable libvirt for you. On Fedora / RHEL 9+
   (and recent Debian/Ubuntu) libvirt ships as modular, socket-activated daemons,
   so enable the sockets the gateway uses:

   ```sh
   sudo systemctl enable --now virtqemud.socket virtnetworkd.socket virtstoraged.socket
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
   sudo nano /etc/rdp-tls-gateway/rdp-tls-gateway.conf
   ```

4. **Enable and start** the service (installation does not start it
   automatically):

   ```sh
   sudo systemctl enable --now rdp-tls-gateway
   ```

5. **Check status and logs**:

   ```sh
   systemctl status rdp-tls-gateway
   journalctl -u rdp-tls-gateway -f
   ```

To upgrade, install the newer RPM (`sudo dnf upgrade ./rdp-tls-gateway-*.rpm`);
your config file is preserved and the service is restarted automatically. To
remove it: `sudo dnf remove rdp-tls-gateway`.

> Building the RPM yourself instead of downloading it is covered under
> [Building from source](#building-from-source).

## Installing the deb

For a native deployment on a Debian-based distribution (Debian / Ubuntu / Mint
…), each tagged release also publishes a `rdp-tls-gateway_<version>_amd64.deb`
artifact on the
[GitHub Releases](https://github.com/define42/rdp-tls-gateway/releases) page,
built from the same binary as the RPM and container for that release.

The package installs:

| Path                                            | Purpose                                              |
|-------------------------------------------------|------------------------------------------------------|
| `/usr/bin/rdp-tls-gateway`                       | The gateway binary.                                  |
| `/lib/systemd/system/rdp-tls-gateway.service`    | systemd unit (runs as root, binds `:443`).          |
| `/etc/rdp-tls-gateway/rdp-tls-gateway.conf`      | Config file, registered as a `conffile` so your edits survive upgrades. |

It depends on `libvirt0` and `ca-certificates`, plus `libvirt-daemon-system` and
`qemu-system-x86` — the local libvirt/KVM stack that hosts the virtual desktops
(the Debian-named counterparts of the RPM's requires).

1. **Install** (let `apt` pull in the dependencies):

   ```sh
   sudo apt install ./rdp-tls-gateway_<version>_amd64.deb
   ```

2. Then follow the same steps as the RPM install above — satisfy the libvirt/KVM
   runtime prerequisites, edit `/etc/rdp-tls-gateway/rdp-tls-gateway.conf`, and
   `sudo systemctl enable --now rdp-tls-gateway`. Installation enables the unit
   per systemd preset policy but does not start it; an upgrade preserves your
   config and restarts the service.

To remove it: `sudo apt remove rdp-tls-gateway` (add `--purge` to also delete the
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

- Create a new VM (name, base image, vCPU count, memory).
- Start / restart / shutdown / remove existing VMs that you own.
- Update CPU and memory allocation.
- Open a serial console or noVNC session in the browser.
- Download an `.rdp` file (named after the VM, e.g. `alice-desktop.rdp`)
  preconfigured for the gateway.

The same `johndoe` / `dogood` credentials are exercised by the LDAP
integration tests, so they are also the recommended local smoke-test account.

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
(default `/etc/rdp-tls-gateway/rdp-tls-gateway.conf`, overridable with the
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
| `TIMEOUT`                 | `10s`                                                                                                            | Handshake / dial / read timeout for connection setup.                                             |
| `CERT_FILE`               | _(empty)_                                                                                                        | PEM-encoded TLS certificate for the front side. Empty → self-signed cert is generated.            |
| `KEY_FILE`                | _(empty)_                                                                                                        | PEM-encoded unencrypted private key matching `CERT_FILE`.                                         |
| `ACME_ENABLE`             | `false`                                                                                                          | Enable ACME (Let's Encrypt) certificate management via certmagic on the front side.               |
| `ACME_EMAIL`              | _(empty)_                                                                                                        | ACME account contact email (recommended when `ACME_ENABLE=true`).                                 |
| `ACME_CA`                 | _(empty)_                                                                                                        | ACME directory URL, or `staging` for the Let's Encrypt staging endpoint.                          |
| `FRONT_DOMAIN`            | `desktop.local.gd`                                                                                               | Domain served by the dashboard and used as the suffix for VM SNI routing labels.                  |
| `SNI_HASH_SECRET`         | _(empty)_                                                                                                        | Secret keying the HMAC that turns VM names into opaque SNI labels. Empty → auto-generated once and persisted to `<DATA_ROOT_DIR>/sni_hash.secret` so labels stay stable across restarts. |
| `DATA_ROOT_DIR`           | `/var/lib/libvirt/rdp-tls-gateway`                                                                               | Root directory for gateway-managed state (ACME data, images, serial sockets, VNC sockets). Under `/var/lib/libvirt` so QEMU can use it under SELinux. The bundled `docker-compose.yml` overrides this to `/data`. |
| `VIRT_STORAGE_POOL_NAME`  | `desktop`                                                                                                        | Libvirt storage pool to allocate VM volumes in.                                                   |
| `BASE_IMAGE_DIR`          | _(empty → `<DATA_ROOT_DIR>/baseimages`)_                                                                          | Directory of selectable base VDI images (`.img`, `.qcow2`, `.raw`). Users pick one per VM in the dashboard. The gateway refuses to start if it is empty. |
| `LDAP_URL`                | `ldaps://ldap:389`                                                                                               | LDAP server URL.                                                                                  |
| `LDAP_BASE_DN`            | `dc=glauth,dc=com`                                                                                               | LDAP search base.                                                                                 |
| `LDAP_USER_FILTER`        | `(mail=%s)`                                                                                                      | LDAP search filter; `%s` is replaced with `<username>@LDAP_USER_DOMAIN`.                          |
| `LDAP_USER_DOMAIN`        | `@example.com`                                                                                                   | Domain appended to bare usernames before they are substituted into `LDAP_USER_FILTER`.            |
| `LDAP_STARTTLS`           | `false`                                                                                                          | When `true`, upgrade plain LDAP connections with StartTLS.                                        |
| `LDAP_SKIP_TLS_VERIFY`    | `true`                                                                                                           | When `true`, skip TLS certificate verification against the LDAP server.                           |
| `LOCAL_USER_SHA256`       | _(empty)_                                                                                                        | `;`-delimited list of `sha256("username:password")` hex digests for local users authenticated without LDAP. Checked before LDAP. |
| `LOGIN_RATE_LIMIT_MAX_ATTEMPTS` | `5`                                                                                                      | Maximum failed login attempts allowed per username or client IP within `LOGIN_RATE_LIMIT_WINDOW`. Set `<=0` to disable login throttling. |
| `LOGIN_RATE_LIMIT_WINDOW` | `5m`                                                                                                             | Rolling window for failed login attempt counting.                                                 |
| `LOGIN_RATE_LIMIT_LOCKOUT` | `15m`                                                                                                           | How long login attempts are rejected after the failure limit is reached.                          |
| `RDP_DISABLE_CLIPBOARD`   | `false`                                                                                                          | When `true`, strip the `cliprdr` virtual channel from every proxied session.                      |
| `RDP_DISABLE_DRIVES`      | `false`                                                                                                          | When `true`, strip the `rdpdr` virtual channel from every proxied session.                        |
| `DEBUG_CONNECTIONS`       | `false`                                                                                                          | When `true`, log every accepted front connection (HTTPS vs RDP, with source address) and every HTTP/WebSocket request (type, source address, method, path). Useful for tracing connectivity through the SSH reverse tunnel; noisy, so leave off in normal operation. |
| `SSH_TUNNEL_ENABLE`       | `false`                                                                                                          | Publish the front listener through an SSH reverse tunnel to a public relay instead of binding `LISTEN_ADDR` locally. See [SSH reverse tunnel](#ssh-reverse-tunnel-publish-behind-nat). |
| `SSH_TUNNEL_SERVER`       | _(empty)_                                                                                                        | Relay SSH endpoint as `<ip>:<port>`. Must be a literal IP (not a hostname) so DNS cannot redirect the outbound dial. |
| `SSH_TUNNEL_USER`         | _(empty)_                                                                                                        | SSH username used to authenticate to the relay.                                                   |
| `SSH_TUNNEL_PRIVATE_KEY`  | `/etc/rdp-tls-gateway/ssh/id_ed25519`                                                                            | Path to the PEM SSH private key used to authenticate to the relay.                                |
| `SSH_TUNNEL_PRIVATE_KEY_PASSPHRASE` | _(empty)_                                                                                              | Passphrase for the private key; empty for an unencrypted key. Masked in the printed settings table. |
| `SSH_TUNNEL_KNOWN_HOSTS`  | `/etc/rdp-tls-gateway/ssh/known_hosts`                                                                           | `known_hosts` file pinning the relay's SSH host key.                                              |
| `SSH_TUNNEL_REMOTE_ADDR`  | `:443`                                                                                                           | Address the relay listens on and forwards back through the tunnel.                                |
| `SSH_TUNNEL_KEEPALIVE_INTERVAL` | `15s`                                                                                                     | Interval between SSH keepalive probes that detect a dead tunnel.                                  |
| `SSH_TUNNEL_KEEPALIVE_TIMEOUT`  | `10s`                                                                                                     | How long to wait for a keepalive reply before treating the tunnel as dead.                        |

Booleans accept anything `strconv.ParseBool` recognises (`true`, `false`,
`1`, `0`, `yes`, `no`, …). Durations accept Go's `time.ParseDuration`
syntax (e.g. `15s`, `2m`, `500ms`).

### Disabling clipboard and drive redirection

The gateway can enforce a "no clipboard" and/or "no local drive mapping"
policy on every RDP session it proxies, independently of the client
configuration or the VM-side Group Policy. When enabled, the gateway parses the
client's MCS Connect Initial PDU after the TLS handshake and renames the
`cliprdr` and/or `rdpdr` static virtual channel entries in the CS_NET block to
unused names. The server allocates MCS channel IDs as usual (so the RDP
connection still establishes) but no clipboard or drive redirection service is
ever bound to the renamed channels.

| Environment variable     | Default | Effect                                                                                                                                                          |
|--------------------------|---------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `RDP_DISABLE_CLIPBOARD`  | `false` | When `true`, strip the `cliprdr` virtual channel so clipboard redirection is disabled.                                                                          |
| `RDP_DISABLE_DRIVES`     | `false` | When `true`, strip the `rdpdr` virtual channel so local drive mapping (and other RDPDR redirections such as printers and smart cards over RDPDR) is disabled.   |

### SSH reverse tunnel (publish behind NAT)

By default the gateway binds `LISTEN_ADDR` (`:443`) directly, which requires the
host to be reachable from clients. When the gateway runs behind NAT — on a home
or lab network with no inbound port forwarding — set `SSH_TUNNEL_ENABLE=true` to
publish it through a **public relay** instead:

```
                       SSH (gateway dials OUT)
   ┌─────────────┐   ───────────────────────────►   ┌──────────────────┐
   │  gateway    │   reverse tunnel (ssh -R)         │  public relay    │
   │  behind NAT │ ◄─────────────────────────────   │  (sshd)          │
   └─────────────┘   forwarded RDP/HTTPS conns       └────────┬─────────┘
                                                              │ :443
                                                       clients connect here
```

The gateway opens an outbound SSH connection to `SSH_TUNNEL_SERVER`, asks the
relay to listen on `SSH_TUNNEL_REMOTE_ADDR`, and serves every connection the
relay forwards back down the tunnel with the exact same HTTPS + RDP handling
used for a local listener. No inbound firewall rule is needed on the gateway
side; only the relay exposes a public port.

**Relay (`sshd`) requirements.** A stock OpenSSH server permits the reverse
tunnel but will *not* expose it on a public `:443` without changes, because of
two independent defaults plus one rule that is not configurable:

| `sshd_config` setting | Default | Effect on a `-R` reverse tunnel |
|-----------------------|---------|---------------------------------|
| `AllowTcpForwarding`  | `yes`   | Remote (`-R`) forwarding is allowed. |
| `GatewayPorts`        | `no`    | The forwarded port binds to `127.0.0.1` only, so no other host can connect to it. |
| `PermitListen`        | `any`   | Does not restrict which port may be forwarded (443 is not blocked here). |

On top of that, OpenSSH enforces — with no override — that **only the superuser
can forward privileged ports** (below 1024). So an ordinary login user cannot
bind `443` on the relay at all, even with `GatewayPorts yes`. Publishing the
relay's public `:443` therefore means working around both the loopback default
and the privileged-port rule. Pick one:

**Option A — unprivileged user + a root TCP proxy (recommended).** The gateway
forwards a high port on the relay's loopback (allowed for any user, and needing
no `GatewayPorts` change), and a small root-run service publishes `:443` by
relaying the raw TCP stream to it. Use a byte-level proxy — **not** an
HTTP/TLS-terminating reverse proxy, which would break SNI routing and the ACME
TLS-ALPN-01 challenge:

```bash
# On the relay, as a root system service (so it may bind privileged :443):
socat TCP-LISTEN:443,fork,reuseaddr TCP:127.0.0.1:8443
```
On the gateway: `SSH_TUNNEL_USER=rdptunnel`, `SSH_TUNNEL_REMOTE_ADDR=127.0.0.1:8443`.

**Option B — root SSH binding `:443` directly.** Simpler, but it grants the
gateway root SSH access to the relay. Enable wildcard binding and key-only root
login in the relay's `sshd_config`:

```
GatewayPorts yes
PermitRootLogin prohibit-password
```
On the gateway: `SSH_TUNNEL_USER=root`, `SSH_TUNNEL_REMOTE_ADDR=:443`.

In either case, lock the tunnel key down in the relay user's `authorized_keys`
so it can do nothing but the one forward, then restart `sshd`:

```
restrict,port-forwarding,permitlisten="127.0.0.1:8443" ssh-ed25519 AAAA...key... rdp-tls-gateway
```
(use `permitlisten="443"` for Option B).

**Gateway setup.**

1. Generate a key pair for the gateway and install the public key in the relay
   user's `authorized_keys` (`ssh-keygen` does not create the parent directory):
   ```bash
   mkdir -p /etc/rdp-tls-gateway/ssh
   ssh-keygen -t ed25519 -f /etc/rdp-tls-gateway/ssh/id_ed25519 -N ''
   ```
2. Pin the relay's host key so the outbound dial cannot be spoofed:
   ```bash
   ssh-keyscan -p 22 <relay-ip> > /etc/rdp-tls-gateway/ssh/known_hosts
   ```
3. Configure the tunnel (config file or environment). `SSH_TUNNEL_USER` and
   `SSH_TUNNEL_REMOTE_ADDR` follow whichever relay option you chose above; the
   recommended Option A looks like:
   ```ini
   SSH_TUNNEL_ENABLE=true
   SSH_TUNNEL_SERVER=203.0.113.10:22
   SSH_TUNNEL_USER=rdptunnel
   SSH_TUNNEL_REMOTE_ADDR=127.0.0.1:8443
   ```

`SSH_TUNNEL_SERVER` must be a literal IP address, not a hostname: on a private
host DNS may be resolved through a VPN, and pinning by IP closes the only
attacker-controlled lookup before the host-key pin is checked. If the tunnel
drops, a keepalive probe (`SSH_TUNNEL_KEEPALIVE_INTERVAL` /
`SSH_TUNNEL_KEEPALIVE_TIMEOUT`) detects it and the process exits with a failure
status so `systemd` (`Restart=on-failure`) re-establishes the connection.

**ACME over the tunnel.** `ACME_ENABLE=true` works through the tunnel: the
gateway brings the tunnel up first and only then starts certificate management,
so Let's Encrypt's TLS-ALPN-01 validation (which arrives on the relay's `:443`
and is forwarded down the tunnel) is answered by the gateway's own TLS
handshake. This requires that the relay's public `:443` is a **raw-TCP** path to
the gateway (the byte proxy in Option A or the direct forward in Option B — never
a TLS-terminating reverse proxy) and that every managed name — `FRONT_DOMAIN` and
each VM's routing label under it — resolves to the **relay's** public IP.
Issuance runs in the background with retry, so the
gateway boots immediately on the self-signed fallback and swaps in the real
certificate once it is obtained; a slow relay or unpropagated DNS never blocks
start-up.

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

Backend (VM) TLS certificates are intentionally **not** validated — VMs
typically present per-host self-signed certs.

### LDAP

For local development, the bundled `glauth` container is configured in
`testldap/default-config.cfg` and is reachable from the gateway container at
`ldaps://ldap:389`. For production, point `LDAP_URL` at your own directory and
adjust `LDAP_BASE_DN`, `LDAP_USER_FILTER`, and `LDAP_USER_DOMAIN` to match.
Prefer `ldaps://` or `LDAP_STARTTLS=true` and set
`LDAP_SKIP_TLS_VERIFY=false` once your CA chain is trusted.

### Local users

Alongside LDAP, a small set of accounts can be authenticated offline against a
static list of digests in `LOCAL_USER_SHA256` — useful for a break-glass admin
or a deployment without a directory. Each entry is the lowercase hex
`sha256("<username>:<password>")`, and multiple entries are separated by `;`.

Generate a digest:

```sh
printf '%s:%s' alice 's3cret' | sha256sum
```

Then configure one or more (whitespace around entries is ignored):

```sh
LOCAL_USER_SHA256=2bb80d537b1da3e38bd30361aa855686bde0eacd7162fef6a25fe97bf527a25b;<another-digest>
```

Local users are checked **before** LDAP, so a successful local match skips the
directory entirely (no LDAP round-trip, and it keeps working if LDAP is down). A
login that doesn't match any digest falls through to LDAP as usual. Leave
`LOCAL_USER_SHA256` empty to disable local users. Because the credential is a
plain salt-less digest, treat the config file as a secret and use strong,
unique passwords.

**Local users only (no LDAP).** Set `LDAP_URL=` (empty) to run without a
directory at all. The gateway then authenticates solely against
`LOCAL_USER_SHA256` and never attempts an LDAP connection — a login that matches
no digest is simply rejected. With the default non-empty `LDAP_URL`, the gateway
still treats LDAP as a fallback, so for a clean local-only deployment clear
`LDAP_URL` as well.

### Libvirt and VM storage

The dashboard manages VMs through libvirt. The gateway expects:

- A libvirt socket bind-mounted at `/var/run/libvirt` (already wired up in
  `docker-compose.yml`).
- A storage pool named by `VIRT_STORAGE_POOL_NAME` (default `desktop`) backed
  by `$DATA_ROOT_DIR/image` on the host. The gateway defines and starts this
  pool automatically if it is missing.
- The libvirt `default` NAT network (the `virbr0` bridge, `192.168.122.0/24`),
  which every VDI attaches to. The gateway defines, starts, and sets it to
  autostart automatically if it is missing — handy on a fresh modular-libvirt
  host (e.g. Rocky/RHEL 9) that ships without it.
- A base image library directory (`BASE_IMAGE_DIR`, default
  `$DATA_ROOT_DIR/baseimages`) containing at least one `.img`, `.qcow2`, or
  `.raw` disk image.
- Network reachability from the gateway container to each VM's RDP port over
  the `virbr0` bridge. The compose file attaches the gateway to a macvlan on
  `virbr0` with a fixed address of `192.168.122.254`.

Base images are operator-supplied: place one or more disk images in
`BASE_IMAGE_DIR`, and the dashboard create form lets each user pick which image
to clone for a new VM. **If the directory contains no usable image at startup,
the gateway fails to boot** with a clear error, so populate it first.

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
`/var/lib/libvirt/rdp-tls-gateway`, so populate
`/var/lib/libvirt/rdp-tls-gateway/baseimages` instead (or set `DATA_ROOT_DIR` /
`BASE_IMAGE_DIR` to wherever you keep images).

## Building from source

Requirements:

- Go (see `go.mod` for the minimum version).
- A C toolchain and `libvirt-dev` headers (the binary is built with
  `CGO_ENABLED=1`).
- Node.js + TypeScript 5.x for the dashboard bundle.

Build the dashboard bundle and the binary locally:

```sh
tsc -p tsconfig.json          # compile ui/dashboard.ts → static/dashboard.js
CGO_ENABLED=1 go build -o rdp-tls-gateway
```

Or build the production container image:

```sh
docker compose build
```

The multi-stage `Dockerfile` compiles the TypeScript UI and the Go binary in a
`golang:1.25-alpine` builder (pinned via the `GO_VERSION` build arg) and ships
only the resulting binary plus `libvirt-libs` and `ca-certificates` in the
runtime image.

### Building the RPM

To produce the same RPM the [release workflow](#installing-the-rpm) publishes,
run (overriding `VERSION` as needed):

```sh
make rpm VERSION=1.4.0
```

This compiles the UI and a `CGO_ENABLED=1` binary into `dist/`, then packages it
together with the systemd unit and `rdp-tls-gateway.conf` into
`dist/rdp-tls-gateway-<version>-1.x86_64.rpm` using the pure-Go
[`cmd/mkrpm`](cmd/mkrpm) helper — no `rpmbuild` or spec file required. Run `go run
./cmd/mkrpm -h` to see the available packaging flags.

### Building the deb

To produce the same `.deb` the [release workflow](#installing-the-deb) publishes,
run (overriding `VERSION` as needed):

```sh
make deb VERSION=1.4.0
```

This packages the same `dist/` artifacts into
`dist/rdp-tls-gateway_<version>_amd64.deb` using the pure-Go
[`cmd/mkdeb`](cmd/mkdeb) helper (built on `github.com/xor-gate/debpkg`) — no
`dpkg-deb` or `debian/` tree required. Run `go run ./cmd/mkdeb -h` to see the
available packaging flags. Override `DEB_ARCH` for a non-`amd64` target.

### UI (TypeScript)

The dashboard UI source lives in `ui/dashboard.ts`. Rebuild the embedded asset
with:

```sh
tsc -p tsconfig.json
```

The compiled output is `static/dashboard.js` and is embedded into the binary
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
├── main.go, handlers.go, dashboard.go, console.go, html.go, assets.go
│       Top-level HTTP/RDP entrypoints and request handlers.
├── internal/
│   ├── cert/        TLS certificate management (self-signed + ACME via certmagic).
│   ├── config/      Environment-backed settings registry (the only place env
│   │                vars may be read from).
│   ├── console/     Serial console and noVNC WebSocket handlers.
│   ├── contextKey/  Typed context-key helpers.
│   ├── dashboard/   Dashboard HTML / JSON rendering and VM listing.
│   ├── hash/        Password/credential hashing helpers.
│   ├── ldap/        LDAP login authentication.
│   ├── rdp/         RDP/X.224/MCS parsing, TLS-to-TLS proxy, channel stripping.
│   ├── session/     Cookie session manager and middleware.
│   ├── sshtunnel/   SSH reverse tunnel that publishes the front listener via a relay.
│   ├── types/       Shared types (e.g. authenticated user).
│   └── virt/        Libvirt VM lifecycle (create/start/stop/remove/resize).
├── ui/              TypeScript sources for the dashboard.
├── static/          Static assets, including the compiled dashboard.js.
├── testldap/        glauth config + cert/key used for local LDAP.
├── Dockerfile, docker-compose.yml, makefile, tsconfig.json
└── *_test.go        Unit and integration tests.
```

## Security notes

- Do **not** commit real certificates, private keys, or production LDAP
  endpoints. The files under `testldap/` are intended for local development
  only.
- Backend TLS verification is disabled by design (VMs typically use self-signed
  certs). Treat the network between the gateway and its VMs as trusted.
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
- When the SSH reverse tunnel is enabled, `SSH_TUNNEL_SERVER` must be a literal
  IP and the relay's host key must be pinned in `SSH_TUNNEL_KNOWN_HOSTS`; keep
  the tunnel private key (`SSH_TUNNEL_PRIVATE_KEY`) readable only by the gateway.

## License

See the repository for license details.
