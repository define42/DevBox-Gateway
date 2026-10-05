# DevBox Gateway documentation

DevBox Gateway publishes libvirt-managed virtual desktops through an HTTPS
dashboard and an RDP-over-TLS proxy on one public port. LDAP authenticates
dashboard users and authorizes proxied RDP connections; SauronAgent collects
audit events from inside the guest VMs over virtio-vsock.

The gateway proxies raw RDP with TLS on both sides. It does not implement
Microsoft RD Gateway's HTTP/UDP transports. Read the
[RDP client guide](usage/rdp.md) before configuring a client.

## Get started

For a complete native setup, follow the
[production installation walkthrough](installation/production.md). It covers
installing the RPM, configuring LDAP and TLS, starting with an empty image
library, signing in as an administrator, and uploading the first image.

1. Choose a [deployment method](installation/index.md): native
   [RPM on Rocky Linux 9](installation/rpm.md), native
   [DEB on Debian 12](installation/deb.md), or the
   [Docker Compose development stack](installation/docker-compose.md).
   Native packages do not require Docker on the host.
2. Follow your installation guide to configure libvirt, LDAP, and the gateway,
   then start the service.
3. [Sign in to the dashboard](usage/dashboard.md) as an administrator.
   [Download and verify a VM image](vm-images.md), then upload it through
   **Admin → Base Images**. Releases include Ubuntu 26.04 XFCE, Ubuntu 24.04
   XFCE or GNOME, and Rocky Linux 9 XFCE images with SauronAgent already installed.
4. Create a VM from an uploaded image and
   [connect with an RDP client](usage/rdp.md).

Packages and VM images are available on
[GitHub Releases](https://github.com/define42/DevBox-Gateway/releases).
For a custom guest image, see [installing SauronAgent](installation/sauronagent.md).

## Configure and operate

| Guide | What it covers |
| --- | --- |
| [Configuration reference](configuration/index.md) | Config files, environment overrides, defaults, and value formats. |
| [LDAP](configuration/ldap.md) | Directory identities, login access, and administrator groups. |
| [TLS certificates](configuration/tls.md) | Public certificates and each VM's backend identity. |
| [Libvirt and storage](configuration/storage.md) | Host requirements, VM networking, base images, and isolation. |
| [Audit logs and Splunk](operations/audit-logs.md) | Application events, local logs, durable forwarding, and HEC acknowledgements. |
| [Audit coverage comparison](compliance.md) | Implemented audit coverage, event inventories, and deployment checks. |
| [SauronAgent guest events](operations/guest-events.md) | Guest collection, attribution, spooling, and delivery limits. |
| [Health checks](operations/health-checks.md) | Liveness, readiness, and recovery considerations. |
| [Security](security.md) | Trust boundaries, connection grants, and session behavior. |

## Understand and develop

- [Architecture](architecture.md) explains HTTPS/RDP dispatch and connection handling.
- [HTTP API reference](reference/http-api.md) documents dashboard routes and WebSockets.
- [Building from source](development/building.md) covers binaries, packages, VM images, and UI assets.
- [Testing and linting](development/testing.md) describes local verification.
- [Repository layout](development/repository-layout.md) maps the source tree.
- [Documentation development](development/documentation.md) explains site previews and checks.
- [Contributing](https://github.com/define42/DevBox-Gateway/blob/main/CONTRIBUTING.md) covers contributor setup and pull requests.
