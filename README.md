# DevBox Gateway

[![codecov](https://codecov.io/gh/define42/devbox-gateway/graph/badge.svg?token=HS2KD8YHNG)](https://codecov.io/gh/define42/devbox-gateway)

DevBox Gateway is a self-hosted gateway for libvirt-managed virtual desktops.
It provides an HTTPS dashboard and an RDP-over-TLS proxy on one public port,
with LDAP authentication for both. Users can create and manage their VMs,
download an RDP connection file, and open serial or noVNC consoles in the browser.
SauronAgent collects audit events from inside the guests over virtio-vsock.

> This is **not Microsoft RD Gateway**. It proxies raw RDP (X.224 / TPKT) with
> TLS on both sides; it does not implement Microsoft's HTTP/UDP RD Gateway
> transports. See [connecting an RDP client](page/docs/usage/rdp.md).

## Getting started

Download gateway and SauronAgent packages, plus **Ubuntu 26.04**, **Ubuntu 24.04**,
and **Rocky Linux 9** XFCE VM images, from
[GitHub Releases](https://github.com/define42/DevBox-Gateway/releases).

Choose an installation guide for your host:

| Deployment | Supported host | Docker required on the host? |
| --- | --- | --- |
| [Native RPM](page/docs/installation/rpm.md) | Rocky Linux 9, x86_64 | No |
| [Native DEB](page/docs/installation/deb.md) | Debian 12, amd64 | No |
| [Docker Compose development stack](page/docs/installation/docker-compose.md) | Linux x86_64 with KVM | Yes, with Docker Compose v2 |

For the complete RPM setup, follow the
[production installation walkthrough](page/docs/installation/production.md):
install, configure, add the first image, start, sign in, and upload more images.

The native packages run the gateway directly as a systemd service using the
host's libvirt/QEMU/KVM stack. They require an LDAP server and at least one
base image before the first start. **Docker is not required to install the
RPM or DEB and use prebuilt VM images.** Splunk is optional; native installations
default to local audit files.

Follow [downloading VM images](page/docs/vm-images.md) to reconstruct and verify
the release assets, then follow your installation guide for host setup,
configuration, and service startup. The guest operating system does not change
the native package's supported host distribution.

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

## Documentation

The [documentation index](page/docs/index.md) links to the complete guides:

- [Installation and deployment options](page/docs/installation/index.md)
- [VM image downloads](page/docs/vm-images.md) and [image builds](page/docs/development/building.md#building-vm-images)
- [Dashboard and login](page/docs/usage/dashboard.md), [RDP clients](page/docs/usage/rdp.md)
- [Configuration reference](page/docs/configuration/index.md), [LDAP](page/docs/configuration/ldap.md), [TLS](page/docs/configuration/tls.md), [libvirt and storage](page/docs/configuration/storage.md)
- [Audit logs and Splunk](page/docs/operations/audit-logs.md), [SauronAgent guest events](page/docs/operations/guest-events.md), [health checks](page/docs/operations/health-checks.md)
- [Architecture](page/docs/architecture.md), [security](page/docs/security.md), [HTTP API](page/docs/reference/http-api.md)
- [Building from source](page/docs/development/building.md), [testing](page/docs/development/testing.md), [repository layout](page/docs/development/repository-layout.md)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for prerequisites, focused test commands,
the shared Go module layout, and pull-request guidance. Documentation lives in
[`page/docs/`](page/docs/index.md); see [previewing and checking the documentation](page/docs/development/documentation.md)
before changing it. The [documentation index for automated tooling](llms.txt)
lists guides and source references.

## License

DevBox-Gateway is released under the [MIT License](LICENSE). The `LICENSE`
file is bundled into the RPM (`/usr/share/licenses/devbox-gateway/LICENSE`)
and Debian (`/usr/share/doc/devbox-gateway/copyright`) packages.

The bundled SauronAgent code has its own [Apache-2.0 license](SauronAgent/LICENSE).
The embedded noVNC assets retain their [license notices](internal/webassets/novnc/LICENSE.txt),
including notices for bundled dependencies. Sharing a Go module does not replace
these component licenses.
