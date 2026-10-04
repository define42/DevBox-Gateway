# Quick start (Docker Compose)

## Host prerequisites

Host requirements for this Docker Compose setup:

- Docker and Docker Compose v2.
- Linux x86_64 with KVM available to QEMU and the `vhost_vsock` kernel module loaded.
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
  valid QCOW2 image — follow
  [Downloading VM images](../vm-images.md#downloading-vm-images) before starting the stack.

## Start the stack

```sh
git clone https://github.com/define42/DevBox-Gateway.git
cd DevBox-Gateway
make run
```

`make run` stops any previous stack, rebuilds the images, and starts:

- `gateway` — the Go binary, using host networking and listening on
  `https://localhost` (port `443`).
- `ldap` — a `glauth/glauth` LDAP server pre-populated from
  `testldap/default-config.cfg` for local development.
- `splunk` — a `splunk/splunk` Splunk Enterprise instance that receives
  application audit events from the gateway over HEC (see
  [Forwarding to Splunk HEC](../operations/audit-logs.md#forwarding-to-splunk-hec)), and every SauronAgent
  event from inside the VMs (see
  [SauronAgent guest events](../operations/guest-events.md#sauronagent-guest-events)). Starting it accepts
  the [Splunk General Terms](https://www.splunk.com/en_us/legal/splunk-general-terms.html).

## Sign in

Open `https://localhost`, accept the local self-signed certificate, and sign
in with `johndoe` / `dogood`. See [Login flow](../usage/dashboard.md#login-flow)
for the dashboard and the seeded administrator account. This Compose
configuration is a local development setup with test credentials and
certificate verification disabled for LDAP and Splunk.

## View events in Splunk

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

## Stop the stack

Run `docker compose stop` from the repository directory.
