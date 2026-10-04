# Installing the RPM

For the complete first-time setup, follow the
[production installation walkthrough](production.md), including configuration,
the first base image, administrator login, and image uploads. This page provides
the package reference and service commands.

For a native (non-container) deployment on Rocky Linux 9 (x86_64), each tagged
release publishes a `devbox-gateway-<version>-1.x86_64.rpm` artifact on the
[GitHub Releases](https://github.com/define42/devbox-gateway/releases) page. The
RPM version matches the container image tag for the same release. Packages are
built and installation-tested against the current Rocky Linux 9 repositories;
other RPM distributions are not part of the native compatibility baseline.

Docker and Docker Compose are not required to install or run this package.

## Package contents and dependencies

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

## Install and start

1. **Install** (let `dnf` pull in the dependencies):

   ```sh
   sudo dnf install ./devbox-gateway-<version>-1.x86_64.rpm
   ```

2. **Satisfy the native runtime prerequisites**: a running libvirt daemon
   (version 6.2.0 or newer), QEMU/KVM, the `vhost_vsock` kernel module loaded for
   guest-event collection, a storage pool, write access to `DATA_ROOT_DIR`
   (native default `/var/lib/libvirt/devbox-gateway`), and at least one base
   image in `<DATA_ROOT_DIR>/baseimages` (the gateway refuses to start with an
   empty library). Docker and Docker Compose are not required.
   The default lives under `/var/lib/libvirt` so
   images and sockets sit in a tree QEMU can use under SELinux without
   relabeling. Use a [prebuilt release image](../vm-images.md#downloading-vm-images); see
   [Libvirt and VM storage](../configuration/storage.md#libvirt-and-vm-storage) for the host setup.

   Make sure libvirt itself is enabled — the gateway's unit only *wants*
   `libvirtd.service`, it does not enable libvirt for you. If the host uses
   modular, socket-activated daemons, enable the sockets the gateway uses:

   ```sh
   sudo systemctl enable --now virtqemud.socket virtnetworkd.socket virtstoraged.socket virtnwfilterd.socket virtproxyd.socket
   ```

   The proxy socket provides the gateway's `/var/run/libvirt/libvirt-sock`
   endpoint. Modular hosts must keep `libvirtd.service` masked because the
   gateway unit otherwise requests it at startup; see the
   [production walkthrough](production.md#3-enable-libvirt-and-guest-event-transport).
   On a host using the monolithic daemon, use instead:

   ```sh
   sudo systemctl enable --now libvirtd
   ```

   If you get `Unit file libvirtd.service does not exist`, your system uses the
   modular daemons above. Keep the host's existing daemon mode; see the
   [production walkthrough](production.md#3-enable-libvirt-and-guest-event-transport)
   for mode checks. Verify the gateway's exact libvirt connection with
   `sudo virsh -c 'qemu+unix:///system?socket=/var/run/libvirt/libvirt-sock' version`.

3. **Configure** the gateway by editing the config file (every setting is
   documented inline; see [Configuration](../configuration/index.md#configuration)):

   ```sh
   sudo nano /etc/devbox-gateway/devbox-gateway.conf
   ```

   Point the [LDAP settings](../configuration/ldap.md#ldap) at your directory;
   the native package does not provide the Compose stack's LDAP server or test
   accounts. Splunk is optional: the native defaults write application audit
   and guest events to local files. See [Audit logs and Splunk](../operations/audit-logs.md#audit-logs-and-splunk)
   and [SauronAgent guest events](../operations/guest-events.md#sauronagent-guest-events).

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

## Upgrade or remove

To upgrade, install the newer RPM (`sudo dnf upgrade ./devbox-gateway-*.rpm`);
your config file is preserved and the service is restarted automatically. To
remove it: `sudo dnf remove devbox-gateway`.

> Building the RPM yourself instead of downloading it is covered under
> [Building the RPM](../development/building.md#building-the-rpm).
