# Installing the deb

After the Debian-specific package and libvirt steps below, the
[production walkthrough](production.md#4-configure-dns-tls-and-network-access)
covers gateway configuration, the first base image, administrator login, and
image uploads. Use your Debian host's firewall and certificate-trust tools in
place of the walkthrough's Rocky Linux commands.

For a native deployment on Debian 12 (amd64), each tagged release also publishes
a `devbox-gateway_<version>_amd64.deb` artifact on the
[GitHub Releases](https://github.com/define42/devbox-gateway/releases) page,
built and installation-tested against Debian 12 (Bookworm). It uses the same
source version as the RPM and container, with a separate binary linked against
Debian 12 libraries. Other Debian-based distributions are not part of the
native compatibility baseline.

Docker and Docker Compose are not required to install or run this package.

## Package contents and dependencies

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

## Install and start

1. **Install** (let `apt` pull in the dependencies):

   ```sh
   sudo apt install ./devbox-gateway_<version>_amd64.deb
   ```

2. **Satisfy the native runtime prerequisites**: a running libvirt daemon
   (version 6.2.0 or newer), QEMU/KVM, and the `vhost_vsock` kernel module loaded
   for guest-event collection. Ensure the service can write to `DATA_ROOT_DIR`
   (native default `/var/lib/libvirt/devbox-gateway`) and place at least one
   [prebuilt VM image](../vm-images.md#downloading-vm-images) in
   `<DATA_ROOT_DIR>/baseimages` before starting the gateway. It refuses to start
   with an empty image library. The gateway defines and starts its storage pool
   when needed; see [Libvirt and VM storage](../configuration/storage.md#libvirt-and-vm-storage)
   for the host setup.

   On Debian 12, enable the libvirt daemon and check the system connection:

   ```sh
   sudo systemctl enable --now libvirtd
   sudo virsh -c 'qemu+unix:///system?socket=/var/run/libvirt/libvirt-sock' version
   ```

   Package installation does not open the public gateway port. Allow `443/tcp`
   through the host firewall, or the port set by `LISTEN_ADDR`.

3. **Configure** the gateway:

   ```sh
   sudo nano /etc/devbox-gateway/devbox-gateway.conf
   ```

   Point the [LDAP settings](../configuration/ldap.md#ldap) at your directory;
   the native package does not provide the Compose stack's LDAP server or test
   accounts. Every setting is documented inline and in the
   [configuration reference](../configuration/index.md#configuration).
   Splunk is optional: the native defaults write application audit and guest
   events to local files. See [Audit logs and Splunk](../operations/audit-logs.md#audit-logs-and-splunk)
   and [SauronAgent guest events](../operations/guest-events.md#sauronagent-guest-events).

4. **Enable and start** the gateway:

   ```sh
   sudo systemctl enable --now devbox-gateway
   ```

   Installation enables the unit per systemd preset policy but does not start
   it.

5. **Check status and logs**:

   ```sh
   systemctl status devbox-gateway
   journalctl -u devbox-gateway -f
   ```

## Upgrade or remove

Install a newer DEB with `sudo apt install ./devbox-gateway_<version>_amd64.deb`.
An upgrade preserves your config and restarts the service. To remove the
package, run `sudo apt remove devbox-gateway`.

> Building the DEB yourself instead of downloading it is covered under
> [Building the deb](../development/building.md#building-the-deb).
