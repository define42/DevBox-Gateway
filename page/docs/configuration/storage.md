# Libvirt and VM storage

The dashboard manages VMs through libvirt. The gateway expects:

- Access to the host libvirt socket at `/var/run/libvirt/libvirt-sock`.
  Native installations use it directly; `docker-compose.yml` bind-mounts
  `/var/run/libvirt` into the container.
- A storage pool named by `VIRT_STORAGE_POOL_NAME` (default `desktop`) backed
  by `$DATA_ROOT_DIR/image` on the host. The gateway defines and starts this
  pool automatically if it is missing.
- The dedicated libvirt `devbox` NAT network (`virbr-devbox`,
  `192.168.123.0/24`, host gateway `192.168.123.1`). The gateway defines, starts,
  and enables autostart for it. Reserve this subnet for the gateway and attach
  only gateway-managed VMs to this bridge.
- Access to the base image library directory (`BASE_IMAGE_DIR`, default
  `$DATA_ROOT_DIR/baseimages`). The gateway creates it if missing and accepts an
  empty library at startup. Directory filesystem errors still prevent startup.
  VM creation requires a valid QCOW2 disk image named `.img`, `.qcow2`, or `.raw`.
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
lets each user pick which image to clone for a new VM. **An empty library does
not prevent startup or administrator access.** VM creation remains unavailable
until a valid image is uploaded or copied into the directory. Deleting the
final image blocks new VM creation until another is added, but the gateway
can still restart.

To populate an empty library, configure `ADMIN_GROUP`, sign in as a direct
member who also meets `LDAP_REQUIRED_GROUPS`, and open **Admin → Base Images**.
[Download a VM image](../vm-images.md#downloading-vm-images) from this project's
[GitHub Releases](https://github.com/define42/DevBox-Gateway/releases), join its
parts, verify its checksum, and upload the complete `.img`. Ubuntu 26.04 XFCE,
Ubuntu 24.04 XFCE, and Rocky Linux 9 XFCE images are available. See the
[production walkthrough](../installation/production.md#7-log-in-as-an-administrator)
for the first upload.

You can also [build an Ubuntu or Rocky Linux XFCE image from this checkout](../development/building.md#building-vm-images),
including its matching SauronAgent package, and copy the resulting `.img` into
`BASE_IMAGE_DIR` or upload it through the administrator's **Base Images** modal.

Because `docker-compose.yml` already bind-mounts `/data/`, files dropped in
`/data/baseimages` on the host are visible to the gateway container.

For a native RPM or deb install the data root defaults to
`/var/lib/libvirt/devbox-gateway`. Optional host imports go into
`/var/lib/libvirt/devbox-gateway/baseimages` (or the directory configured by
`DATA_ROOT_DIR` / `BASE_IMAGE_DIR`).
