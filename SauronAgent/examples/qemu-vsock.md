# Giving a VM a virtio-vsock device

SauronAgent talks to the hypervisor over `AF_VSOCK`, so every monitored VM
needs a virtio-vsock device and a context ID (CID). This is the whole of the
hypervisor-side setup.

## Context IDs

A CID is a 32-bit number identifying one endpoint of the vsock address space.
Three values are reserved:

| CID | Name | Meaning |
|---|---|---|
| 0 | `VMADDR_CID_HYPERVISOR` | the hypervisor process; not a usable destination here |
| 1 | `VMADDR_CID_LOCAL` | loopback within one machine |
| 2 | `VMADDR_CID_HOST` | the host, and the address every agent dials |
| 0xFFFFFFFF | `VMADDR_CID_ANY` | the wildcard the collector binds |

**Guest CIDs therefore start at 3.** Everything in between is yours to assign.

Two properties matter for SauronAgent:

* A CID is assigned by the hypervisor and written into the address of every
  connection the guest makes. The guest cannot choose or forge it, which is why
  the collector uses it as the VM's identity.
* A CID is unique **per hypervisor**, not globally. The kernel refuses to start
  a second VM with a CID already in use on that host, but nothing stops
  hypervisor A and hypervisor B both having a VM with CID 100.

## QEMU

```sh
qemu-system-x86_64 \
  -machine q35,accel=kvm \
  -m 4096 \
  -drive file=transfer-vm-03.qcow2,if=virtio \
  -device vhost-vsock-pci,id=vsock0,guest-cid=102
```

For machine types without PCI (for example `virt` on some arm64 setups) the
device is `vhost-vsock-device` on the virtio-mmio bus; the `guest-cid`
property is the same.

QEMU needs access to `/dev/vhost-vsock`. Under libvirt that is handled for you;
running QEMU by hand as a non-root user means giving that user access to the
node.

If QEMU refuses to start with

```text
vhost-vsock: unable to set guest cid: Address already in use
```

another VM on this hypervisor already has that CID.

## libvirt

```xml
<domain type='kvm'>
  <name>transfer-vm-03</name>
  ...
  <devices>
    ...
    <vsock model='virtio'>
      <cid auto='no' address='102'/>
    </vsock>
  </devices>
</domain>
```

Add it to a running definition with `virsh edit <domain>`; the device is added
on the next full start of the VM, not on a reboot from inside the guest.

`auto='yes'` lets libvirt pick a free CID instead. That is convenient and wrong
for this purpose: the CID is the VM's identity in the collector's `vms:` map,
and an identity that libvirt may choose differently after a redefinition turns
into events attributed to the wrong VM -- or to no VM at all. Pin it with
`auto='no'`.

Check what a domain actually got:

```sh
virsh dumpxml transfer-vm-03 | grep -A2 '<vsock'
```

## Assigning CIDs across a fleet

The CID map in `sauronhost.yaml` is only as good as the discipline behind it. A
workable scheme:

1. **Allocate CIDs from one authoritative list**, the same place you track VM
   names and UUIDs -- the CMDB, the Terraform state, the Ansible inventory.
   Treat a CID like an IP address: allocated once, recorded, never guessed.
2. **Make them unique across the whole fleet, not just per hypervisor.** The
   kernel only requires per-host uniqueness, but fleet-wide uniqueness means
   one `vms:` list can be deployed to every hypervisor unchanged, and a VM that
   is live-migrated keeps its identity on the destination host.
3. **Use a readable structure.** For example: `1xx` production web, `2xx`
   build and CI, `3xx` databases -- whatever survives contact with your naming.
   Start at 3 and stay well below `0xFFFFFFFF`.
4. **Never reuse a CID for a different VM** without removing the old entry from
   every collector first. A reused CID does not fail; it silently attributes
   the new VM's audit trail to the decommissioned VM's name, which is the worst
   possible failure mode for an audit system.
5. **Record the mapping in both directions.** When an alert says "no events
   from CID 102 for 5 minutes", the operator needs to get from 102 to a VM and
   a hypervisor without guessing.
6. **Mark production VMs `expected: true`.** That is what turns "this VM went
   quiet" into an alert instead of silence.

## Kernel modules

| Side | Module | Notes |
|---|---|---|
| Hypervisor | `vhost_vsock` | provides `/dev/vhost-vsock` for QEMU; pulls in `vhost`, `vmw_vsock_virtio_transport_common` and `vsock` |
| Guest | `vmw_vsock_virtio_transport` | the virtio transport; pulls in `vmw_vsock_virtio_transport_common` and `vsock` |

Both are usually autoloaded -- on the host when QEMU opens `/dev/vhost-vsock`,
in the guest when the virtio-vsock PCI device is probed. Load them explicitly
if they are not:

```sh
# hypervisor
modprobe vhost_vsock
echo vhost_vsock > /etc/modules-load.d/vsock.conf

# guest
modprobe vmw_vsock_virtio_transport
echo vmw_vsock_virtio_transport > /etc/modules-load.d/vsock.conf
```

A guest with no vsock transport reports it in an unhelpful way -- `connect()`
to CID 2 fails with `EAFNOSUPPORT`, `EPROTONOSUPPORT` or `ENODEV` depending on
how far the stack got -- so SauronAgent turns all three into one message
naming the modules and the QEMU device.

## Verifying the path end to end

### 1. The device exists in the guest

```sh
lspci | grep -i vsock
# 00:05.0 Communication controller: Red Hat, Inc. Virtio 1.0 socket
ls -l /dev/vsock
lsmod | grep vsock
```

### 2. The guest knows its own CID

```sh
python3 - <<'PY'
import fcntl, struct
IOCTL_VM_SOCKETS_GET_LOCAL_CID = 0x7b9
with open("/dev/vsock", "rb") as f:
    print(struct.unpack("I", fcntl.ioctl(f, IOCTL_VM_SOCKETS_GET_LOCAL_CID, b"\0" * 4))[0])
PY
# 102
```

It must match the `guest-cid` you configured and the `cid:` in the collector's
`vms:` list. (SauronAgent itself never asks for this value -- the host reads it
from the connection -- which is why the agent's systemd unit can run with
`PrivateDevices=true` and no `/dev/vsock` at all. This check is for operators.)

### 3. A plain socket gets through

Stop the collector first, or pick another port: only one listener can hold
port 9000.

```sh
# on the hypervisor
systemctl stop sauronhost
socat VSOCK-LISTEN:9000,fork -

# in the guest
echo "hello from $(hostname)" | socat - VSOCK-CONNECT:2:9000
```

The text appears on the hypervisor. If `socat` is unavailable, Python does the
same job:

```sh
# hypervisor
python3 -c 'import socket
s=socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM); s.bind((socket.VMADDR_CID_ANY,9000)); s.listen()
c,a=s.accept(); print("from CID",a[0],c.recv(100))'

# guest
python3 -c 'import socket
s=socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM); s.connect((2,9000)); s.send(b"hello")'
```

Note what the hypervisor side prints: the CID of the peer, read from the
connection rather than from anything the guest sent. That is exactly the
mechanism SauronHost uses to identify VMs.

### 4. The real thing

```sh
systemctl start sauronhost                    # hypervisor
systemctl restart sauronagent                 # guest
journalctl -u sauronagent -n 20               # guest: connected to the host
journalctl -u sauronhost  -f                  # hypervisor: events arriving
```

Then generate something audited in the guest -- `sudo -u nobody id`, or `cat
/etc/shadow` as root -- and watch it appear on the hypervisor with
`"source": {"cid": 102, "vm": "transfer-vm-03", ...}`.

## Guest-to-guest is not possible

A guest's vsock device reaches the host and nothing else: there is no route
from CID 102 to CID 103. Two VMs on the same hypervisor cannot see each other's
agents or interfere with each other's telemetry, and a compromised VM cannot
reach the collector's socket by any path other than its own device.

## Troubleshooting

See [../docs/deployment.md](../docs/deployment.md) for the full list. The three
most common:

| Symptom | Cause |
|---|---|
| agent logs "no AF_VSOCK transport on this system" | no vsock device on the VM, or the guest module is not loaded |
| agent connects, host never logs the session | the collector is not running, or is listening on another port |
| host logs events with `"known": false` | the CID has no entry in `vms:` |
