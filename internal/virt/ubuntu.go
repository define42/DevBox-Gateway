package virt

import (
	"encoding/xml"
	"fmt"
	"strings"
)

const ubuntuDomainXML = `<domain type='kvm'>
  <name>%s</name>
  <memory unit='MiB'>%d</memory>
  <currentMemory unit='MiB'>%d</currentMemory>
  <vcpu placement='static'>%d</vcpu>

  <os>
    <type arch='x86_64' machine='q35'>hvm</type>
    <boot dev='hd'/>
  </os>

  <cpu mode='host-passthrough' check='none'/>

  <features>
    <acpi/>
    <apic/>
    <vmport state='off'/>
  </features>

  <clock offset='utc'/>

  <devices>
    <!-- Main disk -->
    <disk type='volume' device='disk'>
      <driver name='qemu' type='qcow2'/>
      <source pool='%s' volume='%s'/>
      <target dev='vda' bus='virtio'/>
    </disk>

    <!-- cloud-init seed ISO -->
    <disk type='volume' device='disk'>
      <driver name='qemu' type='raw'/>
      <source pool='%s' volume='%s'/>
      <target dev='vdb' bus='virtio'/>
      <readonly/>
    </disk>

    <!-- Network: shared NAT bridge (libvirt 'default'). port isolated='yes'
         enforces VDI-to-VDI isolation on the host bridge so guests cannot reach
         each other, while still allowing DHCP/DNS from the gateway and NAT to
         the internet. -->
<interface type='network'>
  <source network='default'/>
  <model type='virtio'/>
  <port isolated='yes'/>
</interface>

    <!-- Graphics: libvirt manages the VNC unix socket (it allocates the path
         under the per-domain runtime dir and applies the svirt SELinux label so
         the confined QEMU can bind it). The actual path is read back from the
         gateway connects to it via libvirt's OpenGraphicsFD; see OpenVNCConn. -->
    <graphics type='vnc' autoport='no'>
      <listen type='socket'/>
    </graphics>

    <!-- Video -->
    <video>
      <model type='virtio' heads='1' primary='yes'/>
    </video>

    <!-- Serial console: explicit unix socket path. Unlike VNC, libvirt itself
         opens this socket (as root) and passes the fd to QEMU, so it is not
         subject to svirt's confinement and the gateway-chosen path is fine. -->
    <serial type='unix'>
      <source mode='bind' path='%s'/>
      <target port='0'/>
    </serial>

    <!-- Input -->
    <input type='tablet' bus='usb'/>

    <!-- RNG -->
    <rng model='virtio'>
      <backend model='random'>/dev/urandom</backend>
    </rng>
  </devices>
</domain>`

// UbuntuDomain returns the libvirt domain XML for a standard Ubuntu VM. The VNC
// socket is libvirt-managed (no explicit path) so libvirt allocates and
// SELinux-labels it under its per-domain runtime dir, while the serial socket
// uses the gateway-chosen serialSocketPath (libvirt opens it as root and passes
// the fd to QEMU, so svirt does not block it). Every interpolated value is
// XML-escaped so a name or path can never alter the document structure.
func UbuntuDomain(name, seedIso, storagePoolName, serialSocketPath string, vcpu int, memoryMiB int) string {
	return fmt.Sprintf(
		ubuntuDomainXML,
		xmlValue(name), memoryMiB, memoryMiB, vcpu,
		xmlValue(storagePoolName), xmlValue(name),
		xmlValue(storagePoolName), xmlValue(seedIso),
		xmlValue(serialSocketPath),
	)
}

// xmlValue escapes a string for safe inclusion in the domain XML in both element
// text and single-quoted attribute positions.
func xmlValue(s string) string {
	var buf strings.Builder
	if err := xml.EscapeText(&buf, []byte(s)); err != nil {
		return ""
	}
	return buf.String()
}
