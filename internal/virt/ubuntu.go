package virt

import (
	"fmt"
)

func UbuntuDomain(name, seedIso, storagePoolName, serialSocketPath string, vcpu int, memoryMiB int) string {
	return fmt.Sprintf(`<domain type='kvm'>
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

    <!-- Network (user-mode NAT, like -netdev user) -->
<interface type='network'>
  <source network='default'/>
  <model type='virtio'/>
</interface>

    <!-- Graphics -->
    <graphics type="vnc" autoport="no">
    <listen type="none"/>
    </graphics>

    <!-- Video -->
    <video>
      <model type='virtio' heads='1' primary='yes'/>
    </video>

    <!-- Serial console -->
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
</domain>`, name, memoryMiB, memoryMiB, vcpu, storagePoolName, name, storagePoolName, seedIso, serialSocketPath)
}
