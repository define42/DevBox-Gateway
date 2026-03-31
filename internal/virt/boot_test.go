package virt_test

import (
	"fmt"
	"log"
	"rdptlsgateway/internal/config"
	typesUser "rdptlsgateway/internal/types"
	"rdptlsgateway/internal/virt"
	"testing"
	"time"

	"libvirt.org/go/libvirt"
)

const (
	testVMName   = "test-vm"
	testUsername = "testuser"
	testPassword = "dogood"
)

func checkCpuAndMemory(testUsername, vmName string, vcpu, memory int, conn *libvirt.Connect) error {
	vms, err := virt.ListVMs(testUsername, conn)
	if err != nil {
		return err
	}

	for _, v := range vms {
		if v.Name == vmName {
			if v.VCPU == vcpu && v.MemoryMiB == memory {
				return nil
			}
			return fmt.Errorf("VM %s has CPU %d and Memory %dMB, expected CPU 2 and Memory 2048MB", vmName, v.VCPU, v.MemoryMiB)
		}
	}

	return fmt.Errorf("VM %s not found for CPU and Memory check", vmName)
}

func checkState(testUsername, vmName, state string, conn *libvirt.Connect) error {
	vms, err := virt.ListVMs(testUsername, conn)
	if err != nil {
		return err
	}

	for _, v := range vms {
		if v.Name == vmName {
			if v.State == state {
				return nil
			}
			return fmt.Errorf("VM %s state is %s, expected %s", vmName, v.State, state)
		}
	}

	return fmt.Errorf("VM %s with state %s not found", vmName, state)
}

func TestStartVM(t *testing.T) {

	//tmpDir := t.TempDir()

	settings := config.NewSettingType(false)
	if settings.OverwriteForTestString(config.VIRT_SERIAL_SOCKET_DIR, t.TempDir()) != nil {
		t.Fatalf("Failed to overwrite VIRT_SERIAL_SOCKET_DIR for test")
	}
	if settings.OverwriteForTestString(config.VIRT_VNC_SOCKET_DIR, t.TempDir()) != nil {
		t.Fatalf("Failed to overwrite VIRT_VNC_SOCKET_DIR for test")
	}

	user, err := typesUser.NewUser(testUsername, testPassword)
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	vmName, err := virt.BootNewVM(testVMName, user, settings, 4, 4096)
	if err != nil {
		t.Fatalf("Failed to boot new VM %s: %v", vmName, err)
	}

	conn, err := libvirt.NewConnect(virt.LibvirtURI())
	if err != nil {
		log.Printf("list vms connect: %v", err)
	}
	defer conn.Close()

	//######################### Test StartExistingVM #########################
	time.Sleep(20 * time.Second) // Wait for VM to boot up

	if err := checkState(testUsername, vmName, "running", conn); err != nil {
		t.Fatalf("VM %s is not running as expected: %v", vmName, err)
	}

	//######################### Test ShutdownVM #########################
	if err := virt.ShutdownVM(vmName); err != nil {
		t.Fatalf("Failed to shutdown VM %s: %v", vmName, err)
	}
	time.Sleep(10 * time.Second) // Wait for shutdown to complete
	if err := checkState(testUsername, vmName, "shut off", conn); err != nil {
		t.Fatalf("VM %s is not shut off as expected: %v", vmName, err)
	}

	//######################## Test UpdateVMResources #########################
	if err := virt.UpdateVMResources(vmName, 2, 2048); err != nil {
		t.Fatalf("Failed to update VM %s resources: %v", vmName, err)
	}

	if err := checkCpuAndMemory(testUsername, vmName, 2, 2048, conn); err != nil {
		t.Fatalf("VM %s does not have updated CPU and Memory as expected: %v", vmName, err)
	}

	//######################### Test StartExistingVM Again #########################
	// RewstartVM will start the VM again if it's shut off
	if err := virt.RestartVM(vmName); err != nil {
		t.Fatalf("Failed to start VM %s: %v", vmName, err)
	}

	time.Sleep(20 * time.Second) // Wait for startup to complete

	if err := checkState(testUsername, vmName, "running", conn); err != nil {
		t.Fatalf("VM %s is not running after restart as expected: %v", vmName, err)
	}

	// Cleanup: Destroy the VM after test
	// (In a real test, consider using defer to ensure cleanup)
	err = virt.RemoveVM(vmName, settings)
	if err != nil {
		t.Fatalf("Failed to destroy VM %s: %v", vmName, err)
	}

	// Verify that the VM has been removed
	vms, err := virt.ListVMs("", conn)
	if err != nil {
		t.Fatalf("Failed to list VMs after deletion: %v", err)
	}
	for _, v := range vms {
		if v.Name == vmName {
			t.Fatalf("VM %s still found in VM list after deletion", vmName)
		}
	}
}
