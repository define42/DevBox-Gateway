package virt_test

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"rdptlsgateway/internal/config"
	typesUser "rdptlsgateway/internal/types"
	"rdptlsgateway/internal/virt"
	"syscall"
	"testing"
	"time"

	"libvirt.org/go/libvirt"
)

const (
	testVMName            = "test-vm"
	testUsername          = "testuser"
	testPassword          = "dogood"
	testTimeout           = 30 * time.Second
	legacyDefaultImageDir = "/data/desktop"
)

func newLibvirtAccessibleTempDir(t *testing.T, prefix string) string {
	t.Helper()

	dir, err := os.MkdirTemp("", prefix)
	if err != nil {
		t.Fatalf("Failed to create temporary directory for libvirt: %v", err)
	}
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatalf("Failed to chmod temporary directory %s: %v", dir, err)
	}
	t.Cleanup(func() {
		_ = os.RemoveAll(dir)
	})
	return dir
}

func checkCPUAndMemory(testUsername, vmName string, vcpu, memory int, conn *libvirt.Connect) error {
	vms, err := virt.ListVMs(testUsername, conn)
	if err != nil {
		return err
	}

	for _, v := range vms {
		if v.Name == vmName {
			if v.VCPU == vcpu && v.MemoryMiB == memory {
				return nil
			}
			return fmt.Errorf("vm %s has CPU %d and memory %dMB, expected CPU 2 and memory 2048MB", vmName, v.VCPU, v.MemoryMiB)
		}
	}

	return fmt.Errorf("vm %s not found for CPU and memory check", vmName)
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
			return fmt.Errorf("vm %s state is %s, expected %s", vmName, v.State, state)
		}
	}

	return fmt.Errorf("vm %s with state %s not found", vmName, state)
}

func waitForState(t *testing.T, username, vmName, state string, conn *libvirt.Connect, timeout time.Duration) {
	t.Helper()

	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		err := checkState(username, vmName, state, conn)
		if err == nil {
			return
		}
		lastErr = err
		time.Sleep(500 * time.Millisecond)
	}

	t.Fatalf("VM %s did not reach state %s within %s: %v", vmName, state, timeout, lastErr)
}

func waitForSerialSocket(t *testing.T, vmName string, timeout time.Duration) {
	t.Helper()

	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		conn, err := virt.DialSerialSocket(vmName, time.Second)
		if err == nil {
			_ = conn.Close()
			return
		}
		if errors.Is(err, os.ErrPermission) || errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.EPERM) {
			return
		}
		if errors.Is(err, virt.ErrSerialConsoleNotRunning) || errors.Is(err, virt.ErrSerialConsoleNotReady) {
			lastErr = err
			time.Sleep(500 * time.Millisecond)
			continue
		}
		t.Fatalf("DialSerialSocket(%s) failed: %v", vmName, err)
	}

	t.Fatalf("serial socket for %s was not ready within %s: %v", vmName, timeout, lastErr)
}

func waitForVNCSocket(t *testing.T, vmName string, timeout time.Duration) {
	t.Helper()

	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		conn, err := virt.DialVNCSocket(vmName, time.Second)
		if err == nil {
			_ = conn.Close()
			return
		}
		if errors.Is(err, os.ErrPermission) || errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.EPERM) {
			return
		}
		if errors.Is(err, virt.ErrVNCNotRunning) || errors.Is(err, virt.ErrVNCNotReady) {
			lastErr = err
			time.Sleep(500 * time.Millisecond)
			continue
		}
		t.Fatalf("DialVNCSocket(%s) failed: %v", vmName, err)
	}

	t.Fatalf("VNC socket for %s was not ready within %s: %v", vmName, timeout, lastErr)
}

func newConsoleSocketSettings(t *testing.T) *config.SettingsType {
	t.Helper()

	rootDir := newLibvirtAccessibleTempDir(t, "rdptlsgateway-console-root-")

	settings := config.NewSettingType(false)
	if settings.OverwriteForTestString(config.DATA_ROOT_DIR, rootDir) != nil {
		t.Fatalf("Failed to overwrite DATA_ROOT_DIR for test")
	}
	if settings.OverwriteForTestString(config.VIRT_STORAGE_POOL_NAME, "virt-console-test-"+fmt.Sprint(time.Now().UnixNano())) != nil {
		t.Fatalf("Failed to overwrite VIRT_STORAGE_POOL_NAME for test")
	}
	stageExistingBaseImageFromDefaultRoot(t, settings)
	return settings
}

func stageExistingBaseImageFromDefaultRoot(t *testing.T, settings *config.SettingsType) {
	t.Helper()

	if settings == nil {
		return
	}
	parsedURL, err := url.Parse(settings.Get(config.BASE_IMAGE_URL))
	if err != nil {
		return
	}
	imageName := path.Base(parsedURL.Path)
	if imageName == "." || imageName == "/" || imageName == "" {
		return
	}

	sourcePath, ok := findExistingBaseImageSourcePath(imageName)
	if !ok {
		return
	}
	targetPath := filepath.Join(config.ImageDir(settings), imageName)
	if err := os.MkdirAll(filepath.Dir(targetPath), 0o755); err != nil {
		t.Fatalf("Failed to create image directory %s: %v", filepath.Dir(targetPath), err)
	}
	if _, err := os.Stat(targetPath); err == nil {
		return
	}
	if err := os.Link(sourcePath, targetPath); err == nil {
		return
	}

	sourceFile, err := os.Open(sourcePath)
	if err != nil {
		t.Fatalf("Failed to open source base image %s: %v", sourcePath, err)
	}
	defer func() { _ = sourceFile.Close() }()

	targetFile, err := os.Create(targetPath)
	if err != nil {
		t.Fatalf("Failed to create staged base image %s: %v", targetPath, err)
	}
	defer func() { _ = targetFile.Close() }()

	if _, err := io.Copy(targetFile, sourceFile); err != nil {
		t.Fatalf("Failed to copy base image into test root: %v", err)
	}
}

func findExistingBaseImageSourcePath(imageName string) (string, bool) {
	candidates := []string{
		filepath.Join(config.ImageDir(nil), imageName),
		filepath.Join(legacyDefaultImageDir, imageName),
	}
	for _, candidate := range candidates {
		if _, err := os.Stat(candidate); err == nil {
			return candidate, true
		}
	}
	return "", false
}

func waitForRunningVM(t *testing.T, username, vmName string, conn *libvirt.Connect, timeout time.Duration) {
	t.Helper()

	waitForState(t, username, vmName, "running", conn, timeout)
	waitForSerialSocket(t, vmName, timeout)
	waitForVNCSocket(t, vmName, timeout)
}

func assertRemovedVM(t *testing.T, conn *libvirt.Connect, vmName string) {
	t.Helper()

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

func TestStartVM(t *testing.T) {
	settings := newConsoleSocketSettings(t)

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
	defer func() {
		_, _ = conn.Close()
	}()

	waitForRunningVM(t, testUsername, vmName, conn, testTimeout)

	if err := virt.ShutdownVM(vmName); err != nil {
		t.Fatalf("Failed to shutdown VM %s: %v", vmName, err)
	}
	waitForState(t, testUsername, vmName, "shut off", conn, testTimeout)

	if err := virt.UpdateVMResources(vmName, 2, 2048); err != nil {
		t.Fatalf("Failed to update VM %s resources: %v", vmName, err)
	}

	if err := checkCPUAndMemory(testUsername, vmName, 2, 2048, conn); err != nil {
		t.Fatalf("VM %s does not have updated CPU and Memory as expected: %v", vmName, err)
	}

	if err := virt.StartExistingVM(vmName); err != nil {
		t.Fatalf("Failed to start existing VM %s: %v", vmName, err)
	}
	waitForRunningVM(t, testUsername, vmName, conn, testTimeout)

	if err := virt.RestartVM(vmName); err != nil {
		t.Fatalf("Failed to restart VM %s: %v", vmName, err)
	}
	waitForRunningVM(t, testUsername, vmName, conn, testTimeout)

	if err := virt.RemoveVM(vmName, settings); err != nil {
		t.Fatalf("Failed to destroy VM %s: %v", vmName, err)
	}
	assertRemovedVM(t, conn, vmName)
}
