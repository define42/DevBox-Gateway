package main

import (
	"devboxgateway/internal/config"
	dashboard "devboxgateway/internal/dashboard"
	"devboxgateway/internal/hash"
	"devboxgateway/internal/types"
	"devboxgateway/internal/virt"
	"devboxgateway/internal/vmname"
	"strconv"
	"strings"
	"testing"
	"time"
)

const dashboardVMTestTimeout = 30 * time.Second

func waitForDashboardVM(t *testing.T, user, name string, timeout time.Duration) dashboard.VM {
	t.Helper()

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		rows, err := dashboard.ListDashboardVMs(user)
		if err != nil {
			t.Fatalf("dashboard.ListDashboardVMs(%q): %v", user, err)
		}
		for _, row := range rows {
			if row.Name == name && row.State == "running" && row.TTYReady && row.VNCReady {
				return row
			}
		}
		time.Sleep(500 * time.Millisecond)
	}

	t.Fatalf("VM %s was not visible in dashboard data for user %s within %s", name, user, timeout)
	return dashboard.VM{}
}

func newDashboardVMSettings(t *testing.T) *config.SettingsType {
	t.Helper()

	settings := config.NewSettingType(false)
	if err := settings.OverwriteForTestString(config.DATA_ROOT_DIR, newLibvirtAccessibleTempDir(t, "devboxgateway-root-")); err != nil {
		t.Fatalf("overwrite DATA_ROOT_DIR: %v", err)
	}
	if err := settings.OverwriteForTestString(config.VIRT_STORAGE_POOL_NAME, "dashboard-test-"+strconv.FormatInt(time.Now().UnixNano(), 10)); err != nil {
		t.Fatalf("overwrite VIRT_STORAGE_POOL_NAME: %v", err)
	}
	if err := settings.OverwriteForTestString(config.FRONT_DOMAIN, "dashboard.test"); err != nil {
		t.Fatalf("overwrite FRONT_DOMAIN: %v", err)
	}
	stageExistingBaseImageFromDefaultRoot(t, settings)
	return settings
}

func createDashboardVM(t *testing.T, settings *config.SettingsType) (string, string) {
	t.Helper()

	suffix := time.Now().UnixNano() % 1_000_000
	username := "dashuser" + strconv.FormatInt(suffix, 10)
	vmShortName := "dashvm" + strconv.FormatInt(suffix, 10)

	user, err := types.NewUser(username)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	vmName, err := virt.BootNewVM(vmShortName, user, "", testGuestPassword, testBaseImageName, settings, 2, 4096)
	if err != nil {
		t.Fatalf("boot VM %s: %v", vmShortName, err)
	}
	t.Cleanup(func() {
		if err := virt.RemoveVM(vmName, settings); err != nil {
			t.Errorf("cleanup VM %s: %v", vmName, err)
		}
	})

	return username, vmName
}

func assertDashboardVMRow(t *testing.T, row dashboard.VM, wantDisplayName string) {
	t.Helper()

	if row.DisplayName != wantDisplayName {
		t.Fatalf("expected display name %q, got %q", wantDisplayName, row.DisplayName)
	}
	if row.State != "running" {
		t.Fatalf("expected state running, got %q", row.State)
	}
	if row.MemoryMiB != 4096 {
		t.Fatalf("expected memory 4096 MiB, got %d", row.MemoryMiB)
	}
	if row.VCPU != 2 {
		t.Fatalf("expected vCPU 2, got %d", row.VCPU)
	}
	if row.VolumeGB != config.DefaultVMDiskSizeGB {
		t.Fatalf("expected disk %d GB, got %d", config.DefaultVMDiskSizeGB, row.VolumeGB)
	}
	if !row.TTYReady {
		t.Fatal("expected TTYReady=true")
	}
	if !row.VNCReady {
		t.Fatal("expected VNCReady=true")
	}
}

func assertRDPFileContent(t *testing.T, content, wantConnectHost, username string) {
	t.Helper()

	if !strings.Contains(content, "full address:s:"+wantConnectHost+":443") {
		t.Fatalf("expected RDP file to contain connect host %q, got %q", wantConnectHost, content)
	}
	if !strings.Contains(content, "username:s:"+username) {
		t.Fatalf("expected RDP file to contain username %q, got %q", username, content)
	}
}

func TestListDashboardVMs(t *testing.T) {
	virt.GetInstance()

	settings := newDashboardVMSettings(t)
	username, vmName := createDashboardVM(t, settings)
	row := waitForDashboardVM(t, username, vmName, dashboardVMTestTimeout)
	wantDisplayName := vmname.BareHostname(vmName, username)
	wantConnectHost := hash.RoutingLabel([]byte(settings.Get(config.SNI_HASH_SECRET)), vmName) + ".dashboard.test"

	assertDashboardVMRow(t, row, wantDisplayName)

	// The .rdp now comes from the explicit Connect download, not an inline field,
	// so assert the file the user would actually receive for their owned VM.
	_, content, ok := dashboard.RDPFileForUser(settings, username, vmName)
	if !ok {
		t.Fatalf("expected an RDP file for owned VM %q", vmName)
	}
	assertRDPFileContent(t, string(content), wantConnectHost, username)
}
