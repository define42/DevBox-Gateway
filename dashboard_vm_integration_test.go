package main

import (
	"encoding/base64"
	"rdptlsgateway/internal/config"
	dashboard "rdptlsgateway/internal/dashboard"
	"rdptlsgateway/internal/types"
	"rdptlsgateway/internal/virt"
	"strconv"
	"strings"
	"testing"
	"time"
)

const dashboardVMTestTimeout = 30 * time.Second

func waitForDashboardVM(t *testing.T, settings *config.SettingsType, user, name string, timeout time.Duration) dashboard.VM {
	t.Helper()

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		rows, err := dashboard.ListDashboardVMs(settings, user)
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
	if err := settings.OverwriteForTestString(config.VIRT_SERIAL_SOCKET_DIR, t.TempDir()); err != nil {
		t.Fatalf("overwrite VIRT_SERIAL_SOCKET_DIR: %v", err)
	}
	if err := settings.OverwriteForTestString(config.VIRT_VNC_SOCKET_DIR, t.TempDir()); err != nil {
		t.Fatalf("overwrite VIRT_VNC_SOCKET_DIR: %v", err)
	}
	if err := settings.OverwriteForTestString(config.FRONT_DOMAIN, "dashboard.test"); err != nil {
		t.Fatalf("overwrite FRONT_DOMAIN: %v", err)
	}
	return settings
}

func createDashboardVM(t *testing.T, settings *config.SettingsType) (string, string) {
	t.Helper()

	suffix := time.Now().UnixNano() % 1_000_000
	username := "dashuser" + strconv.FormatInt(suffix, 10)
	vmShortName := "dashvm" + strconv.FormatInt(suffix, 10)

	user, err := types.NewUser(username, "dogood")
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	vmName, err := virt.BootNewVM(vmShortName, user, settings, 2, 4096)
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
	if row.VolumeGB != 40 {
		t.Fatalf("expected disk 40 GB, got %d", row.VolumeGB)
	}
	if !row.TTYReady {
		t.Fatal("expected TTYReady=true")
	}
	if !row.VNCReady {
		t.Fatal("expected VNCReady=true")
	}
}

func assertDashboardRDPConnect(t *testing.T, rdpConnect, wantDisplayName, username string) {
	t.Helper()

	const prefix = "data:application/x-rdp;base64,"
	if !strings.HasPrefix(rdpConnect, prefix) {
		t.Fatalf("expected RDP data URI prefix, got %q", rdpConnect)
	}

	decodedRDP, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(rdpConnect, prefix))
	if err != nil {
		t.Fatalf("decode RDP payload: %v", err)
	}
	rdp := string(decodedRDP)
	if !strings.Contains(rdp, "full address:s:"+wantDisplayName+":443") {
		t.Fatalf("expected RDP payload to contain display name %q, got %q", wantDisplayName, rdp)
	}
	if !strings.Contains(rdp, "username:s:"+username) {
		t.Fatalf("expected RDP payload to contain username %q, got %q", username, rdp)
	}
}

func TestListDashboardVMs(t *testing.T) {
	virt.GetInstance()

	settings := newDashboardVMSettings(t)
	username, vmName := createDashboardVM(t, settings)
	row := waitForDashboardVM(t, settings, username, vmName, dashboardVMTestTimeout)
	wantDisplayName := vmName + ".dashboard.test"

	assertDashboardVMRow(t, row, wantDisplayName)
	assertDashboardRDPConnect(t, row.RDPConnect, wantDisplayName, username)
}
