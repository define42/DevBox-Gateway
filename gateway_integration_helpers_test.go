package main

import (
	"devboxgateway/internal/config"
	"devboxgateway/internal/dashboard"
	"devboxgateway/internal/vmname"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

func newGatewayIntegrationSettings(t *testing.T, ldapURL string) *config.SettingsType {
	t.Helper()

	t.Setenv(config.LDAP_URL, ldapURL)
	t.Setenv(config.LDAP_SKIP_TLS_VERIFY, "true")
	t.Setenv(config.LDAP_STARTTLS, "false")
	t.Setenv(config.LDAP_USER_DOMAIN, "@example.com")
	t.Setenv(config.FRONT_DOMAIN, "gateway.test")
	t.Setenv(config.DATA_ROOT_DIR, newLibvirtAccessibleTempDir(t, "devboxgateway-root-"))
	t.Setenv(config.VIRT_STORAGE_POOL_NAME, "gateway-test-"+uniqueGatewayVMShortName("pool"))

	settings := config.NewSettingType(false)
	stageExistingBaseImageFromDefaultRoot(t, settings)
	return settings
}

func assertGatewayStatus(t *testing.T, client *http.Client, method, rawURL string, form url.Values, wantStatus int) string {
	t.Helper()

	resp, body := gatewayRequest(t, client, method, rawURL, form)
	if resp.StatusCode != wantStatus {
		t.Fatalf("expected %s %s to return %d, got %d with body %s", method, rawURL, wantStatus, resp.StatusCode, body)
	}
	return body
}

func assertGatewayStatusContains(t *testing.T, client *http.Client, method, rawURL string, form url.Values, wantStatus int, wantSubstring string) {
	t.Helper()

	body := assertGatewayStatus(t, client, method, rawURL, form, wantStatus)
	if wantSubstring != "" && !strings.Contains(body, wantSubstring) {
		t.Fatalf("expected response body to contain %q, got %q", wantSubstring, body)
	}
}

func assertGatewayRedirect(t *testing.T, client *http.Client, method, rawURL string, form url.Values, wantStatus int, wantLocation string) {
	t.Helper()

	resp, body := gatewayRequest(t, client, method, rawURL, form)
	if resp.StatusCode != wantStatus {
		t.Fatalf("expected %s %s to return %d, got %d with body %s", method, rawURL, wantStatus, resp.StatusCode, body)
	}
	if loc := resp.Header.Get("Location"); loc != wantLocation {
		t.Fatalf("expected redirect to %q, got %q", wantLocation, loc)
	}
}

func uniqueGatewayVMShortName(prefix string) string {
	return prefix + strconv.FormatInt(time.Now().UnixNano()%1_000_000, 10)
}

func createGatewayVM(t *testing.T, server gatewayTestServer, shortName string) string {
	t.Helper()

	// The server composes the VDI name from the login user ("johndoe") and the
	// submitted short name via vmname.Compose, so build the expected full name
	// the same way instead of hard-coding the separator.
	fullName := "johndoe" + vmname.Separator + shortName
	createClient := *server.client
	createClient.Timeout = 2 * time.Minute

	assertGatewayStatus(t, &createClient, http.MethodPost, server.baseURL+"/api/dashboard", url.Values{
		"vm_name":             {shortName},
		"vm_password":         {"devbox-pass"},
		"vm_password_confirm": {"devbox-pass"},
		"vm_vcpu":             {"2"},
		"vm_memory_mib":       {"4096"},
		"vm_base_image":       {testBaseImageName},
	}, http.StatusOK)
	return fullName
}

// assertGatewayVMCreateConflict asserts that creating a VM whose name already
// exists is refused with 409 and a message telling the user to delete it first.
func assertGatewayVMCreateConflict(t *testing.T, server gatewayTestServer, shortName string) {
	t.Helper()

	assertGatewayStatusContains(t, server.client, http.MethodPost, server.baseURL+"/api/dashboard", url.Values{
		"vm_name":             {shortName},
		"vm_password":         {"devbox-pass"},
		"vm_password_confirm": {"devbox-pass"},
		"vm_vcpu":             {"2"},
		"vm_memory_mib":       {"4096"},
		"vm_base_image":       {testBaseImageName},
	}, http.StatusConflict, "already exists")
}

func waitForGatewayVMState(t *testing.T, server gatewayTestServer, vmName, state string) dashboard.VM {
	t.Helper()

	return waitForDashboardVMRow(t, server.client, server.baseURL, vmName, func(vm dashboard.VM) bool {
		return vm.State == state
	})
}

func waitForGatewayVMReady(t *testing.T, server gatewayTestServer, vmName string) dashboard.VM {
	t.Helper()

	return waitForDashboardVMRow(t, server.client, server.baseURL, vmName, func(vm dashboard.VM) bool {
		return vm.State == "running" && vm.TTYReady && vm.VNCReady
	})
}

func waitForGatewayVMResources(t *testing.T, server gatewayTestServer, vmName string, vcpu, memoryMiB int) dashboard.VM {
	t.Helper()

	return waitForDashboardVMRow(t, server.client, server.baseURL, vmName, func(vm dashboard.VM) bool {
		return vm.State == "shut off" && vm.VCPU == vcpu && vm.MemoryMiB == memoryMiB
	})
}
