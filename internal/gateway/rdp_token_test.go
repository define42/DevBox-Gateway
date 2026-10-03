package gateway

import (
	"encoding/hex"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/define42/devbox-gateway/internal/config"
	"github.com/define42/devbox-gateway/internal/session"
	"github.com/define42/devbox-gateway/internal/vmname"
)

func downloadRDPToken(t *testing.T, handler http.Handler, cookie *http.Cookie, vmName, user string) string {
	t.Helper()

	rec := hcovPostForm(t, handler, cookie, "/api/dashboard/rdp", url.Values{"vm_name": {vmName}})
	if rec.Code != http.StatusOK {
		t.Fatalf("RDP download returned %d: %s", rec.Code, rec.Body.String())
	}
	hcovAssertRDPDownload(t, rec, user)
	if !strings.Contains(rec.Header().Get("Cache-Control"), "no-store") {
		t.Fatal("token download must prohibit HTTP caching")
	}
	var tokens []string
	for _, line := range strings.Split(rec.Body.String(), "\n") {
		if token, found := strings.CutPrefix(line, "loadbalanceinfo:s:"); found {
			tokens = append(tokens, token)
		}
	}
	if len(tokens) != 1 {
		t.Fatalf("download contained %d routing tokens, want one", len(tokens))
	}
	token := tokens[0]
	decoded, err := hex.DecodeString(token)
	if err != nil || len(decoded) != 16 || token != strings.ToLower(token) {
		t.Fatal("download token must contain 128 bits encoded as lowercase hex")
	}
	return token
}

func assertRDPTokenTarget(t *testing.T, manager *session.Manager, token, clientIP, wantVM string) {
	t.Helper()

	vmName, ok := manager.RDPConnectTarget(token, clientIP)
	if vmName != wantVM || ok != (wantVM != "") {
		t.Fatalf("token target = %q, %v; want %q", vmName, ok, wantVM)
	}
}

func TestRDPDownloadsBindTokensToIssuingBrowserSession(t *testing.T) {
	user := hcovUniqueName("rdptokens")
	vmName := user + vmname.Separator + "desk"
	hcovDefineOwnedDomain(t, vmName, user)
	hcovWaitForCachedVM(t, user)
	manager := session.New()
	t.Cleanup(func() { _ = manager.Close() })
	router := NewHandler(manager, config.NewSettings(false))
	firstCookie := issueSessionCookie(t, manager, user)
	secondCookie := issueSessionCookie(t, manager, user)

	first := downloadRDPToken(t, router, firstCookie, vmName, user)
	second := downloadRDPToken(t, router, secondCookie, vmName, user)
	assertRDPTokenTarget(t, manager, first, "192.0.2.1", vmName)
	assertRDPTokenTarget(t, manager, second, "192.0.2.1", vmName)

	replacement := downloadRDPToken(t, router, firstCookie, vmName, user)
	assertRDPTokenTarget(t, manager, first, "192.0.2.1", "")
	assertRDPTokenTarget(t, manager, second, "192.0.2.1", vmName)
	assertRDPTokenTarget(t, manager, replacement, "192.0.2.1", vmName)
}
