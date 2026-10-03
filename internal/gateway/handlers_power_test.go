package gateway

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/define42/devbox-gateway/internal/audit"
	"github.com/define42/devbox-gateway/internal/config"
	"github.com/define42/devbox-gateway/internal/identity"
	"github.com/define42/devbox-gateway/internal/session"
	"libvirt.org/go/libvirt"
)

func TestDashboardPowerRoutesRequireSessionAndSameOrigin(t *testing.T) {
	sm := session.New()
	t.Cleanup(func() { _ = sm.Close() })
	router := NewHandler(sm, config.NewSettings(false))
	cookie := issueSessionCookie(t, sm, "alice")
	for _, path := range []string{"/api/dashboard/shutdown", "/api/dashboard/power-off"} {
		for _, tt := range []struct {
			name   string
			cookie *http.Cookie
			origin string
			want   int
		}{
			{name: "unauthenticated", origin: "http://example.com", want: http.StatusSeeOther},
			{name: "missing origin", cookie: cookie, want: http.StatusForbidden},
			{name: "foreign origin", cookie: cookie, origin: "https://attacker.invalid", want: http.StatusForbidden},
		} {
			t.Run(path+"/"+tt.name, func(t *testing.T) {
				req := httptest.NewRequest(http.MethodPost, path, strings.NewReader("vm_name=alice.desktop"))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				if tt.cookie != nil {
					req.AddCookie(tt.cookie)
				}
				req.Header.Set("Origin", tt.origin)
				rec := httptest.NewRecorder()
				router.ServeHTTP(rec, req)
				if rec.Code != tt.want {
					t.Fatalf("status = %d, want %d: %s", rec.Code, tt.want, rec.Body.String())
				}
			})
		}
	}
}

func TestDashboardPowerRoutesRejectPendingDeletion(t *testing.T) {
	dom := definePendingPowerTestDomain(t)
	for _, admin := range []bool{false, true} {
		sm := session.New()
		t.Cleanup(func() { _ = sm.Close() })
		router := NewHandler(sm, config.NewSettings(false))
		user := &identity.User{Name: "alice", IsAdmin: admin}
		if admin {
			user.Name = "operator"
		}
		cookie := issueSessionCookieForUser(t, sm, user, "192.0.2.1:12345", testGuestPasswordHash)
		auditOutput := captureStructuredLogs(t)
		for _, path := range []string{"start", "restart", "shutdown", "power-off"} {
			rec := hcovPostForm(t, router, cookie, "/api/dashboard/"+path, url.Values{"vm_name": {"alice.pending-power"}})
			hcovAssertAction(t, rec, http.StatusConflict,
				"VM deletion is pending. Retry removal before changing its power state.")
		}
		if active, err := dom.IsActive(); err != nil || active {
			t.Fatalf("pending removal VM changed power state: active=%v error=%v", active, err)
		}
		assertPendingPowerAudit(t, auditOutput, user)
	}
}

func assertPendingPowerAudit(t *testing.T, output *synchronizedLogBuffer, user *identity.User) {
	t.Helper()
	records := structuredAuditRecords(t, output)
	if len(records) != 4 {
		t.Fatalf("got %d pending deletion audit records, want 4: %#v", len(records), records)
	}
	for _, record := range records {
		isAdmin, _ := record["administrator"].(bool)
		if record["result"] != audit.ResultFailure || record["user"] != user.Name ||
			record["vm"] != "alice.pending-power" || isAdmin != user.IsAdmin {
			t.Errorf("incorrect pending deletion audit context: %#v", record)
		}
	}
	if records[2]["operation"] != "shutdown" || records[3]["operation"] != "force_power_off" {
		t.Errorf("power operations are not distinct: %#v", records)
	}
}

func definePendingPowerTestDomain(t *testing.T) *libvirt.Domain {
	t.Helper()
	// The in-process test driver shares fixture state while this connection is
	// open; no real hypervisor, storage, or network is involved.
	t.Setenv("LIBVIRT_URI", "test:///default")
	conn, err := libvirt.NewConnect("test:///default")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = conn.Close() })
	dom, err := conn.DomainDefineXML(`<domain type="test"><name>alice.pending-power</name>
<memory>1024</memory><vcpu>1</vcpu><os><type>hvm</type></os></domain>`)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = dom.Undefine()
		_ = dom.Free()
	})
	if err := dom.SetMetadata(libvirt.DOMAIN_METADATA_ELEMENT, "<owner>alice</owner>",
		"devboxgateway", "urn:devboxgateway:domain:owner", libvirt.DOMAIN_AFFECT_CONFIG); err != nil {
		t.Fatal(err)
	}
	if err := dom.SetMetadata(libvirt.DOMAIN_METADATA_ELEMENT, "<deletion>pending</deletion>",
		"devboxgatewaydeletion", "urn:devboxgateway:domain:deletion", libvirt.DOMAIN_AFFECT_CONFIG); err != nil {
		t.Fatal(err)
	}
	return dom
}
