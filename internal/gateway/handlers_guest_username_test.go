package gateway

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/define42/devbox-gateway/internal/config"
	"github.com/define42/devbox-gateway/internal/session"
	"github.com/define42/devbox-gateway/internal/virt"
)

func TestCreateVMInputValidatesLongLoginGuestUsername(t *testing.T) {
	login := strings.Repeat("a", maxGuestUsernameLength+1)
	tests := []struct {
		name          string
		guestUsername []string
	}{
		{name: "omitted guest username"},
		{name: "whitespace guest username", guestUsername: []string{" \t\r\n"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec, _, parsed := parseGuestUsernameCreateRequest(t, login, tt.guestUsername)
			hcovAssertAction(t, rec, http.StatusBadRequest, "username must be 32 characters or fewer")
			if parsed {
				t.Fatal("invalid fallback guest username was accepted for provisioning")
			}
		})
	}
}

func TestCreateVMInputAllowsGuestOverrideForLongLogin(t *testing.T) {
	login := strings.Repeat("a", maxGuestUsernameLength+1)
	rec, input, parsed := parseGuestUsernameCreateRequest(t, login, []string{" desktop "})
	if !parsed || rec.Code != http.StatusNoContent {
		t.Fatalf("explicit guest username was rejected: status=%d body=%s", rec.Code, rec.Body.String())
	}
	if input.GuestUsername != "desktop" || input.Owner == nil || input.Owner.Name != login {
		t.Fatalf("guest override changed the wrong identity: guest=%q owner=%v", input.GuestUsername, input.Owner)
	}
	if input.PasswordHash != testGuestPasswordHash {
		t.Error("guest override did not preserve the login password hash")
	}
}

func parseGuestUsernameCreateRequest(
	t *testing.T,
	login string,
	guestUsername []string,
) (*httptest.ResponseRecorder, virt.VMCreateRequest, bool) {
	t.Helper()
	settings := baseImageTestSettings(t)
	image := hcovSeedBaseImage(t, config.BaseImageDir(settings))
	manager := session.New()
	cookie := issueSessionCookie(t, manager, login)
	form := url.Values{"vm_name": {"desktop"}, "vm_base_image": {image}}
	if guestUsername != nil {
		form["vm_username"] = guestUsername
	}
	var input virt.VMCreateRequest
	var parsed bool
	handler := manager.LoadAndSave(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		input, parsed = parseCreateVMInput(w, r, manager, settings)
		if parsed {
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	rec := hcovPostForm(t, handler, cookie, "/api/dashboard", form)
	return rec, input, parsed
}
