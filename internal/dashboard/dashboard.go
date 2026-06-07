// Package dashboard contains dashboard page rendering helpers and
// data contracts used by the gateway API.
package dashboard

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"rdptlsgateway/internal/config"
	"rdptlsgateway/internal/hash"
	"rdptlsgateway/internal/virt"
	"strings"
)

// DashboardHTMLPath is the embedded dashboard HTML template location.
const DashboardHTMLPath = "static/dashboard.html"

const (
	cacheControlValue = "no-store, no-cache, must-revalidate, max-age=0"
	pragmaValue       = "no-cache"
	expiresValue      = "0"
)

// VM represents a single virtual machine row returned to the dashboard.
type VM struct {
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
	User        string `json:"user"`
	RDPConnect  string `json:"rdpConnect"`
	RDPFilename string `json:"rdpFilename"`
	IP          string `json:"ip"`
	State       string `json:"state"`
	MemoryMiB   int    `json:"memoryMiB"`
	VCPU        int    `json:"vcpu"`
	VolumeGB    int    `json:"volumeGB"`
	TTYReady    bool   `json:"ttyReady"`
	VNCReady    bool   `json:"vncReady"`
}

// DataResponse is the API response for /api/dashboard/data.
type DataResponse struct {
	Filename   string   `json:"filename"`
	Username   string   `json:"username,omitempty"`
	VMs        []VM     `json:"vms"`
	BaseImages []string `json:"baseImages,omitempty"`
	Error      string   `json:"error,omitempty"`
}

// ActionResponse is the API response envelope used by dashboard actions.
type ActionResponse struct {
	OK      bool   `json:"ok"`
	Message string `json:"message,omitempty"`
	Error   string `json:"error,omitempty"`
}

// RenderDashboardPage writes the dashboard HTML page to the HTTP response.
func RenderDashboardPage(w http.ResponseWriter, staticFiles fs.FS) {
	setNoCacheHeaders(w)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	dashboardHTML, err := fs.ReadFile(staticFiles, DashboardHTMLPath)
	if err != nil {
		log.Printf("render dashboard page: %v", err)
		http.Error(w, "Dashboard template unavailable.", http.StatusInternalServerError)
		return
	}
	if _, err := w.Write(dashboardHTML); err != nil {
		log.Printf("render dashboard page: %v", err)
	}
}

// vmBareName returns the name the user typed at creation time, i.e. the VM
// name with the leading "<owner>-" prefix removed. VMs without owner metadata
// (older ones) fall back to the full name.
func vmBareName(vm virt.VMInfo) string {
	if owner := strings.TrimSpace(vm.Owner); owner != "" {
		if bare := strings.TrimPrefix(vm.Name, owner+"-"); bare != "" {
			return bare
		}
	}
	return vm.Name
}

// rdpDownloadFilename derives a friendly per-VM download filename (e.g.
// "alice-desktop.rdp") so the saved file and many RDP clients label the
// connection by VM name. The on-wire SNI is unaffected — it still uses the
// hashed connect host. The VM name is sanitized to safe filename characters
// because the username portion is not otherwise constrained.
func rdpDownloadFilename(vmName string) string {
	name := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			return r
		case r == '-', r == '_', r == '.':
			return r
		default:
			return '-'
		}
	}, vmName)
	name = strings.Trim(name, "-._")
	if name == "" {
		return "rdpgw.rdp"
	}
	return name + ".rdp"
}

// GenerateRDP builds a base64-encoded RDP payload for the provided server/user pair.
func GenerateRDP(server, username string) string {
	lines := []string{
		fmt.Sprintf("full address:s:%s:443", server),
		fmt.Sprintf("username:s:%s", username),
		"prompt for credentials:i:1",
		"administrative session:i:1",
		"enablecredsspsupport:i:0",
	}

	rdp := strings.Join(lines, "\n") + "\n"
	encoded := base64.StdEncoding.EncodeToString([]byte(rdp))

	return "data:application/x-rdp;base64," + encoded
}

// ListDashboardVMs returns VM rows visible to the given user.
func ListDashboardVMs(settings *config.SettingsType, user string) ([]VM, error) {
	vmList := virt.GetInstance().GetVMs(user)
	return buildDashboardRows(vmList, settings, user), nil
}

func buildDashboardRows(vmList []virt.VMInfo, settings *config.SettingsType, user string) []VM {
	rows := make([]VM, 0, len(vmList))
	secret := []byte(settings.Get(config.SNI_HASH_SECRET))
	for _, vm := range vmList {
		// The UI shows the bare VM name (the part the user typed at creation,
		// without the owner prefix) — the old FQDN was never the on-wire SNI.
		// connectHost uses the opaque HMAC routing label so the cleartext TLS
		// SNI never reveals the username-hostname.
		displayName := vmBareName(vm)
		connectHost := vm.Name
		if domain := strings.TrimSpace(settings.GetString(config.FRONT_DOMAIN)); domain != "" {
			connectHost = hash.RoutingLabel(secret, vm.Name) + "." + domain
		}
		// Prefer the guest account stored on the VM; older VMs without that
		// metadata fall back to the requesting user's own name.
		rdpUser := strings.TrimSpace(vm.GuestUser)
		if rdpUser == "" {
			rdpUser = user
		}
		rows = append(rows, VM{
			Name:        vm.Name,
			DisplayName: displayName,
			User:        rdpUser,
			RDPConnect:  GenerateRDP(connectHost, rdpUser),
			RDPFilename: rdpDownloadFilename(vm.Name),
			IP:          vm.IP,
			State:       vm.State,
			MemoryMiB:   vm.MemoryMiB,
			VCPU:        vm.VCPU,
			VolumeGB:    vm.VolumeGB,
			TTYReady:    vm.TTYReady,
			VNCReady:    vm.VNCReady,
		})
	}
	return rows
}

// WriteJSON serializes a payload as JSON with cache-control headers.
func WriteJSON(w http.ResponseWriter, status int, payload any) {
	setNoCacheHeaders(w)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	if err := enc.Encode(payload); err != nil {
		log.Printf("write json response: %v", err)
	}
}

func setNoCacheHeaders(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", cacheControlValue)
	w.Header().Set("Pragma", pragmaValue)
	w.Header().Set("Expires", expiresValue)
}
