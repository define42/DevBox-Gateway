// Package dashboard contains dashboard page rendering helpers and
// data contracts used by the gateway API.
package dashboard

import (
	"devboxgateway/internal/config"
	"devboxgateway/internal/hash"
	"devboxgateway/internal/virt"
	"devboxgateway/internal/vmname"
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"net/http"
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
	Name         string `json:"name"`
	DisplayName  string `json:"displayName"`
	User         string `json:"user"`
	BaseImage    string `json:"baseImage,omitempty"`
	CreatedAt    string `json:"createdAt,omitempty"`
	RDPFilename  string `json:"rdpFilename"`
	IP           string `json:"ip"`
	State        string `json:"state"`
	MemoryMiB    int    `json:"memoryMiB"`
	VCPU         int    `json:"vcpu"`
	VolumeGB     int    `json:"volumeGB"`
	VolumeUsedGB int    `json:"volumeUsedGB"`
	TTYReady     bool   `json:"ttyReady"`
	VNCReady     bool   `json:"vncReady"`
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
// name with the leading "<owner><Separator>" prefix removed. VMs without owner
// metadata (older ones) fall back to the full name. The owner/hostname boundary
// rule lives in the vmname package so it stays consistent with Compose.
func vmBareName(vm virt.VMInfo) string {
	return vmname.BareHostname(vm.Name, vm.Owner)
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

// GenerateRDPContent builds the raw .rdp file body for the provided server/user
// pair. It is the single source of truth for the connection settings used by the
// downloadable file (WriteRDPFile).
func GenerateRDPContent(server, username string) string {
	lines := []string{
		fmt.Sprintf("full address:s:%s:443", server),
		fmt.Sprintf("username:s:%s", username),
		"prompt for credentials:i:1",
		"administrative session:i:1",
		"enablecredsspsupport:i:0",
	}

	return strings.Join(lines, "\n") + "\n"
}

// rdpConnectHost returns the host an RDP client connects to for the VM: the
// opaque HMAC routing label under FRONT_DOMAIN, or the bare VM name when no
// front domain is configured, so the downloaded .rdp file routes to the right VM
// without leaking the username-hostname in the cleartext TLS SNI.
func rdpConnectHost(settings *config.SettingsType, vmName string) string {
	domain := strings.TrimSpace(settings.GetString(config.FRONT_DOMAIN))
	if domain == "" {
		return vmName
	}
	secret := []byte(settings.Get(config.SNI_HASH_SECRET))
	return hash.RoutingLabel(secret, vmName) + "." + domain
}

// RDPFileForUser builds the .rdp download (filename and body) for the named VM,
// resolved from the requesting user's own VM list so callers cannot mint a file
// for a VM the user does not own. ok is false when the VM is not in that list.
func RDPFileForUser(settings *config.SettingsType, user, vmName string) (filename string, content []byte, ok bool) {
	for _, vm := range virt.GetInstance().GetVMs(user) {
		if vm.Name != vmName {
			continue
		}
		rdpUser := strings.TrimSpace(vm.GuestUser)
		if rdpUser == "" {
			rdpUser = user
		}
		body := GenerateRDPContent(rdpConnectHost(settings, vm.Name), rdpUser)
		return rdpDownloadFilename(vm.Name), []byte(body), true
	}
	return "", nil, false
}

// WriteRDPFile writes the named VM's .rdp connection file as an attachment
// download. The caller is responsible for authenticating the session and
// verifying ownership (and for recording the RDP connect grant) before calling.
func WriteRDPFile(w http.ResponseWriter, settings *config.SettingsType, user, vmName string) {
	filename, content, ok := RDPFileForUser(settings, user, vmName)
	if !ok {
		WriteJSON(w, http.StatusNotFound, ActionResponse{OK: false, Error: "VM not found."})
		return
	}
	setNoCacheHeaders(w)
	w.Header().Set("Content-Type", "application/x-rdp")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(content); err != nil {
		log.Printf("write rdp file for vm %q: %v", vmName, err)
	}
}

// ListDashboardVMs returns VM rows visible to the given user.
func ListDashboardVMs(user string) ([]VM, error) {
	vmList := virt.GetInstance().GetVMs(user)
	return buildDashboardRows(vmList, user), nil
}

func buildDashboardRows(vmList []virt.VMInfo, user string) []VM {
	rows := make([]VM, 0, len(vmList))
	for _, vm := range vmList {
		// The UI shows the bare VM name (the part the user typed at creation,
		// without the owner prefix) — the old FQDN was never the on-wire SNI.
		displayName := vmBareName(vm)
		// Prefer the guest account stored on the VM; older VMs without that
		// metadata fall back to the requesting user's own name. This is the RDP
		// login surfaced in the downloaded .rdp file (see RDPFileForUser).
		rdpUser := strings.TrimSpace(vm.GuestUser)
		if rdpUser == "" {
			rdpUser = user
		}
		rows = append(rows, VM{
			Name:         vm.Name,
			DisplayName:  displayName,
			User:         rdpUser,
			BaseImage:    strings.TrimSpace(vm.BaseImage),
			CreatedAt:    strings.TrimSpace(vm.CreatedAt),
			RDPFilename:  rdpDownloadFilename(vm.Name),
			IP:           vm.IP,
			State:        vm.State,
			MemoryMiB:    vm.MemoryMiB,
			VCPU:         vm.VCPU,
			VolumeGB:     vm.VolumeGB,
			VolumeUsedGB: vm.VolumeUsedGB,
			TTYReady:     vm.TTYReady,
			VNCReady:     vm.VNCReady,
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
