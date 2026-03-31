package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"strings"

	"rdptlsgateway/internal/config"
	"rdptlsgateway/internal/virt"
)

const dashboardHTMLPath = "static/dashboard.html"

type dashboardVM struct {
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
	RDPConnect  string `json:"rdpConnect"`
	IP          string `json:"ip"`
	State       string `json:"state"`
	MemoryMiB   int    `json:"memoryMiB"`
	VCPU        int    `json:"vcpu"`
	VolumeGB    int    `json:"volumeGB"`
	TTYReady    bool   `json:"ttyReady"`
	VNCReady    bool   `json:"vncReady"`
}

type dashboardDataResponse struct {
	Filename string        `json:"filename"`
	VMs      []dashboardVM `json:"vms"`
	Error    string        `json:"error,omitempty"`
}

type dashboardActionResponse struct {
	OK      bool   `json:"ok"`
	Message string `json:"message,omitempty"`
	Error   string `json:"error,omitempty"`
}

func renderDashboardPage(w http.ResponseWriter) {
	setNoCacheHeaders(w)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	dashboardHTML, err := fs.ReadFile(staticFiles, dashboardHTMLPath)
	if err != nil {
		log.Printf("render dashboard page: %v", err)
		http.Error(w, "Dashboard template unavailable.", http.StatusInternalServerError)
		return
	}
	if _, err := w.Write(dashboardHTML); err != nil {
		log.Printf("render dashboard page: %v", err)
	}
}

func generateRDP(server, username string) string {
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

func listDashboardVMs(settings *config.SettingsType, user string) ([]dashboardVM, error) {
	vmList := virt.GetInstance().GetVMs(user)

	rows := make([]dashboardVM, 0, len(vmList))
	for _, vm := range vmList {
		displayName := vm.Name
		if domain := strings.TrimSpace(settings.GetString(config.FRONT_DOMAIN)); domain != "" {
			displayName = vm.Name + "." + domain
		}
		rows = append(rows, dashboardVM{
			Name:        vm.Name,
			DisplayName: displayName,
			RDPConnect:  generateRDP(displayName, user),
			IP:          vm.IP,
			State:       vm.State,
			MemoryMiB:   vm.MemoryMiB,
			VCPU:        vm.VCPU,
			VolumeGB:    vm.VolumeGB,
			TTYReady:    vm.TTYReady,
			VNCReady:    vm.VNCReady,
		})
	}
	return rows, nil
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	setNoCacheHeaders(w)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	if err := enc.Encode(payload); err != nil {
		log.Printf("write json response: %v", err)
	}
}
