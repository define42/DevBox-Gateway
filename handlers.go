package main

import (
	"context"
	"errors"
	"fmt"
	"html"
	"log"
	"net/http"
	"rdptlsgateway/internal/config"
	consolepkg "rdptlsgateway/internal/console"
	dashboard "rdptlsgateway/internal/dashboard"
	"rdptlsgateway/internal/ldap"
	"rdptlsgateway/internal/session"
	"rdptlsgateway/internal/types"
	"rdptlsgateway/internal/virt"
	"rdptlsgateway/internal/vmname"
	"strconv"
	"strings"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humachi"
	"github.com/go-chi/chi/v5"
)

const (
	cacheControlValue = "no-store, no-cache, must-revalidate, max-age=0"
	pragmaValue       = "no-cache"
	expiresValue      = "0"
	rdpFilename       = "rdpgw.rdp"
	maxFormBodyBytes  = 1 << 20
	// maxVMNameLength and maxLoginUsernameLength mirror the canonical limits in
	// the vmname package, which is the single source of truth for VDI naming.
	maxVMNameLength   = vmname.MaxHostnameLength
	maxVMNameFieldLen = 128
	// maxGuestUsernameLength matches the conventional Linux useradd limit.
	maxGuestUsernameLength = 32
	// maxGuestPasswordLength bounds the optional guest account password set at
	// VM creation time.
	maxGuestPasswordLength = 128
	maxLoginUsernameLength = vmname.MaxUsernameLength
)

func parseFormWithBodyLimit(w http.ResponseWriter, req *http.Request) error {
	if req.Form != nil {
		return nil
	}
	req.Body = http.MaxBytesReader(w, req.Body, maxFormBodyBytes)
	return req.ParseForm()
}

func extractCredentials(w http.ResponseWriter, r *http.Request) (string, string, bool, error) {
	username, password, ok := r.BasicAuth()
	if ok && username != "" && password != "" {
		return username, password, true, nil
	}
	if err := parseFormWithBodyLimit(w, r); err != nil {
		return "", "", false, err
	}
	username = strings.TrimSpace(r.FormValue("username"))
	password = r.FormValue("password")
	if username == "" || password == "" {
		return username, password, false, nil
	}
	return username, password, true, nil
}

// validateLoginUsername normalizes and constrains the login username before it
// is trusted downstream. The username becomes the owner half of every VDI name,
// so the rules live in the vmname package (the single source of truth) and this
// is a thin wrapper for the login handler.
func validateLoginUsername(username string) (string, error) {
	return vmname.ValidateUsername(username)
}

func handleLoginPost(sessionManager *session.Manager, settings *config.SettingsType) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		username, password, ok, err := extractCredentials(w, r)
		if err != nil {
			serveLogin(w, "Invalid form submission.")
			return
		}
		if !ok {
			serveLogin(w, "Missing credentials.")
			return
		}

		username, err = validateLoginUsername(username)
		if err != nil {
			log.Printf("rejected login attempt: %v", err)
			serveLogin(w, "Invalid credentials.")
			return
		}

		user, err := ldap.AuthenticateAccess(username, password, settings)
		if err != nil {
			log.Printf("ldap auth failed for %s: %v", username, err)
			serveLogin(w, "Invalid credentials.")
			return
		}

		completeLogin(sessionManager, w, r, user, password)
	}
}

func completeLogin(sessionManager *session.Manager, w http.ResponseWriter, r *http.Request, user *types.User, password string) {
	if err := sessionManager.CreateAuthenticatedSession(r.Context(), user, r.RemoteAddr, password); err != nil {
		log.Printf("session create failed for %s: %v", user.GetName(), err)
		serveLogin(w, "Login failed.")
		return
	}
	http.Redirect(w, r, "/api/dashboard", http.StatusSeeOther)
}

func serveLogin(w http.ResponseWriter, message string) {
	setNoCacheHeaders(w)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	errorHTML := ""
	if message != "" {
		errorHTML = `<div class="alert alert-danger mb-3" role="alert">` + html.EscapeString(message) + `</div>`
	}
	if _, err := fmt.Fprint(w, strings.Replace(loginHTML, "{{ERROR}}", errorHTML, 1)); err != nil {
		log.Printf("serve login response: %v", err)
	}
}

func setNoCacheHeaders(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", cacheControlValue)
	w.Header().Set("Pragma", pragmaValue)
	w.Header().Set("Expires", expiresValue)
}

func handleLoginGet(w http.ResponseWriter, _ *http.Request) {
	serveLogin(w, "")
}

func handleLogout(sessionManager *session.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := sessionManager.DestroySession(r.Context()); err != nil {
			log.Printf("session destroy failed: %v", err)
		}
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	}
}

func getRemoteGatewayRotuer(sessionManager *session.Manager, settings *config.SettingsType) http.Handler {
	router := chi.NewRouter()
	router.Use(sessionManager.LoadAndSave)

	router.Handle("/static/*", noCacheStaticFileServer())
	router.Post("/login", handleLoginPost(sessionManager, settings))
	router.Get("/login", handleLoginGet)
	router.HandleFunc("/logout", handleLogout(sessionManager))

	router.HandleFunc("/api/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte("ok\n")); err != nil {
			log.Printf("failed to write health response: %v", err)
		}
	})

	apiCfg := huma.DefaultConfig("RemoteGateway", "1.0.0")
	apiCfg.OpenAPIPath = ""
	apiCfg.DocsPath = ""
	apiCfg.SchemasPath = ""
	api := humachi.New(router, apiCfg)
	registerAPI(api, sessionManager, settings)
	router.Get("/api/dashboard/console/{name}/ws", consolepkg.HandleDashboardConsoleWS(sessionManager, settings))
	router.Get("/api/dashboard/vnc/{name}/ws", consolepkg.HandleDashboardVNCWS(sessionManager, settings))

	router.Get("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	})
	return router
}

func noCacheStaticFileServer() http.Handler {
	fileServer := http.FileServer(http.FS(staticFiles))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		setNoCacheHeaders(w)
		fileServer.ServeHTTP(w, r)
	})
}

func registerAPI(api huma.API, sessionManager *session.Manager, settings *config.SettingsType) {
	group := huma.NewGroup(api, "/api")
	group.UseMiddleware(sessionManager.SessionMiddleware())

	registerDashboardPageRoute(group)
	registerDashboardDataRoute(group, sessionManager, settings)
	registerDashboardCreateRoute(group, sessionManager, settings)
	registerDashboardResourcesRoute(group, sessionManager)
	registerDashboardVMActionRoute(group, sessionManager, "/dashboard/remove", "dashboard remove", "remove", "Failed to remove VM.", "VM removed.", func(name string) error {
		return virt.RemoveVM(name, settings)
	})
	registerDashboardVMActionRoute(group, sessionManager, "/dashboard/start", "dashboard start", "start", "Failed to start VM.", "VM start requested.", virt.StartExistingVM)
	registerDashboardVMActionRoute(group, sessionManager, "/dashboard/restart", "dashboard restart", "restart", "Failed to restart VM.", "VM restart requested.", virt.RestartVM)
	registerDashboardVMActionRoute(group, sessionManager, "/dashboard/shutdown", "dashboard shutdown", "shutdown", "Failed to shutdown VM.", "VM shutdown requested.", virt.ShutdownVM)
}

type dashboardRouteBody func(huma.Context)

func hiddenStreamOperation(op *huma.Operation) {
	op.Hidden = true
}

func streamRoute(body dashboardRouteBody) func(context.Context, *struct{}) (*huma.StreamResponse, error) {
	return func(_ context.Context, _ *struct{}) (*huma.StreamResponse, error) {
		return &huma.StreamResponse{Body: body}, nil
	}
}

func registerHiddenGet(group huma.API, path string, body dashboardRouteBody) {
	huma.Get(group, path, streamRoute(body), hiddenStreamOperation)
}

func registerHiddenPost(group huma.API, path string, body dashboardRouteBody) {
	huma.Post(group, path, streamRoute(body), hiddenStreamOperation)
}

func registerDashboardPageRoute(group huma.API) {
	registerHiddenGet(group, "/dashboard", func(ctx huma.Context) {
		_, w := humachi.Unwrap(ctx)
		dashboard.RenderDashboardPage(w, staticFiles)
	})
}

func registerDashboardDataRoute(group huma.API, sessionManager *session.Manager, settings *config.SettingsType) {
	registerHiddenGet(group, "/dashboard/data", func(ctx huma.Context) {
		req, w := humachi.Unwrap(ctx)
		user, ok := sessionManager.UserFromContext(req.Context())
		if !ok {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		vmRows, err := dashboard.ListDashboardVMs(settings, user.Name)
		if err != nil {
			log.Printf("list vms: %v", err)
			dashboard.WriteJSON(w, http.StatusInternalServerError, dashboard.DataResponse{
				Filename: rdpFilename,
				Error:    "Unable to load virtual machines right now.",
			})
			return
		}
		dashboard.WriteJSON(w, http.StatusOK, dashboard.DataResponse{
			Filename: rdpFilename,
			Username: user.Name,
			VMs:      vmRows,
		})
	})
}

// createVMInput holds the validated dashboard create-VM form fields.
type createVMInput struct {
	name          string
	vcpu          int
	memoryMiB     int
	user          *types.User
	guestUsername string
	guestPassword string
}

// parseCreateVMInput validates and collects the create-VM form fields. It writes
// the error response and returns ok=false when any field is invalid or the
// session is missing.
func parseCreateVMInput(w http.ResponseWriter, req *http.Request, sessionManager *session.Manager) (createVMInput, bool) {
	if err := parseFormWithBodyLimit(w, req); err != nil {
		log.Printf("dashboard form parse failed: %v", err)
		dashboard.WriteJSON(w, http.StatusBadRequest, dashboard.ActionResponse{
			OK:    false,
			Error: "Invalid form submission.",
		})
		return createVMInput{}, false
	}

	name, err := validateVMName(req.FormValue("vm_name"))
	if handleDashboardFormError(w, "dashboard create", err) {
		return createVMInput{}, false
	}
	vcpu, err := parseDashboardVCPU(req.FormValue("vm_vcpu"))
	if handleDashboardFormError(w, "dashboard create", err) {
		return createVMInput{}, false
	}
	memoryMiB, err := parseDashboardMemoryMiB(req.FormValue("vm_memory_mib"))
	if handleDashboardFormError(w, "dashboard create", err) {
		return createVMInput{}, false
	}
	user, ok := sessionManager.UserFromContext(req.Context())
	if !ok {
		dashboard.WriteJSON(w, http.StatusUnauthorized, dashboard.ActionResponse{
			OK:    false,
			Error: "Login required.",
		})
		return createVMInput{}, false
	}
	guestUsername, err := validateGuestUsername(req.FormValue("vm_username"), user.GetName())
	if handleDashboardFormError(w, "dashboard create", err) {
		return createVMInput{}, false
	}
	guestPassword, err := validateGuestPassword(req.FormValue("vm_password"), req.FormValue("vm_password_confirm"))
	if handleDashboardFormError(w, "dashboard create", err) {
		return createVMInput{}, false
	}

	return createVMInput{
		name:          name,
		vcpu:          vcpu,
		memoryMiB:     memoryMiB,
		user:          user,
		guestUsername: guestUsername,
		guestPassword: guestPassword,
	}, true
}

func registerDashboardCreateRoute(group huma.API, sessionManager *session.Manager, settings *config.SettingsType) {
	registerHiddenPost(group, "/dashboard", func(ctx huma.Context) {
		req, w := humachi.Unwrap(ctx)
		input, ok := parseCreateVMInput(w, req, sessionManager)
		if !ok {
			return
		}

		if vmName, err := virt.BootNewVM(input.name, input.user, input.guestUsername, input.guestPassword, settings, input.vcpu, input.memoryMiB); err != nil {
			log.Printf("boot new vm %q failed: %v", vmName, err)
			dashboard.WriteJSON(w, http.StatusInternalServerError, dashboard.ActionResponse{
				OK:    false,
				Error: "Failed to create VM.",
			})
			return
		}

		dashboard.WriteJSON(w, http.StatusOK, dashboard.ActionResponse{
			OK:      true,
			Message: "VM creation started.",
		})
	})
}

func registerDashboardResourcesRoute(group huma.API, sessionManager *session.Manager) {
	registerHiddenPost(group, "/dashboard/resources", func(ctx huma.Context) {
		req, w := humachi.Unwrap(ctx)
		name, ok := authorizeDashboardVMAction(req, w, sessionManager, "dashboard resources", "update")
		if !ok {
			return
		}

		vcpu, err := parseDashboardVCPU(req.FormValue("vm_vcpu"))
		if handleDashboardFormError(w, "dashboard resources", err) {
			return
		}
		memoryMiB, err := parseDashboardMemoryMiB(req.FormValue("vm_memory_mib"))
		if handleDashboardFormError(w, "dashboard resources", err) {
			return
		}

		if err := virt.UpdateVMResources(name, vcpu, memoryMiB); err != nil {
			log.Printf("update resources for vm %q failed: %v", name, err)
			dashboard.WriteJSON(w, http.StatusBadRequest, dashboard.ActionResponse{
				OK:    false,
				Error: err.Error(),
			})
			return
		}

		dashboard.WriteJSON(w, http.StatusOK, dashboard.ActionResponse{
			OK:      true,
			Message: "VM resources updated.",
		})
	})
}

func registerDashboardVMActionRoute(
	group huma.API,
	sessionManager *session.Manager,
	path string,
	dashboardAction string,
	verb string,
	failureMessage string,
	successMessage string,
	run func(string) error,
) {
	registerHiddenPost(group, path, func(ctx huma.Context) {
		req, w := humachi.Unwrap(ctx)
		name, ok := authorizeDashboardVMAction(req, w, sessionManager, dashboardAction, verb)
		if !ok {
			return
		}
		if err := run(name); err != nil {
			log.Printf("%s vm %q failed: %v", verb, name, err)
			dashboard.WriteJSON(w, http.StatusInternalServerError, dashboard.ActionResponse{
				OK:    false,
				Error: failureMessage,
			})
			return
		}
		dashboard.WriteJSON(w, http.StatusOK, dashboard.ActionResponse{
			OK:      true,
			Message: successMessage,
		})
	})
}

func authorizeDashboardVMAction(req *http.Request, w http.ResponseWriter, sessionManager *session.Manager, dashboardAction string, verb string) (string, bool) {
	user, ok := sessionManager.UserFromContext(req.Context())
	if !ok {
		dashboard.WriteJSON(w, http.StatusUnauthorized, dashboard.ActionResponse{
			OK:    false,
			Error: "Login required.",
		})
		return "", false
	}

	name, err := parseDashboardVMName(w, req, user.GetName())
	if handleDashboardFormError(w, dashboardAction, err) {
		return "", false
	}

	owned, err := virt.UserOwnsVM(name, user.GetName())
	if err != nil {
		writeDashboardVMActionOwnershipError(w, name, user.GetName(), verb, err)
		return "", false
	}

	if !owned {
		writeDashboardVMActionOwnershipError(w, name, user.GetName(), verb, nil)
		return "", false
	}

	return name, true
}

func writeDashboardVMActionOwnershipError(w http.ResponseWriter, name, username, verb string, err error) {
	if err != nil {
		log.Printf("verify ownership for user %q %s vm %q failed: %v", username, verb, name, err)
		dashboard.WriteJSON(w, http.StatusInternalServerError, dashboard.ActionResponse{
			OK:    false,
			Error: "Unable to verify VM ownership.",
		})
		return
	}

	log.Printf("user %q attempted to %s vm %q not owned by them", username, verb, name)
	dashboard.WriteJSON(w, http.StatusForbidden, dashboard.ActionResponse{
		OK:    false,
		Error: fmt.Sprintf("You do not have permission to %s this VM.", verb),
	})
}

// validateVMName validates the user-chosen hostname half of a VDI name. The
// rules live in the vmname package; this is a thin wrapper for the dashboard
// handlers.
func validateVMName(name string) (string, error) {
	return vmname.ValidateHostname(name)
}

// validateGuestUsername validates the optional guest login name provisioned
// inside the VM. An empty value falls back to the owning user's name, matching
// the previous behavior where the guest account always mirrored the login user.
func validateGuestUsername(raw, fallback string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return fallback, nil
	}
	if len(raw) > maxGuestUsernameLength {
		return "", fmt.Errorf("username must be %d characters or fewer", maxGuestUsernameLength)
	}
	for i, r := range raw {
		switch {
		case r >= 'a' && r <= 'z':
		case r == '_':
		case i > 0 && r >= '0' && r <= '9':
		case i > 0 && r == '-':
		default:
			return "", fmt.Errorf("username must start with a lowercase letter or underscore and use only lowercase letters, numbers, hyphens, or underscores")
		}
	}
	return raw, nil
}

// validateGuestPassword validates the mandatory guest account password set at VM
// creation. The password must be supplied twice (raw and confirm) and the two
// values must match. The raw value is intentionally not trimmed because
// surrounding whitespace can be a meaningful part of a password.
func validateGuestPassword(raw, confirm string) (string, error) {
	if raw == "" {
		return "", fmt.Errorf("password is required")
	}
	if len(raw) > maxGuestPasswordLength {
		return "", fmt.Errorf("password must be %d characters or fewer", maxGuestPasswordLength)
	}
	for _, r := range raw {
		if r < 0x20 || r == 0x7f {
			return "", fmt.Errorf("password must not contain control characters")
		}
	}
	if raw != confirm {
		return "", fmt.Errorf("passwords do not match")
	}
	return raw, nil
}

func parseDashboardVMName(w http.ResponseWriter, req *http.Request, username string) (string, error) {
	if err := parseFormWithBodyLimit(w, req); err != nil {
		return "", fmt.Errorf("%w: %w", errInvalidDashboardForm, err)
	}
	name := strings.TrimSpace(req.FormValue("vm_name"))
	if name == "" {
		return "", fmt.Errorf("vm name is required")
	}
	username = strings.TrimSpace(username)
	if username != "" {
		prefix := username + "-"
		if suffix, ok := strings.CutPrefix(name, prefix); ok {
			validatedSuffix, err := validateVMName(suffix)
			if err != nil {
				return "", err
			}
			return prefix + validatedSuffix, nil
		}
	}
	if len(name) > maxVMNameFieldLen {
		return "", fmt.Errorf("vm name is too long")
	}
	return name, nil
}

func parseDashboardVCPU(raw string) (int, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, fmt.Errorf("cpu selection is required")
	}
	value, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("cpu selection is invalid")
	}
	allowedDashboardVCPU := map[int]struct{}{
		1: {},
		2: {},
		4: {},
		8: {},
	}

	if _, ok := allowedDashboardVCPU[value]; !ok {
		return 0, fmt.Errorf("cpu selection is not supported")
	}
	return value, nil
}

func parseDashboardMemoryMiB(raw string) (int, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, fmt.Errorf("memory selection is required")
	}
	value, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("memory selection is invalid")
	}

	allowedDashboardMemoryMiB := map[int]struct{}{
		4096:  {},
		8192:  {},
		16384: {},
		32768: {},
	}

	if _, ok := allowedDashboardMemoryMiB[value]; !ok {
		return 0, fmt.Errorf("memory selection is not supported")
	}
	return value, nil
}

func handleDashboardFormError(w http.ResponseWriter, action string, err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, errInvalidDashboardForm) {
		log.Printf("%s form parse failed: %v", action, err)
		dashboard.WriteJSON(w, http.StatusBadRequest, dashboard.ActionResponse{
			OK:    false,
			Error: "Invalid form submission.",
		})
		return true
	}
	dashboard.WriteJSON(w, http.StatusBadRequest, dashboard.ActionResponse{
		OK:    false,
		Error: err.Error(),
	})
	return true
}

var errInvalidDashboardForm = errors.New("invalid form submission")
