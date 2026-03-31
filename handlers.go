package main

import (
	"context"
	"errors"
	"fmt"
	"html"
	"log"
	"net/http"
	"rdptlsgateway/internal/config"
	"rdptlsgateway/internal/ldap"
	"rdptlsgateway/internal/session"
	"rdptlsgateway/internal/types"
	"rdptlsgateway/internal/virt"
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
)

func extractCredentials(r *http.Request) (string, string, bool, error) {
	username, password, ok := r.BasicAuth()
	if ok && username != "" && password != "" {
		return username, password, true, nil
	}
	if err := r.ParseForm(); err != nil {
		return "", "", false, err
	}
	username = strings.TrimSpace(r.FormValue("username"))
	password = r.FormValue("password")
	if username == "" || password == "" {
		return username, password, false, nil
	}
	return username, password, true, nil
}

func handleLoginPost(sessionManager *session.Manager, settings *config.SettingsType) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		username, password, ok, err := extractCredentials(r)
		if err != nil {
			serveLogin(w, "Invalid form submission.")
			return
		}
		if !ok {
			serveLogin(w, "Missing credentials.")
			return
		}

		user, err := ldap.AuthenticateAccess(username, password, settings)
		if err != nil {
			log.Printf("ldap auth failed for %s: %v", username, err)
			serveLogin(w, "Invalid credentials.")
			return
		}

		completeLogin(sessionManager, w, r, user)
	}
}

func completeLogin(sessionManager *session.Manager, w http.ResponseWriter, r *http.Request, user *types.User) {
	if err := sessionManager.CreateSession(r.Context(), user, r.RemoteAddr); err != nil {
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
	router.Get("/api/dashboard/console/{name}/ws", handleDashboardConsoleWS(sessionManager, settings))
	router.Get("/api/dashboard/vnc/{name}/ws", handleDashboardVNCWS(sessionManager, settings))

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
		renderDashboardPage(w)
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
		vmRows, err := listDashboardVMs(settings, user.Name)
		if err != nil {
			log.Printf("list vms: %v", err)
			writeJSON(w, http.StatusInternalServerError, dashboardDataResponse{
				Filename: rdpFilename,
				Error:    "Unable to load virtual machines right now.",
			})
			return
		}
		writeJSON(w, http.StatusOK, dashboardDataResponse{
			Filename: rdpFilename,
			VMs:      vmRows,
		})
	})
}

func registerDashboardCreateRoute(group huma.API, sessionManager *session.Manager, settings *config.SettingsType) {
	registerHiddenPost(group, "/dashboard", func(ctx huma.Context) {
		req, w := humachi.Unwrap(ctx)
		if err := req.ParseForm(); err != nil {
			log.Printf("dashboard form parse failed: %v", err)
			writeJSON(w, http.StatusBadRequest, dashboardActionResponse{
				OK:    false,
				Error: "Invalid form submission.",
			})
			return
		}

		name, err := validateVMName(req.FormValue("vm_name"))
		if handleDashboardFormError(w, "dashboard create", err) {
			return
		}
		vcpu, err := parseDashboardVCPU(req.FormValue("vm_vcpu"))
		if handleDashboardFormError(w, "dashboard create", err) {
			return
		}
		memoryMiB, err := parseDashboardMemoryMiB(req.FormValue("vm_memory_mib"))
		if handleDashboardFormError(w, "dashboard create", err) {
			return
		}
		user, ok := sessionManager.UserFromContext(req.Context())
		if !ok {
			writeJSON(w, http.StatusUnauthorized, dashboardActionResponse{
				OK:    false,
				Error: "Login required.",
			})
			return
		}

		if vmName, err := virt.BootNewVM(name, user, settings, vcpu, memoryMiB); err != nil {
			log.Printf("boot new vm %q failed: %v", vmName, err)
			writeJSON(w, http.StatusInternalServerError, dashboardActionResponse{
				OK:    false,
				Error: "Failed to create VM.",
			})
			return
		}

		writeJSON(w, http.StatusOK, dashboardActionResponse{
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
			writeJSON(w, http.StatusBadRequest, dashboardActionResponse{
				OK:    false,
				Error: err.Error(),
			})
			return
		}

		writeJSON(w, http.StatusOK, dashboardActionResponse{
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
			writeJSON(w, http.StatusInternalServerError, dashboardActionResponse{
				OK:    false,
				Error: failureMessage,
			})
			return
		}
		writeJSON(w, http.StatusOK, dashboardActionResponse{
			OK:      true,
			Message: successMessage,
		})
	})
}

func authorizeDashboardVMAction(req *http.Request, w http.ResponseWriter, sessionManager *session.Manager, dashboardAction string, verb string) (string, bool) {
	user, ok := sessionManager.UserFromContext(req.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, dashboardActionResponse{
			OK:    false,
			Error: "Login required.",
		})
		return "", false
	}

	name, err := parseDashboardVMName(req)
	if handleDashboardFormError(w, dashboardAction, err) {
		return "", false
	}

	owned, err := dashboardVMOwnershipCheck(name, user.GetName())
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
		writeJSON(w, http.StatusInternalServerError, dashboardActionResponse{
			OK:    false,
			Error: "Unable to verify VM ownership.",
		})
		return
	}

	log.Printf("user %q attempted to %s vm %q not owned by them", username, verb, name)
	writeJSON(w, http.StatusForbidden, dashboardActionResponse{
		OK:    false,
		Error: fmt.Sprintf("You do not have permission to %s this VM.", verb),
	})
}

func validateVMName(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", fmt.Errorf("vm name is required")
	}
	if len(name) > 63 {
		return "", fmt.Errorf("vm name must be 63 characters or fewer")
	}
	if strings.HasPrefix(name, "-") || strings.HasSuffix(name, "-") {
		return "", fmt.Errorf("vm name cannot start or end with a hyphen")
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= '0' && r <= '9':
		case r == '-':
		default:
			return "", fmt.Errorf("vm name must use lowercase letters, numbers, or hyphens")
		}
	}
	return name, nil
}

func parseDashboardVMName(req *http.Request) (string, error) {
	if err := req.ParseForm(); err != nil {
		return "", fmt.Errorf("%w: %w", errInvalidDashboardForm, err)
	}
	name := strings.TrimSpace(req.FormValue("vm_name"))
	if name == "" {
		return "", fmt.Errorf("vm name is required")
	}
	if len(name) > 128 {
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
		writeJSON(w, http.StatusBadRequest, dashboardActionResponse{
			OK:    false,
			Error: "Invalid form submission.",
		})
		return true
	}
	writeJSON(w, http.StatusBadRequest, dashboardActionResponse{
		OK:    false,
		Error: err.Error(),
	})
	return true
}

var errInvalidDashboardForm = errors.New("invalid form submission")
