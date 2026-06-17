package main

import (
	"context"
	"devboxgateway/internal/config"
	"devboxgateway/internal/ldap"
	"devboxgateway/internal/localauth"
	"devboxgateway/internal/session"
	"devboxgateway/internal/types"
	"devboxgateway/internal/virt"
	"devboxgateway/internal/vmname"
	"errors"
	"fmt"
	"html"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	consolepkg "devboxgateway/internal/console"
	dashboard "devboxgateway/internal/dashboard"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humachi"
	"github.com/go-chi/chi/v5"
)

const (
	cacheControlValue = "no-store, no-cache, must-revalidate, max-age=0"
	pragmaValue       = "no-cache"
	expiresValue      = "0"
	rdpFilename       = "rdpgw.rdp"
	forbiddenOrigin   = "Forbidden request origin."
	loginLocked       = "Too many login attempts. Try again later."
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

func handleLoginPost(sessionManager *session.Manager, settings *config.SettingsType, loginLimiter *loginRateLimiter) http.HandlerFunc {
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

		if rejectRateLimitedLogin(w, loginLimiter, "", r.RemoteAddr) {
			return
		}

		username, err = validateLoginUsername(username)
		if err != nil {
			log.Printf("rejected login attempt: %v", err)
			recordFailedLogin(w, loginLimiter, "", r.RemoteAddr, "Invalid credentials.")
			return
		}

		if rejectRateLimitedLogin(w, loginLimiter, username, r.RemoteAddr) {
			return
		}

		user, err := authenticateLogin(username, password, settings)
		if err != nil {
			log.Printf("auth failed for %s: %v", username, err)
			recordFailedLogin(w, loginLimiter, username, r.RemoteAddr, "Invalid credentials.")
			return
		}

		loginLimiter.RecordSuccess(username, r.RemoteAddr)
		completeLogin(sessionManager, w, r, user)
	}
}

func rejectRateLimitedLogin(w http.ResponseWriter, loginLimiter *loginRateLimiter, username, remoteAddr string) bool {
	retryAfter, limited := loginLimiter.RetryAfter(username, remoteAddr)
	if !limited {
		return false
	}
	serveLoginRateLimited(w, retryAfter)
	return true
}

func recordFailedLogin(w http.ResponseWriter, loginLimiter *loginRateLimiter, username, remoteAddr, message string) {
	if retryAfter := loginLimiter.RecordFailure(username, remoteAddr); retryAfter > 0 {
		serveLoginRateLimited(w, retryAfter)
		return
	}
	serveLogin(w, message)
}

// authenticateLogin authorizes a login attempt. Local users (matched against the
// LOCAL_USER_SHA256 digests) are checked first so the gateway works without a
// directory and without an LDAP round-trip; otherwise the credentials are
// validated against LDAP.
func authenticateLogin(username, password string, settings *config.SettingsType) (*types.User, error) {
	if localauth.Validate(username, password, settings) {
		return types.NewUser(username)
	}
	if !ldap.Configured(settings) {
		// Local-users-only mode: no directory to fall back to.
		return nil, errors.New("invalid credentials")
	}
	return ldap.AuthenticateAccess(username, password, settings)
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
	serveLoginStatus(w, message, http.StatusOK)
}

func serveLoginRateLimited(w http.ResponseWriter, retryAfter time.Duration) {
	w.Header().Set("Retry-After", loginRetryAfterSeconds(retryAfter))
	serveLoginStatus(w, loginLocked, http.StatusTooManyRequests)
}

func serveLoginStatus(w http.ResponseWriter, message string, status int) {
	setNoCacheHeaders(w)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
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
		if !sameOriginRequest(r) {
			http.Error(w, forbiddenOrigin, http.StatusForbidden)
			return
		}

		user, authenticated := sessionManager.UserFromContext(r.Context())
		username := ""
		if authenticated {
			username = user.GetName()
			if err := sessionManager.DestroyAllSessionsForUser(username); err != nil {
				log.Printf("destroy sessions for user %q failed: %v", username, err)
			}
		}
		if err := sessionManager.DestroySession(r.Context()); err != nil {
			log.Printf("session destroy failed: %v", err)
		}
		if authenticated {
			closed := sessionManager.CloseUserConnections(username)
			if closed > 0 {
				log.Printf("closed %d live connection(s) for user %q during logout", closed, username)
			}
		}
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	}
}

func sameOriginRequest(r *http.Request) bool {
	if origin := strings.TrimSpace(r.Header.Get("Origin")); origin != "" {
		return matchesRequestOrigin(origin, r)
	}
	return matchesRequestOrigin(strings.TrimSpace(r.Header.Get("Referer")), r)
}

func matchesRequestOrigin(raw string, r *http.Request) bool {
	if raw == "" {
		return false
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return false
	}
	return strings.EqualFold(parsed.Scheme, requestScheme(r)) && strings.EqualFold(parsed.Host, r.Host)
}

func requestScheme(r *http.Request) string {
	if r.URL != nil && r.URL.Scheme != "" {
		return r.URL.Scheme
	}
	if r.TLS != nil {
		return "https"
	}
	return "http"
}

// debugConnectionLogger logs every HTTP request (including WebSocket upgrades)
// with its source address, method, and path. It is installed only when
// DEBUG_CONNECTIONS is set, so operators can trace connectivity — for example,
// to confirm that dashboard and console traffic arrives through the SSH reverse
// tunnel and to see the originating address. It passes the ResponseWriter
// through unwrapped so it never interferes with the WebSocket hijack.
func debugConnectionLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		kind := "http"
		if strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
			kind = "websocket"
		}
		forwardedFor := r.Header.Get("X-Forwarded-For")
		if forwardedFor == "" {
			forwardedFor = "-"
		}
		log.Printf("debug-conn: %s from %s host=%q %s %s (forwarded-for=%s)",
			kind, r.RemoteAddr, r.Host, r.Method, r.URL.Path, forwardedFor)
		next.ServeHTTP(w, r)
	})
}

// contentSecurityPolicy locks the gateway's pages down to same-origin resources
// to blunt cross-site scripting. script-src stays strict ('self', no inline) —
// every script the login, dashboard, and noVNC pages load is a same-origin file
// and none use inline handlers, so this is the XSS-critical guarantee. The
// concessions are: style-src 'unsafe-inline' because xterm.js injects <style>
// elements at runtime; img-src data: for the noVNC framebuffer and cursor images
// rendered from base64 data: URLs; and connect-src 'self' for the dashboard and
// console WebSockets, which target this same origin.
const contentSecurityPolicy = "default-src 'self'; " +
	"script-src 'self'; " +
	"style-src 'self' 'unsafe-inline'; " +
	"img-src 'self' data:; " +
	"font-src 'self'; " +
	"connect-src 'self'; " +
	"object-src 'none'; " +
	"base-uri 'self'; " +
	"form-action 'self'; " +
	"frame-ancestors 'none'"

// securityHeaders sets HTTP response security headers on every response. The
// gateway terminates TLS and is only ever reachable over HTTPS, so HSTS is safe
// to assert unconditionally: it instructs browsers to refuse any future
// cleartext connection to this host. The remaining headers harden the dashboard
// and login pages against clickjacking, MIME-sniffing, and cross-site scripting.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", contentSecurityPolicy)
		next.ServeHTTP(w, r)
	})
}

func getRemoteGatewayRotuer(sessionManager *session.Manager, settings *config.SettingsType) http.Handler {
	router := chi.NewRouter()
	loginLimiter := newLoginRateLimiter(settings)
	if settings.GetBool(config.DEBUG_CONNECTIONS) {
		router.Use(debugConnectionLogger)
	}
	router.Use(securityHeaders)
	router.Use(sessionManager.LoadAndSave)

	router.Handle("/static/*", noCacheStaticFileServer())
	router.Post("/login", handleLoginPost(sessionManager, settings, loginLimiter))
	router.Get("/login", handleLoginGet)
	router.Post("/logout", handleLogout(sessionManager))

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
	router.Get("/api/dashboard/console/{name}/ws", consolepkg.HandleDashboardConsoleWS(sessionManager))
	router.Get("/api/dashboard/vnc/{name}/ws", consolepkg.HandleDashboardVNCWS(sessionManager))

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
	registerDashboardRDPRoute(group, sessionManager, settings)
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
	huma.Post(group, path, streamRoute(requireSameOriginDashboardPost(body)), hiddenStreamOperation)
}

func requireSameOriginDashboardPost(body dashboardRouteBody) dashboardRouteBody {
	return func(ctx huma.Context) {
		req, w := humachi.Unwrap(ctx)
		if !sameOriginRequest(req) {
			dashboard.WriteJSON(w, http.StatusForbidden, dashboard.ActionResponse{
				OK:    false,
				Error: forbiddenOrigin,
			})
			return
		}
		body(ctx)
	}
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
		vmRows, err := dashboard.ListDashboardVMs(user.Name)
		if err != nil {
			log.Printf("list vms: %v", err)
			dashboard.WriteJSON(w, http.StatusInternalServerError, dashboard.DataResponse{
				Filename: rdpFilename,
				Error:    "Unable to load virtual machines right now.",
			})
			return
		}
		baseImages, err := virt.ListBaseImages(settings)
		if err != nil {
			// A listing failure should not blank the whole dashboard; the create
			// form just shows no selectable images.
			log.Printf("list base images: %v", err)
			baseImages = nil
		}
		dashboard.WriteJSON(w, http.StatusOK, dashboard.DataResponse{
			Filename:   rdpFilename,
			Username:   user.Name,
			VMs:        vmRows,
			BaseImages: baseImages,
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
	baseImage     string
}

// parseCreateVMInput validates and collects the create-VM form fields. It writes
// the error response and returns ok=false when any field is invalid or the
// session is missing.
func parseCreateVMInput(w http.ResponseWriter, req *http.Request, sessionManager *session.Manager, settings *config.SettingsType) (createVMInput, bool) {
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
	baseImage, err := validateBaseImage(req.FormValue("vm_base_image"), settings)
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
		baseImage:     baseImage,
	}, true
}

func registerDashboardCreateRoute(group huma.API, sessionManager *session.Manager, settings *config.SettingsType) {
	registerHiddenPost(group, "/dashboard", func(ctx huma.Context) {
		req, w := humachi.Unwrap(ctx)
		input, ok := parseCreateVMInput(w, req, sessionManager, settings)
		if !ok {
			return
		}

		vmName, err := virt.BootNewVM(input.name, input.user, input.guestUsername, input.guestPassword, input.baseImage, settings, input.vcpu, input.memoryMiB)
		if errors.Is(err, virt.ErrVMAlreadyExists) {
			dashboard.WriteJSON(w, http.StatusConflict, dashboard.ActionResponse{
				OK:    false,
				Error: fmt.Sprintf("A VM named %q already exists. Delete it before creating a new one.", input.name),
			})
			return
		}
		if err != nil {
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

// registerDashboardRDPRoute serves the per-VM "Connect" action. It verifies the
// caller owns the VM, opens a short-lived RDP authorization window for the
// caller's client IP (so the RDP front handler's authorizeRDPAccess will admit
// the connection), and returns the .rdp connection file as a download. Making
// the download an explicit, authenticated, same-origin POST is what narrows RDP
// authorization to a deliberate action instead of any standing dashboard session.
func registerDashboardRDPRoute(group huma.API, sessionManager *session.Manager, settings *config.SettingsType) {
	registerHiddenPost(group, "/dashboard/rdp", func(ctx huma.Context) {
		req, w := humachi.Unwrap(ctx)
		name, ok := authorizeDashboardVMAction(req, w, sessionManager, "dashboard rdp", "connect to")
		if !ok {
			return
		}
		user, ok := sessionManager.UserFromContext(req.Context())
		if !ok {
			dashboard.WriteJSON(w, http.StatusUnauthorized, dashboard.ActionResponse{
				OK:    false,
				Error: "Login required.",
			})
			return
		}
		if err := sessionManager.GrantRDPConnect(req.Context(), name); err != nil {
			log.Printf("grant rdp connect for vm %q failed: %v", name, err)
			dashboard.WriteJSON(w, http.StatusInternalServerError, dashboard.ActionResponse{
				OK:    false,
				Error: "Failed to authorize RDP connection.",
			})
			return
		}
		dashboard.WriteRDPFile(w, settings, user.GetName(), name)
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

// validateBaseImage confirms the user-selected base image is one of the images
// currently offered by the gateway. The authoritative path-traversal guard
// lives in virt.BootNewVM; this exists to return a friendly 400 instead of a
// generic create failure when the selection is empty or unknown.
func validateBaseImage(raw string, settings *config.SettingsType) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("base image is required")
	}
	available, err := virt.ListBaseImages(settings)
	if err != nil {
		return "", fmt.Errorf("unable to list base images")
	}
	for _, name := range available {
		if name == raw {
			return raw, nil
		}
	}
	return "", fmt.Errorf("selected base image is not available")
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
