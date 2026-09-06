package gateway

import (
	"context"
	"errors"
	"fmt"
	"html"
	"io/fs"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/define42/devbox-gateway/internal/audit"
	"github.com/define42/devbox-gateway/internal/config"
	"github.com/define42/devbox-gateway/internal/hash"
	"github.com/define42/devbox-gateway/internal/identity"
	"github.com/define42/devbox-gateway/internal/ldap"
	"github.com/define42/devbox-gateway/internal/session"
	"github.com/define42/devbox-gateway/internal/virt"
	"github.com/define42/devbox-gateway/internal/vmname"
	"github.com/define42/devbox-gateway/internal/webassets"

	consolepkg "github.com/define42/devbox-gateway/internal/console"
	dashboard "github.com/define42/devbox-gateway/internal/dashboard"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humachi"
	"github.com/go-chi/chi/v5"
)

func staticFiles() fs.FS {
	return webassets.Files()
}

const (
	cacheControlValue = "no-store, no-cache, must-revalidate, max-age=0"
	pragmaValue       = "no-cache"
	expiresValue      = "0"
	rdpFilename       = dashboard.DefaultRDPFilename
	forbiddenOrigin   = "Forbidden request origin."
	loginLocked       = "Too many login attempts. Try again later."
	maxFormBodyBytes  = 1 << 20
	// maxVMNameLength and maxLoginUsernameLength mirror the canonical limits in
	// the vmname package, which is the single source of truth for VDI naming.
	maxVMNameLength   = vmname.MaxHostnameLength
	maxVMNameFieldLen = vmname.MaxUsernameLength + len(vmname.Separator) + vmname.MaxHostnameLength
	// maxGuestUsernameLength matches the conventional Linux useradd limit.
	maxGuestUsernameLength = 32
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

type loginAuthenticator func(ctx context.Context, username, password string, settings *config.Settings) (*identity.User, error)

func handleLoginPost(sessionManager *session.Manager, settings *config.Settings, loginLimiter *loginRateLimiter) http.HandlerFunc {
	return handleLoginPostWithAuthenticator(sessionManager, settings, loginLimiter, ldap.AuthenticateAccess)
}

func handleLoginPostWithAuthenticator(
	sessionManager *session.Manager,
	settings *config.Settings,
	loginLimiter *loginRateLimiter,
	authenticate loginAuthenticator,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Gate login behind the same-origin check that guards logout and every
		// dashboard POST. Without it the endpoint is open to login CSRF: an
		// attacker auto-submits a cross-site form POST carrying their own
		// credentials, the gateway authenticates them and plants a fresh session
		// cookie, and the victim silently ends up operating under the attacker's
		// identity. SameSite=Lax does not stop this — it blocks riding an
		// existing session, not establishing a new one — so the origin gate is
		// what closes it. Reject before touching the rate limiter or credential
		// parsing so forged requests do no work.
		if !sameOriginRequest(r) {
			http.Error(w, forbiddenOrigin, http.StatusForbidden)
			return
		}

		username, password, ok, err := extractCredentials(w, r)
		if err != nil {
			serveLogin(w, settings, "Invalid form submission.")
			return
		}
		if !ok {
			serveLogin(w, settings, "Missing credentials.")
			return
		}

		if rejectRateLimitedLogin(w, settings, loginLimiter, "", r.RemoteAddr) {
			return
		}

		username, err = validateLoginUsername(username)
		if err != nil {
			log.Printf("rejected login attempt: %v", err)
			recordFailedLogin(w, settings, loginLimiter, "", r.RemoteAddr, "Invalid credentials.")
			return
		}

		if rejectRateLimitedLogin(w, settings, loginLimiter, username, r.RemoteAddr) {
			return
		}

		user, err := authenticate(r.Context(), username, password, settings)
		if err != nil {
			log.Printf("auth failed for %s: %v", strconv.Quote(username), err)
			auditLoginFailure(r, username)
			recordFailedLogin(w, settings, loginLimiter, username, r.RemoteAddr, "Invalid credentials.")
			return
		}

		loginLimiter.RecordSuccess(username, r.RemoteAddr)
		completeLogin(sessionManager, settings, w, r, user, password)
	}
}

func rejectRateLimitedLogin(w http.ResponseWriter, settings *config.Settings, loginLimiter *loginRateLimiter, username, remoteAddr string) bool {
	retryAfter, limited := loginLimiter.RetryAfter(username, remoteAddr)
	if !limited {
		return false
	}
	serveLoginRateLimited(w, settings, retryAfter)
	return true
}

func recordFailedLogin(w http.ResponseWriter, settings *config.Settings, loginLimiter *loginRateLimiter, username, remoteAddr, message string) {
	if retryAfter := loginLimiter.RecordFailure(username, remoteAddr); retryAfter > 0 {
		serveLoginRateLimited(w, settings, retryAfter)
		return
	}
	serveLogin(w, settings, message)
}

// completeLogin establishes the authenticated session for a user whose
// credentials have just been verified. Any session-establishment failure is a
// server-side error that aborts the login.
func completeLogin(sessionManager *session.Manager, settings *config.Settings, w http.ResponseWriter, r *http.Request, user *identity.User, password string) {
	if err := establishSession(r.Context(), sessionManager, user, r.RemoteAddr, password); err != nil {
		log.Printf("login completion failed for %s: %v", strconv.Quote(user.Name), err)
		auditLoginFailure(r, user.Name)
		serveLogin(w, settings, "Login failed.")
		return
	}
	markLoginForAudit(r, user)
	http.Redirect(w, r, "/api/dashboard", http.StatusSeeOther)
}

func auditLoginFailure(r *http.Request, username string) {
	clientIP, _ := session.CanonicalClientIP(r.RemoteAddr)
	audit.Log(r.Context(), audit.Event{
		Action:   audit.ActionUserLogin,
		User:     username,
		Result:   audit.ResultFailure,
		SourceIP: clientIP,
	})
}

// establishSession digests the password and creates the session. The password
// is digested right away so only its salted sha512_crypt hash outlives this
// request: the hash is stored in the in-memory session and later seeds the
// guest account when the user creates a VDI; the cleartext is never retained.
func establishSession(ctx context.Context, sessionManager *session.Manager, user *identity.User, remoteAddr, password string) error {
	loginPasswordHash, err := hash.CloudInitPassword(password)
	if err != nil {
		return err
	}
	return sessionManager.CreateSession(ctx, user, remoteAddr, loginPasswordHash)
}

func serveLogin(w http.ResponseWriter, settings *config.Settings, message string) {
	serveLoginStatus(w, settings, message, http.StatusOK)
}

func serveLoginRateLimited(w http.ResponseWriter, settings *config.Settings, retryAfter time.Duration) {
	w.Header().Set("Retry-After", loginRetryAfterSeconds(retryAfter))
	serveLoginStatus(w, settings, loginLocked, http.StatusTooManyRequests)
}

func serveLoginStatus(w http.ResponseWriter, settings *config.Settings, message string, status int) {
	setNoCacheHeaders(w)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	errorHTML := ""
	if message != "" {
		errorHTML = `<div class="alert alert-danger mb-3" role="alert">` + html.EscapeString(message) + `</div>`
	}
	page := strings.Replace(loginHTML, "{{ERROR}}", errorHTML, 1)
	page = strings.Replace(page, "{{GROUPS}}", loginGroupsHTML(settings), 1)
	if _, err := fmt.Fprint(w, page); err != nil {
		log.Printf("serve login response: %v", err)
	}
}

// loginGroupsHTML renders the informational box below the login form telling
// users which directory groups grant access. Empty when LDAP_REQUIRED_GROUPS
// is unset (or LDAP is not configured), so the box only appears when a group
// requirement is actually enforced. Group names are HTML-escaped because they
// come from operator configuration, not from request input.
func loginGroupsHTML(settings *config.Settings) string {
	names := ldap.RequiredGroupNames(settings)
	if len(names) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString(`<div class="alert alert-info mt-4 mb-0" role="note"><div class="small fw-semibold mb-1"><i class="bi bi-people me-1" aria-hidden="true"></i>The following groups give access:</div><ul class="small mb-0 ps-4">`)
	for _, name := range names {
		b.WriteString("<li>")
		b.WriteString(html.EscapeString(name))
		b.WriteString("</li>")
	}
	b.WriteString("</ul></div>")
	return b.String()
}

func setNoCacheHeaders(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", cacheControlValue)
	w.Header().Set("Pragma", pragmaValue)
	w.Header().Set("Expires", expiresValue)
}

func handleLoginGet(settings *config.Settings) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		serveLogin(w, settings, "")
	}
}

func handleLogout(sessionManager *session.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !sameOriginRequest(r) {
			http.Error(w, forbiddenOrigin, http.StatusForbidden)
			return
		}

		user, authenticated := sessionManager.UserFromContext(r.Context())
		username := ""
		logoutResult := audit.ResultSuccess
		if authenticated {
			username = user.Name
			if err := sessionManager.DestroyAllSessionsForUser(username); err != nil {
				logoutResult = audit.ResultFailure
				log.Printf("destroy sessions for user %q failed: %v", username, err)
			}
		}
		if err := sessionManager.DestroySession(r.Context()); err != nil {
			logoutResult = audit.ResultFailure
			log.Printf("destroy current session for user %q failed: %v", username, err)
		}
		if authenticated {
			closed := sessionManager.CloseUserConnections(username)
			if closed > 0 {
				log.Printf("closed %d live connection(s) for user %q during logout", closed, username)
			}
			clientIP, _ := session.CanonicalClientIP(r.RemoteAddr)
			audit.Log(r.Context(), audit.Event{
				Action:        audit.ActionUserLogout,
				User:          username,
				Result:        logoutResult,
				SourceIP:      clientIP,
				Administrator: user.IsAdmin,
			})
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

type loginAuditState struct {
	user     *identity.User
	sourceIP string
}

type loginAuditContextKey struct{}

type statusResponseWriter struct {
	http.ResponseWriter

	status int
}

func (w *statusResponseWriter) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *statusResponseWriter) Write(payload []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(payload)
}

func (w *statusResponseWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

func auditLoginOutcome(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/login" {
			next.ServeHTTP(w, r)
			return
		}
		state := &loginAuditState{}
		request := r.WithContext(context.WithValue(r.Context(), loginAuditContextKey{}, state))
		response := &statusResponseWriter{ResponseWriter: w}
		next.ServeHTTP(response, request)
		if state.user == nil {
			return
		}

		result := audit.ResultFailure
		if response.status == http.StatusSeeOther {
			result = audit.ResultSuccess
		}
		audit.Log(request.Context(), audit.Event{
			Action:        audit.ActionUserLogin,
			User:          state.user.Name,
			Result:        result,
			SourceIP:      state.sourceIP,
			Administrator: state.user.IsAdmin,
		})
	})
}

func markLoginForAudit(r *http.Request, user *identity.User) {
	state, ok := r.Context().Value(loginAuditContextKey{}).(*loginAuditState)
	if !ok {
		return
	}
	state.user = user
	state.sourceIP, _ = session.CanonicalClientIP(r.RemoteAddr)
}

// debugConnectionLogger logs every HTTP request (including WebSocket upgrades)
// with its source address, method, and path. It is installed only when
// DEBUG_CONNECTIONS is set, so operators can trace connectivity and see the
// originating address. It passes the ResponseWriter through unwrapped so it
// never interferes with the WebSocket hijack.
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
		log.Printf("debug-conn: %s from %s host=%s %s %s (forwarded-for=%s)",
			kind, strconv.Quote(r.RemoteAddr), strconv.Quote(r.Host), strconv.Quote(r.Method),
			strconv.Quote(r.URL.Path), strconv.Quote(forwardedFor))
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
	// 'self', not 'none': the dashboard embeds the noVNC viewer
	// (/static/novnc/vnc.html) in a same-origin iframe. This still blocks
	// third-party sites from framing the gateway.
	"frame-ancestors 'self'"

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
		h.Set("X-Frame-Options", "SAMEORIGIN")
		// same-origin (not no-referrer): no-referrer makes browsers send
		// "Origin: null" on same-origin form POSTs, which breaks the logout and
		// dashboard same-origin checks. same-origin still withholds the referrer
		// from third parties while preserving Origin/Referer for our own requests.
		h.Set("Referrer-Policy", "same-origin")
		h.Set("Content-Security-Policy", contentSecurityPolicy)
		next.ServeHTTP(w, r)
	})
}

// NewHandler constructs the gateway's HTTP application.
func NewHandler(sessionManager *session.Manager, settings *config.Settings) http.Handler {
	router := chi.NewRouter()
	loginLimiter := newLoginRateLimiter(settings)
	if settings.Bool(config.DEBUG_CONNECTIONS) {
		router.Use(debugConnectionLogger)
	}
	router.Use(auditLoginOutcome)
	router.Use(securityHeaders)
	router.Use(sessionManager.LoadAndSave)
	router.Use(sessionManager.EnforceClientIP)

	router.Handle("/static/*", noCacheStaticFileServer())
	router.Post("/login", handleLoginPost(sessionManager, settings, loginLimiter))
	router.Get("/login", handleLoginGet(settings))
	router.Post("/logout", handleLogout(sessionManager))

	router.HandleFunc("/api/health", func(w http.ResponseWriter, _ *http.Request) {
		// Health checks are unauthenticated; close the connection after each
		// response so parked keep-alive probes cannot pin front-connection
		// slots for the httpIdleTimeout between requests.
		w.Header().Set("Connection", "close")
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
	router.Get("/api/dashboard/ws", consolepkg.HandleDashboardWS(sessionManager, settings))
	router.Get("/api/admin/ws", consolepkg.HandleAdminDashboardWS(sessionManager, settings))

	router.Get("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	})
	return router
}

func noCacheStaticFileServer() http.Handler {
	fileServer := http.FileServer(http.FS(staticFiles()))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		setNoCacheHeaders(w)
		fileServer.ServeHTTP(w, r)
	})
}

func registerAPI(api huma.API, sessionManager *session.Manager, settings *config.Settings) {
	group := huma.NewGroup(api, "/api")
	group.UseMiddleware(sessionManager.SessionMiddleware())

	registerDashboardPageRoute(group)
	registerDashboardDataRoute(group, sessionManager, settings)
	registerAdminPageRoute(group, sessionManager)
	registerAdminDataRoute(group, sessionManager, settings)
	registerAdminBaseImageRoutes(group, sessionManager, settings)
	registerDashboardCreateRoute(group, sessionManager, settings)
	registerDashboardRDPRoute(group, sessionManager, settings)
	for _, spec := range []dashboardVMActionSpec{
		{
			path:           "/dashboard/remove",
			action:         "dashboard remove",
			verb:           "remove",
			auditAction:    audit.ActionVMRemove,
			failureMessage: "Failed to remove VM.",
			successMessage: "VM removed.",
			run: func(name string) error {
				return virt.RemoveVM(name, settings)
			},
		},
		{
			path:           "/dashboard/start",
			action:         "dashboard start",
			verb:           "start",
			auditAction:    audit.ActionVMStart,
			failureMessage: "Failed to start VM.",
			successMessage: "VM start requested.",
			run:            virt.StartExistingVM,
		},
		{
			path:           "/dashboard/restart",
			action:         "dashboard restart",
			verb:           "restart",
			auditAction:    audit.ActionVMReboot,
			auditOperation: "restart",
			failureMessage: "Failed to restart VM.",
			successMessage: "VM restart requested.",
			run:            virt.RestartVM,
		},
		{
			path:           "/dashboard/shutdown",
			action:         "dashboard shutdown",
			verb:           "shutdown",
			auditAction:    audit.ActionVMStop,
			auditOperation: "shutdown",
			failureMessage: "Failed to shutdown VM.",
			successMessage: "VM shutdown requested.",
			run:            virt.ShutdownVM,
		},
	} {
		registerDashboardVMActionRoute(group, sessionManager, spec)
	}
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
		dashboard.RenderPage(w, staticFiles())
	})
}

func registerDashboardDataRoute(group huma.API, sessionManager *session.Manager, settings *config.Settings) {
	registerHiddenGet(group, "/dashboard/data", func(ctx huma.Context) {
		req, w := humachi.Unwrap(ctx)
		user, ok := sessionManager.UserFromContext(req.Context())
		if !ok {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		response, err := dashboard.DataForUser(settings, user.Name)
		response.IsAdmin = user.IsAdmin
		if err != nil {
			log.Printf("list vms: %v", err)
			response.Error = "Unable to load virtual machines right now."
			dashboard.WriteJSON(w, http.StatusInternalServerError, response)
			return
		}
		// RDP readiness is owned by the dashboard WebSocket. Do not let the HTTP
		// bootstrap replay a positive result cached by a previous connection;
		// the socket performs a fresh probe before sending its first snapshot.
		for i := range response.VMs {
			response.VMs[i].RDPReady = false
		}
		dashboard.WriteJSON(w, http.StatusOK, response)
	})
}

func registerAdminPageRoute(group huma.API, sessionManager *session.Manager) {
	registerHiddenGet(group, "/admin", func(ctx huma.Context) {
		req, w := humachi.Unwrap(ctx)
		if _, ok := requireAdmin(req, w, sessionManager); !ok {
			return
		}
		dashboard.RenderPage(w, staticFiles())
	})
}

func registerAdminDataRoute(group huma.API, sessionManager *session.Manager, settings *config.Settings) {
	registerHiddenGet(group, "/admin/data", func(ctx huma.Context) {
		req, w := humachi.Unwrap(ctx)
		if _, ok := requireAdmin(req, w, sessionManager); !ok {
			return
		}

		response, err := dashboard.DataForAdmin(settings)
		if err != nil {
			log.Printf("list vms for admin dashboard: %v", err)
			response.Error = "Unable to load virtual machines right now."
			dashboard.WriteJSON(w, http.StatusInternalServerError, response)
			return
		}
		dashboard.WriteJSON(w, http.StatusOK, response)
	})
}

func requireAdmin(req *http.Request, w http.ResponseWriter, sessionManager *session.Manager) (*identity.User, bool) {
	user, ok := sessionManager.UserFromContext(req.Context())
	if !ok {
		http.Error(w, "Login required.", http.StatusUnauthorized)
		return nil, false
	}
	if !user.IsAdmin {
		http.Error(w, "Administrator access required.", http.StatusForbidden)
		return nil, false
	}
	return user, true
}

// parseCreateVMInput validates and collects the create-VM form fields into a
// virt.VMCreateRequest. It writes the error response and returns ok=false when
// any field is invalid or the session is missing. CPU and memory are
// deliberately never read from the form: VM resources are operator-defined
// only (VM_VCPU_COUNT / VM_MEMORY_MIB). The guest password is not a form field
// either: the guest account is provisioned with the salted sha512_crypt hash
// of the user's own gateway login password, captured at login and held in the
// in-memory session (never in cleartext).
func parseCreateVMInput(w http.ResponseWriter, req *http.Request, sessionManager *session.Manager, settings *config.Settings) (virt.VMCreateRequest, bool) {
	user, authenticated := sessionManager.UserFromContext(req.Context())
	if err := parseFormWithBodyLimit(w, req); err != nil {
		auditCreateVMValidationFailure(req, user, "")
		log.Printf("dashboard form parse failed: %v", err)
		dashboard.WriteJSON(w, http.StatusBadRequest, dashboard.ActionResponse{
			OK:    false,
			Error: "Invalid form submission.",
		})
		return virt.VMCreateRequest{}, false
	}

	name, err := validateVMName(req.FormValue("vm_name"))
	if handleDashboardFormError(w, "dashboard create", err) {
		auditCreateVMValidationFailure(req, user, "")
		return virt.VMCreateRequest{}, false
	}
	if !authenticated {
		dashboard.WriteJSON(w, http.StatusUnauthorized, dashboard.ActionResponse{
			OK:    false,
			Error: "Login required.",
		})
		return virt.VMCreateRequest{}, false
	}
	guestUsername, err := validateGuestUsername(req.FormValue("vm_username"), user.Name)
	if handleDashboardFormError(w, "dashboard create", err) {
		auditCreateVMValidationFailure(req, user, name)
		return virt.VMCreateRequest{}, false
	}
	// The guest account password is the user's own gateway login password. Only
	// its salted sha512_crypt hash was kept (in the session, at login), so that
	// digest — never a cleartext password — is what flows into the VM seed. A
	// session without a stored hash (e.g. created before a gateway upgrade)
	// cannot provision a guest account, so ask for a fresh login.
	guestPasswordHash, ok := sessionManager.PasswordHashFromContext(req.Context())
	if !ok {
		auditCreateVMValidationFailure(req, user, name)
		dashboard.WriteJSON(w, http.StatusUnauthorized, dashboard.ActionResponse{
			OK:    false,
			Error: "Your session is missing the credentials needed to create a DevBox. Log out and log in again.",
		})
		return virt.VMCreateRequest{}, false
	}
	baseImage, err := validateBaseImage(req.FormValue("vm_base_image"), settings)
	if handleDashboardFormError(w, "dashboard create", err) {
		auditCreateVMValidationFailure(req, user, name)
		return virt.VMCreateRequest{}, false
	}
	return virt.VMCreateRequest{
		Name:          name,
		Owner:         user,
		GuestUsername: guestUsername,
		PasswordHash:  guestPasswordHash,
		BaseImage:     baseImage,
	}, true
}

// auditCreateVMValidationFailure records an authenticated create attempt that
// failed before provisioning. validatedName must be empty or the canonical
// hostname returned by validateVMName; raw request values must never reach this
// helper. Compose supplies the full VM name only when both identity components
// remain valid, otherwise the event safely omits the target.
func auditCreateVMValidationFailure(req *http.Request, user *identity.User, validatedName string) {
	if user == nil {
		return
	}
	vmName := ""
	if validatedName != "" {
		vmName, _ = vmname.Compose(user.Name, validatedName)
	}
	auditVMAction(req, user, audit.ActionVMCreate, vmName, "", audit.ResultFailure)
}

func registerDashboardCreateRoute(group huma.API, sessionManager *session.Manager, settings *config.Settings) {
	registerHiddenPost(group, "/dashboard", func(ctx huma.Context) {
		req, w := humachi.Unwrap(ctx)
		input, ok := parseCreateVMInput(w, req, sessionManager, settings)
		if !ok {
			return
		}

		var creationStream *dashboard.CreationStream
		var reportProgress virt.DiskCopyProgressFunc
		if dashboard.AcceptsCreationStream(req) {
			creationStream = dashboard.NewCreationStream(w)
			reportProgress = creationStream.ReportDiskCopy
		}

		vmName, err := virt.BootNewVMWithProgress(input, settings, reportProgress)
		auditResult := audit.ResultSuccess
		if err != nil {
			auditResult = audit.ResultFailure
		}
		auditVMAction(req, input.Owner, audit.ActionVMCreate, vmName, "", auditResult)
		status, result := dashboardCreateResult(input.Name, vmName, err, settings)
		if creationStream != nil && creationStream.Started() {
			if result.OK {
				result.Message = "VM created."
			}
			creationStream.WriteResult(result)
			return
		}
		dashboard.WriteJSON(w, status, result)
	})
}

func dashboardCreateResult(name, vmName string, err error, settings *config.Settings) (int, dashboard.ActionResponse) {
	switch {
	case errors.Is(err, virt.ErrVMAlreadyExists):
		return http.StatusConflict, dashboard.ActionResponse{
			OK:    false,
			Error: fmt.Sprintf("A VM named %q already exists. Delete it before creating a new one.", name),
		}
	case errors.Is(err, virt.ErrVMLimitReached):
		return http.StatusConflict, dashboard.ActionResponse{
			OK:    false,
			Error: fmt.Sprintf("VM limit reached: each user can have at most %d VMs. Delete one before creating a new one.", config.MaxVDIPerUser(settings)),
		}
	case err != nil:
		log.Printf("boot new vm %q failed: %v", vmName, err)
		return http.StatusInternalServerError, dashboard.ActionResponse{
			OK:    false,
			Error: "Failed to create VM.",
		}
	default:
		return http.StatusOK, dashboard.ActionResponse{
			OK:      true,
			Message: "VM creation started.",
		}
	}
}

// registerDashboardRDPRoute serves the per-VM "Connect" action. It verifies the
// caller owns the VM, opens a short-lived RDP authorization window for the
// caller's client IP (so the RDP front handler's authorizeRDPAccess will admit
// the connection), and returns the .rdp connection file as a download. Making
// the download an explicit, authenticated, same-origin POST is what narrows RDP
// authorization to a deliberate action instead of any standing dashboard session.
func registerDashboardRDPRoute(group huma.API, sessionManager *session.Manager, settings *config.Settings) {
	registerHiddenPost(group, "/dashboard/rdp", func(ctx huma.Context) {
		req, w := humachi.Unwrap(ctx)
		name, user, ok := authorizeDashboardVMAction(
			req,
			w,
			sessionManager,
			"dashboard rdp",
			"connect to",
			dashboardVMActionOwnerOnly,
			"",
			"",
		)
		if !ok {
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
		// The RDP connect click counts as use for auto-shutdown.
		virt.MarkVMUsed(name)
		dashboard.WriteRDPFile(w, settings, user.Name, name)
	})
}

// dashboardVMActionSpec describes one per-VM dashboard action route: where it
// is mounted, how it is named in logs and form-error messages, what the user
// sees on success or failure, and the virt operation it invokes.
type dashboardVMActionSpec struct {
	path           string
	action         string
	verb           string
	auditAction    string
	auditOperation string
	failureMessage string
	successMessage string
	run            func(string) error
}

func registerDashboardVMActionRoute(group huma.API, sessionManager *session.Manager, spec dashboardVMActionSpec) {
	registerHiddenPost(group, spec.path, func(ctx huma.Context) {
		req, w := humachi.Unwrap(ctx)
		name, user, ok := authorizeDashboardVMAction(
			req,
			w,
			sessionManager,
			spec.action,
			spec.verb,
			dashboardVMActionLifecycle,
			spec.auditAction,
			spec.auditOperation,
		)
		if !ok {
			return
		}
		if err := spec.run(name); err != nil {
			auditVMAction(req, user, spec.auditAction, name, spec.auditOperation, audit.ResultFailure)
			log.Printf("%s vm %q for user %q failed: %v", spec.verb, name, user.Name, err)
			dashboard.WriteJSON(w, http.StatusInternalServerError, dashboard.ActionResponse{
				OK:    false,
				Error: spec.failureMessage,
			})
			return
		}
		auditVMAction(req, user, spec.auditAction, name, spec.auditOperation, audit.ResultSuccess)
		dashboard.WriteJSON(w, http.StatusOK, dashboard.ActionResponse{
			OK:      true,
			Message: spec.successMessage,
		})
	})
}

func auditVMAction(req *http.Request, user *identity.User, action, name, operation, result string) {
	clientIP, _ := session.CanonicalClientIP(req.RemoteAddr)
	audit.Log(req.Context(), audit.Event{
		Action:        action,
		User:          user.Name,
		Result:        result,
		SourceIP:      clientIP,
		VM:            name,
		Operation:     operation,
		Administrator: user.IsAdmin,
	})
}

func auditFailedVMAction(req *http.Request, user *identity.User, action, name, operation string) {
	if action != "" {
		auditVMAction(req, user, action, name, operation, audit.ResultFailure)
	}
}

type dashboardVMActionScope uint8

const (
	dashboardVMActionOwnerOnly dashboardVMActionScope = iota
	dashboardVMActionLifecycle
)

func authorizeDashboardVMAction(
	req *http.Request,
	w http.ResponseWriter,
	sessionManager *session.Manager,
	dashboardAction string,
	verb string,
	scope dashboardVMActionScope,
	auditAction string,
	auditOperation string,
) (string, *identity.User, bool) {
	user, ok := sessionManager.UserFromContext(req.Context())
	if !ok {
		dashboard.WriteJSON(w, http.StatusUnauthorized, dashboard.ActionResponse{
			OK:    false,
			Error: "Login required.",
		})
		return "", nil, false
	}

	nameParserUser := user.Name
	if user.IsAdmin && scope == dashboardVMActionLifecycle {
		// An administrator submits the inventory's exact full domain name. Do not
		// interpret it as being in the administrator's own namespace: directory
		// usernames may contain vmname.Separator, so a different owner's name can
		// legitimately begin with the administrator's apparent prefix.
		nameParserUser = ""
	}
	name, err := parseDashboardVMName(w, req, nameParserUser)
	if handleDashboardFormError(w, dashboardAction, err) {
		auditFailedVMAction(req, user, auditAction, name, auditOperation)
		return "", nil, false
	}

	if user.IsAdmin && scope == dashboardVMActionLifecycle {
		if !authorizeAdminVMActionTarget(req, w, user, name, verb, auditAction, auditOperation) {
			return "", nil, false
		}
		return name, user, true
	}

	owned, err := virt.UserOwnsVM(name, user.Name)
	if err != nil {
		auditFailedVMAction(req, user, auditAction, name, auditOperation)
		writeDashboardVMActionOwnershipError(w, name, user.Name, verb, err)
		return "", nil, false
	}

	if !owned {
		auditFailedVMAction(req, user, auditAction, name, auditOperation)
		writeDashboardVMActionOwnershipError(w, name, user.Name, verb, nil)
		return "", nil, false
	}

	return name, user, true
}

func authorizeAdminVMActionTarget(
	req *http.Request,
	w http.ResponseWriter,
	user *identity.User,
	name string,
	verb string,
	auditAction string,
	auditOperation string,
) bool {
	exists, err := virt.PersistentVMExists(name)
	if err != nil {
		auditFailedVMAction(req, user, auditAction, name, auditOperation)
		log.Printf("verify administrator %q may %s vm %q failed: %v", user.Name, verb, name, err)
		dashboard.WriteJSON(w, http.StatusInternalServerError, dashboard.ActionResponse{
			OK:    false,
			Error: "Unable to verify VM.",
		})
		return false
	}
	if !exists {
		auditFailedVMAction(req, user, auditAction, name, auditOperation)
		log.Printf("administrator %q attempted to %s missing persistent vm %q", user.Name, verb, name)
		dashboard.WriteJSON(w, http.StatusNotFound, dashboard.ActionResponse{
			OK:    false,
			Error: "VM not found.",
		})
		return false
	}
	return true
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

// validateBaseImage confirms the user-selected base image is one of the images
// currently offered by the gateway. The authoritative path-traversal guard
// lives in virt.BootNewVM; this exists to return a friendly 400 instead of a
// generic create failure when the selection is empty or unknown.
func validateBaseImage(raw string, settings *config.Settings) (string, error) {
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
		prefix := username + vmname.Separator
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
