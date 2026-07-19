package main

import (
	"crypto/sha256"
	"crypto/tls"
	"devboxgateway/internal/config"
	"devboxgateway/internal/dashboard"
	"devboxgateway/internal/session"
	"devboxgateway/internal/types"
	"devboxgateway/internal/virt"
	"devboxgateway/internal/vmname"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	scs "github.com/alexedwards/scs/v2"
	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humachi"
	"github.com/go-chi/chi/v5"
	"libvirt.org/go/libvirt"
)

// hcovOwnerMetadataNamespace mirrors the namespace virt uses for domain owner
// metadata so tests can mark a bare test domain as owned by a user.
const hcovOwnerMetadataNamespace = "urn:devboxgateway:domain:owner"

func hcovUniqueName(prefix string) string {
	return prefix + strconv.FormatInt(time.Now().UnixNano(), 10)
}

// hcovDefineOwnedDomain defines a minimal TCG (type='qemu') domain that is
// never expected to boot an OS and stamps it with owner metadata, so ownership
// and dashboard flows can run against a real libvirt domain without images.
func hcovDefineOwnedDomain(t *testing.T, name, owner string) {
	t.Helper()

	conn, err := libvirt.NewConnect(virt.LibvirtURI())
	if err != nil {
		t.Fatalf("connect libvirt: %v", err)
	}
	defer func() { _, _ = conn.Close() }()

	domainXML := fmt.Sprintf(
		"<domain type='qemu'><name>%s</name><memory unit='MiB'>128</memory><vcpu>1</vcpu><os><type arch='x86_64'>hvm</type></os></domain>",
		name)
	dom, err := conn.DomainDefineXML(domainXML)
	if err != nil {
		t.Fatalf("define test domain %s: %v", name, err)
	}
	defer func() { _ = dom.Free() }()
	t.Cleanup(func() { hcovCleanupDomain(name) })

	err = dom.SetMetadata(libvirt.DOMAIN_METADATA_ELEMENT, "<owner>"+owner+"</owner>",
		"devboxgateway", hcovOwnerMetadataNamespace, libvirt.DOMAIN_AFFECT_CONFIG)
	if err != nil {
		t.Fatalf("set owner metadata for %s: %v", name, err)
	}
}

func hcovCleanupDomain(name string) {
	conn, err := libvirt.NewConnect(virt.LibvirtURI())
	if err != nil {
		return
	}
	defer func() { _, _ = conn.Close() }()

	dom, err := conn.LookupDomainByName(name)
	if err != nil {
		return
	}
	defer func() { _ = dom.Free() }()

	if active, activeErr := dom.IsActive(); activeErr == nil && active {
		_ = dom.Destroy()
	}
	_ = dom.Undefine()
}

func hcovCleanupPool(name string) {
	conn, err := libvirt.NewConnect(virt.LibvirtURI())
	if err != nil {
		return
	}
	defer func() { _, _ = conn.Close() }()

	pool, err := conn.LookupStoragePoolByName(name)
	if err != nil {
		return
	}
	defer func() { _ = pool.Free() }()

	if active, activeErr := pool.IsActive(); activeErr == nil && active {
		_ = pool.Destroy()
	}
	_ = pool.Undefine()
}

// hcovDefineActivePool defines and starts a dir storage pool at path so tests
// can provoke deterministic pool-path conflicts without touching the shared
// 'default' pool.
func hcovDefineActivePool(t *testing.T, name, path string) {
	t.Helper()

	conn, err := libvirt.NewConnect(virt.LibvirtURI())
	if err != nil {
		t.Fatalf("connect libvirt: %v", err)
	}
	defer func() { _, _ = conn.Close() }()

	poolXML := fmt.Sprintf("<pool type='dir'><name>%s</name><target><path>%s</path></target></pool>", name, path)
	pool, err := conn.StoragePoolDefineXML(poolXML, 0)
	if err != nil {
		t.Fatalf("define test pool %s: %v", name, err)
	}
	defer func() { _ = pool.Free() }()
	t.Cleanup(func() { hcovCleanupPool(name) })

	if err := pool.Create(0); err != nil {
		t.Fatalf("start test pool %s: %v", name, err)
	}
}

func hcovSeedBaseImage(t *testing.T, dir string) string {
	t.Helper()

	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("create base image dir %s: %v", dir, err)
	}
	const name = "hcov-base.img"
	if err := os.WriteFile(filepath.Join(dir, name), []byte("hcov placeholder"), 0o644); err != nil {
		t.Fatalf("seed base image: %v", err)
	}
	return name
}

// hcovVirtCreateSettings builds settings pointing at an isolated data root and
// storage pool with a placeholder base image staged, so create-VM requests get
// past form validation and fail (or conflict) deterministically inside
// virt.BootNewVM without downloading anything.
func hcovVirtCreateSettings(t *testing.T, poolName string) (*config.SettingsType, string) {
	t.Helper()

	settings := config.NewSettingType(false)
	if err := settings.OverwriteForTestString(config.DATA_ROOT_DIR, newLibvirtAccessibleTempDir(t, "hcov-root-")); err != nil {
		t.Fatalf("overwrite DATA_ROOT_DIR: %v", err)
	}
	if err := settings.OverwriteForTestString(config.VIRT_STORAGE_POOL_NAME, poolName); err != nil {
		t.Fatalf("overwrite VIRT_STORAGE_POOL_NAME: %v", err)
	}
	t.Cleanup(func() { hcovCleanupPool(poolName) })
	baseImage := hcovSeedBaseImage(t, config.BaseImageDir(settings))
	return settings, baseImage
}

func hcovCreateForm(shortName, baseImage string) url.Values {
	return url.Values{
		"vm_name":             {shortName},
		"vm_vcpu":             {"2"},
		"vm_memory_mib":       {"4096"},
		"vm_password":         {"Secret1!"},
		"vm_password_confirm": {"Secret1!"},
		"vm_base_image":       {baseImage},
	}
}

func hcovPostForm(t *testing.T, handler http.Handler, cookie *http.Cookie, path string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	setSameOriginHeader(req)
	if cookie != nil {
		req.AddCookie(cookie)
	}
	handler.ServeHTTP(rec, req)
	return rec
}

func hcovGet(t *testing.T, handler http.Handler, cookie *http.Cookie, path string) *httptest.ResponseRecorder {
	t.Helper()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if cookie != nil {
		req.AddCookie(cookie)
	}
	handler.ServeHTTP(rec, req)
	return rec
}

func hcovAssertAction(t *testing.T, rec *httptest.ResponseRecorder, wantCode int, wantSubstring string) {
	t.Helper()

	if rec.Code != wantCode {
		t.Fatalf("expected status %d, got %d: %s", wantCode, rec.Code, rec.Body.String())
	}
	var resp dashboard.ActionResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode action response: %v", err)
	}
	if wantSubstring != "" && !strings.Contains(resp.Error+resp.Message, wantSubstring) {
		t.Fatalf("expected response to contain %q, got %+v", wantSubstring, resp)
	}
}

// hcovRouterWithoutSessionAuth registers the dashboard routes without the huma
// session middleware (but with the scs session loader), so the handlers' own
// "no authenticated user" branches are reachable.
func hcovRouterWithoutSessionAuth(sessionManager *session.Manager, settings *config.SettingsType) http.Handler {
	router := chi.NewRouter()
	router.Use(sessionManager.LoadAndSave)
	apiCfg := huma.DefaultConfig("HcovCoverage", "1.0.0")
	apiCfg.OpenAPIPath = ""
	apiCfg.DocsPath = ""
	apiCfg.SchemasPath = ""
	api := humachi.New(router, apiCfg)
	group := huma.NewGroup(api, "/api")
	registerDashboardDataRoute(group, sessionManager, settings)
	registerDashboardCreateRoute(group, sessionManager, settings)
	registerDashboardRDPRoute(group, sessionManager, settings)
	return router
}

// hcovDeleteFailStore delegates to a working session store but fails deletes
// and (unlike memstore) does not support iteration, forcing the session
// manager's failure branches during logout and login-session creation.
type hcovDeleteFailStore struct {
	inner scs.Store
}

func (s hcovDeleteFailStore) Find(token string) ([]byte, bool, error) {
	return s.inner.Find(token)
}

func (s hcovDeleteFailStore) Commit(token string, b []byte, expiry time.Time) error {
	return s.inner.Commit(token, b, expiry)
}

func (s hcovDeleteFailStore) Delete(string) error {
	return errors.New("hcov delete failure")
}

// hcovFailingResponseWriter fails every body write so response-write error
// logging branches can be exercised.
type hcovFailingResponseWriter struct {
	header http.Header
	status int
}

func (w *hcovFailingResponseWriter) Header() http.Header {
	if w.header == nil {
		w.header = make(http.Header)
	}
	return w.header
}

func (w *hcovFailingResponseWriter) WriteHeader(status int) { w.status = status }

func (w *hcovFailingResponseWriter) Write([]byte) (int, error) {
	return 0, errors.New("hcov write failure")
}

func TestHcovParseFormWithBodyLimitSkipsParsedForm(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("a=b"))
	req.Form = url.Values{"x": {"y"}}
	rec := httptest.NewRecorder()

	if err := parseFormWithBodyLimit(rec, req); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := req.FormValue("x"); got != "y" {
		t.Fatalf("expected pre-parsed form to be preserved, got %q", got)
	}
}

func TestHcovRequestScheme(t *testing.T) {
	fromURL := httptest.NewRequest(http.MethodGet, "https://example.com/x", nil)
	if got := requestScheme(fromURL); got != "https" {
		t.Fatalf("expected https from URL scheme, got %q", got)
	}

	fromTLS := httptest.NewRequest(http.MethodGet, "http://example.com/x", nil)
	fromTLS.URL.Scheme = ""
	fromTLS.TLS = &tls.ConnectionState{}
	if got := requestScheme(fromTLS); got != "https" {
		t.Fatalf("expected https from TLS state, got %q", got)
	}

	plain := httptest.NewRequest(http.MethodGet, "http://example.com/x", nil)
	plain.URL.Scheme = ""
	if got := requestScheme(plain); got != "http" {
		t.Fatalf("expected http fallback, got %q", got)
	}

	nilURL := httptest.NewRequest(http.MethodGet, "http://example.com/x", nil)
	nilURL.URL = nil
	if got := requestScheme(nilURL); got != "http" {
		t.Fatalf("expected http fallback for nil URL, got %q", got)
	}
}

func TestHcovServeLoginStatusWriteFailure(t *testing.T) {
	w := &hcovFailingResponseWriter{}
	serveLoginStatus(w, "hcov", http.StatusOK)

	if w.status != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, w.status)
	}
}

func hcovPostLoginForm(t *testing.T, handler http.Handler, remoteAddr, body string) *httptest.ResponseRecorder {
	t.Helper()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	setSameOriginHeader(req)
	if remoteAddr != "" {
		req.RemoteAddr = remoteAddr
	}
	handler.ServeHTTP(rec, req)
	return rec
}

func TestHcovLoginPostRejectsOversizedFormBody(t *testing.T) {
	router := getRemoteGatewayRotuer(session.NewManager(), config.NewSettingType(false))
	body := "username=" + strings.Repeat("a", maxFormBodyBytes) + "&password=x"

	rec := hcovPostLoginForm(t, router, "", body)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Invalid form submission.") {
		t.Fatalf("expected invalid form message, got %q", rec.Body.String())
	}
}

func TestHcovLoginPostMissingCredentials(t *testing.T) {
	router := getRemoteGatewayRotuer(session.NewManager(), config.NewSettingType(false))

	rec := hcovPostLoginForm(t, router, "", url.Values{"username": {""}, "password": {""}}.Encode())
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Missing credentials.") {
		t.Fatalf("expected missing credentials message, got %q", rec.Body.String())
	}
}

func TestHcovLoginPostRejectsInvalidUsername(t *testing.T) {
	router := getRemoteGatewayRotuer(session.NewManager(), config.NewSettingType(false))

	rec := hcovPostLoginForm(t, router, "", url.Values{"username": {"bad name"}, "password": {"pw"}}.Encode())
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Invalid credentials.") {
		t.Fatalf("expected invalid credentials message, got %q", rec.Body.String())
	}
}

// TestHcovLoginPostUsernameLockRejectedFromNewIP locks the username bucket via
// a failure from one IP and verifies a fresh IP is rejected by the post-
// validation rate-limit check keyed on the username.
func TestHcovLoginPostUsernameLockRejectedFromNewIP(t *testing.T) {
	t.Setenv(config.LDAP_URL, "")
	t.Setenv(config.LOGIN_RATE_LIMIT_MAX_ATTEMPTS, "1")
	t.Setenv(config.LOGIN_RATE_LIMIT_WINDOW, "1m")
	t.Setenv(config.LOGIN_RATE_LIMIT_LOCKOUT, "1h")
	router := getRemoteGatewayRotuer(session.NewManager(), config.NewSettingType(false))
	form := url.Values{"username": {"hcovlockuser"}, "password": {"wrong"}}.Encode()

	rec := hcovPostLoginForm(t, router, "198.51.100.71:4000", form)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("expected first failure to lock immediately with 429, got %d", rec.Code)
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Fatal("expected Retry-After header on lockout")
	}

	rec = hcovPostLoginForm(t, router, "198.51.100.72:4000", form)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("expected username lock to reject a new IP with 429, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), loginLocked) {
		t.Fatalf("expected lockout message, got %q", rec.Body.String())
	}

	// The locked client IP is rejected before credentials are even validated.
	rec = hcovPostLoginForm(t, router, "198.51.100.71:4001", form)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("expected locked IP to be rejected up front with 429, got %d", rec.Code)
	}
}

func TestHcovLoginPostLocalUserSuccess(t *testing.T) {
	settings := config.NewSettingType(false)
	digest := sha256.Sum256([]byte("hcovlocal:Secret1!"))
	if err := settings.OverwriteForTestString(config.LOCAL_USER_SHA256, hex.EncodeToString(digest[:])); err != nil {
		t.Fatalf("overwrite LOCAL_USER_SHA256: %v", err)
	}
	router := getRemoteGatewayRotuer(session.NewManager(), settings)

	rec := hcovPostLoginForm(t, router, "", url.Values{"username": {"hcovlocal"}, "password": {"Secret1!"}}.Encode())
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("expected 303, got %d: %s", rec.Code, rec.Body.String())
	}
	if loc := rec.Header().Get("Location"); loc != "/api/dashboard" {
		t.Fatalf("expected redirect to /api/dashboard, got %q", loc)
	}
	if !responseSetsSessionCookie(rec.Result()) {
		t.Fatal("expected successful login to set a session cookie")
	}
}

func TestHcovCompleteLoginFailsWhenSessionStoreBroken(t *testing.T) {
	sessionManager := session.NewManager()
	sessionManager.Store = hcovDeleteFailStore{inner: sessionManager.Store}
	cookie := issueSessionCookie(t, sessionManager, "hcovbroken")

	user, err := types.NewUser("hcovbroken")
	if err != nil {
		t.Fatalf("new user: %v", err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/login", nil)
	req.AddCookie(cookie)
	handler := sessionManager.LoadAndSave(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		completeLogin(sessionManager, w, r, user)
	}))
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 login page, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Login failed.") {
		t.Fatalf("expected login failure message, got %q", rec.Body.String())
	}
}

func TestHcovLogoutLogsStoreFailuresAndClosesConnections(t *testing.T) {
	sessionManager := session.NewManager()
	sessionManager.Store = hcovDeleteFailStore{inner: sessionManager.Store}
	router := getRemoteGatewayRotuer(sessionManager, config.NewSettingType(false))
	cookie := issueSessionCookie(t, sessionManager, "hcovlogout")
	closed := 0
	sessionManager.RegisterUserConnection("hcovlogout", func() { closed++ })

	crossOrigin := httptest.NewRecorder()
	forged := httptest.NewRequest(http.MethodPost, "/logout", nil)
	forged.AddCookie(cookie)
	router.ServeHTTP(crossOrigin, forged)
	if crossOrigin.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for logout without origin, got %d", crossOrigin.Code)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/logout", nil)
	setSameOriginHeader(req)
	req.AddCookie(cookie)
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("expected 303, got %d", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/login" {
		t.Fatalf("expected redirect to /login, got %q", loc)
	}
	if closed != 1 {
		t.Fatalf("expected logout to close the live connection once, got %d", closed)
	}
}

func TestHcovDebugConnectionLoggerRequests(t *testing.T) {
	settings := config.NewSettingType(false)
	if err := settings.OverwriteForTestBool(config.DEBUG_CONNECTIONS, true); err != nil {
		t.Fatalf("overwrite DEBUG_CONNECTIONS: %v", err)
	}
	router := getRemoteGatewayRotuer(session.NewManager(), settings)

	rec := hcovGet(t, router, nil, "/api/health")
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for plain request, got %d", rec.Code)
	}

	rec = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/health", nil)
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("X-Forwarded-For", "203.0.113.7")
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for websocket-flagged request, got %d", rec.Code)
	}

	// A client that drops the connection mid-response must only be logged, so
	// the health handler's write-error branch is exercised with a failing writer.
	failing := &hcovFailingResponseWriter{}
	router.ServeHTTP(failing, httptest.NewRequest(http.MethodGet, "/api/health", nil))
	if failing.status != http.StatusOK {
		t.Fatalf("expected health handler to set 200 before the write failure, got %d", failing.status)
	}
}

func TestHcovDashboardDataToleratesBaseImageListFailure(t *testing.T) {
	sessionManager := session.NewManager()
	settings := config.NewSettingType(false)
	notADir := filepath.Join(t.TempDir(), "hcov-not-a-dir")
	if err := os.WriteFile(notADir, []byte("x"), 0o644); err != nil {
		t.Fatalf("write blocker file: %v", err)
	}
	if err := settings.OverwriteForTestString(config.BASE_IMAGE_DIR, notADir); err != nil {
		t.Fatalf("overwrite BASE_IMAGE_DIR: %v", err)
	}
	router := getRemoteGatewayRotuer(sessionManager, settings)
	user := hcovUniqueName("hcovdata")
	cookie := issueSessionCookie(t, sessionManager, user)

	rec := hcovGet(t, router, cookie, "/api/dashboard/data")
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp dashboard.DataResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode data response: %v", err)
	}
	if resp.Error != "" || resp.Username != user || resp.Filename != rdpFilename {
		t.Fatalf("unexpected response: %+v", resp)
	}
	if len(resp.BaseImages) != 0 {
		t.Fatalf("expected no base images after listing failure, got %v", resp.BaseImages)
	}
}

func TestHcovDashboardDataListsSeededBaseImages(t *testing.T) {
	sessionManager := session.NewManager()
	settings := config.NewSettingType(false)
	dir := t.TempDir()
	if err := settings.OverwriteForTestString(config.BASE_IMAGE_DIR, dir); err != nil {
		t.Fatalf("overwrite BASE_IMAGE_DIR: %v", err)
	}
	baseImage := hcovSeedBaseImage(t, dir)
	router := getRemoteGatewayRotuer(sessionManager, settings)
	user := hcovUniqueName("hcovdatb")
	cookie := issueSessionCookie(t, sessionManager, user)

	rec := hcovGet(t, router, cookie, "/api/dashboard/data")
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp dashboard.DataResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode data response: %v", err)
	}
	if len(resp.BaseImages) != 1 || resp.BaseImages[0] != baseImage {
		t.Fatalf("expected base images [%s], got %v", baseImage, resp.BaseImages)
	}
}

func TestHcovDashboardRoutesRequireLoginWithoutSessionMiddleware(t *testing.T) {
	sessionManager := session.NewManager()
	router := hcovRouterWithoutSessionAuth(sessionManager, config.NewSettingType(false))

	rec := hcovGet(t, router, nil, "/api/dashboard/data")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 from data route, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "unauthorized") {
		t.Fatalf("expected unauthorized body, got %q", rec.Body.String())
	}

	createForm := url.Values{"vm_name": {"hcovvm"}, "vm_vcpu": {"2"}, "vm_memory_mib": {"4096"}}
	rec = hcovPostForm(t, router, nil, "/api/dashboard", createForm)
	hcovAssertAction(t, rec, http.StatusUnauthorized, "Login required.")

	rec = hcovPostForm(t, router, nil, "/api/dashboard/rdp", url.Values{"vm_name": {"hcovvm"}})
	hcovAssertAction(t, rec, http.StatusUnauthorized, "Login required.")
}

func TestHcovDashboardRDPRejectsBadAndUnownedNames(t *testing.T) {
	sessionManager := session.NewManager()
	router := getRemoteGatewayRotuer(sessionManager, config.NewSettingType(false))
	cookie := issueSessionCookie(t, sessionManager, hcovUniqueName("hcovnoown"))

	rec := hcovPostForm(t, router, cookie, "/api/dashboard/rdp", url.Values{"vm_name": {""}})
	hcovAssertAction(t, rec, http.StatusBadRequest, "vm name is required")

	rec = hcovPostForm(t, router, cookie, "/api/dashboard/rdp", url.Values{"vm_name": {"hcovghostvm"}})
	hcovAssertAction(t, rec, http.StatusForbidden, "You do not have permission to connect to this VM.")
}

func hcovAssertRDPDownload(t *testing.T, rec *httptest.ResponseRecorder, user string) {
	t.Helper()

	if ct := rec.Header().Get("Content-Type"); ct != "application/x-rdp" {
		t.Fatalf("expected RDP content type, got %q", ct)
	}
	if cd := rec.Header().Get("Content-Disposition"); !strings.Contains(cd, ".rdp") {
		t.Fatalf("expected .rdp attachment, got %q", cd)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "full address:s:") {
		t.Fatalf("expected connection address in RDP body %q", body)
	}
	if !strings.Contains(body, "username:s:"+user) {
		t.Fatalf("expected username %q in RDP body %q", user, body)
	}
}

// TestHcovDashboardRDPDownloadsFileForOwnedVM drives the full authorized RDP
// download: an owned (TCG, never-booted) domain, the ownership check, the RDP
// connect grant, and the .rdp attachment. The dashboard VM cache refreshes
// every couple of seconds, so the request is polled until the cache lists the
// domain.
func TestHcovDashboardRDPDownloadsFileForOwnedVM(t *testing.T) {
	virt.GetInstance()

	user := hcovUniqueName("hcovrdp")
	domainName := user + vmname.Separator + "desk"
	hcovDefineOwnedDomain(t, domainName, user)

	sessionManager := session.NewManager()
	router := getRemoteGatewayRotuer(sessionManager, config.NewSettingType(false))
	cookie := issueSessionCookie(t, sessionManager, user)
	form := url.Values{"vm_name": {domainName}}

	deadline := time.Now().Add(20 * time.Second)
	for {
		rec := hcovPostForm(t, router, cookie, "/api/dashboard/rdp", form)
		if rec.Code == http.StatusOK {
			hcovAssertRDPDownload(t, rec, user)
			return
		}
		if rec.Code != http.StatusNotFound {
			t.Fatalf("unexpected RDP response %d: %s", rec.Code, rec.Body.String())
		}
		if time.Now().After(deadline) {
			t.Fatalf("VM %s never appeared in the dashboard cache", domainName)
		}
		time.Sleep(250 * time.Millisecond)
	}
}

func TestHcovDashboardResourcesValidationAndUpdate(t *testing.T) {
	user := hcovUniqueName("hcovres")
	domainName := user + vmname.Separator + "box"
	hcovDefineOwnedDomain(t, domainName, user)

	sessionManager := session.NewManager()
	router := getRemoteGatewayRotuer(sessionManager, config.NewSettingType(false))
	cookie := issueSessionCookie(t, sessionManager, user)

	rec := hcovPostForm(t, router, cookie, "/api/dashboard/resources", url.Values{"vm_name": {""}})
	hcovAssertAction(t, rec, http.StatusBadRequest, "vm name is required")

	rec = hcovPostForm(t, router, cookie, "/api/dashboard/resources",
		url.Values{"vm_name": {domainName}, "vm_vcpu": {"abc"}, "vm_memory_mib": {"4096"}})
	hcovAssertAction(t, rec, http.StatusBadRequest, "cpu selection is invalid")

	rec = hcovPostForm(t, router, cookie, "/api/dashboard/resources",
		url.Values{"vm_name": {domainName}, "vm_vcpu": {"2"}, "vm_memory_mib": {"abc"}})
	hcovAssertAction(t, rec, http.StatusBadRequest, "memory selection is invalid")

	rec = hcovPostForm(t, router, cookie, "/api/dashboard/resources",
		url.Values{"vm_name": {domainName}, "vm_vcpu": {"2"}, "vm_memory_mib": {"4096"}})
	hcovAssertAction(t, rec, http.StatusOK, "VM resources updated.")
}

// TestHcovDashboardStartThenResourcesRejectedWhileRunning starts the owned TCG
// domain through the dashboard action route (it idles in firmware with no
// disk), verifies resource updates are refused while it runs, and force-stops
// it through the shutdown route.
func TestHcovDashboardStartThenResourcesRejectedWhileRunning(t *testing.T) {
	user := hcovUniqueName("hcovrun")
	domainName := user + vmname.Separator + "run"
	hcovDefineOwnedDomain(t, domainName, user)

	sessionManager := session.NewManager()
	router := getRemoteGatewayRotuer(sessionManager, config.NewSettingType(false))
	cookie := issueSessionCookie(t, sessionManager, user)
	nameForm := url.Values{"vm_name": {domainName}}

	rec := hcovPostForm(t, router, cookie, "/api/dashboard/start", url.Values{"vm_name": {""}})
	hcovAssertAction(t, rec, http.StatusBadRequest, "vm name is required")

	rec = hcovPostForm(t, router, cookie, "/api/dashboard/start", nameForm)
	hcovAssertAction(t, rec, http.StatusOK, "VM start requested.")

	rec = hcovPostForm(t, router, cookie, "/api/dashboard/resources",
		url.Values{"vm_name": {domainName}, "vm_vcpu": {"2"}, "vm_memory_mib": {"4096"}})
	hcovAssertAction(t, rec, http.StatusBadRequest, "stopped")

	rec = hcovPostForm(t, router, cookie, "/api/dashboard/shutdown", nameForm)
	hcovAssertAction(t, rec, http.StatusOK, "VM shutdown requested.")
}

func TestHcovDashboardRemoveFailsWithoutStoragePool(t *testing.T) {
	user := hcovUniqueName("hcovrm")
	domainName := user + vmname.Separator + "gone"
	hcovDefineOwnedDomain(t, domainName, user)

	settings := config.NewSettingType(false)
	if err := settings.OverwriteForTestString(config.VIRT_STORAGE_POOL_NAME, hcovUniqueName("hcov-nopool")); err != nil {
		t.Fatalf("overwrite VIRT_STORAGE_POOL_NAME: %v", err)
	}
	sessionManager := session.NewManager()
	router := getRemoteGatewayRotuer(sessionManager, settings)
	cookie := issueSessionCookie(t, sessionManager, user)

	rec := hcovPostForm(t, router, cookie, "/api/dashboard/remove", url.Values{"vm_name": {domainName}})
	hcovAssertAction(t, rec, http.StatusInternalServerError, "Failed to remove VM.")
}

func TestHcovDashboardCreateConflictsWhenVMExists(t *testing.T) {
	user := hcovUniqueName("hcovdup")
	hcovDefineOwnedDomain(t, user+vmname.Separator+"dup", user)
	settings, baseImage := hcovVirtCreateSettings(t, hcovUniqueName("hcov-pool-dup"))

	sessionManager := session.NewManager()
	router := getRemoteGatewayRotuer(sessionManager, settings)
	cookie := issueSessionCookie(t, sessionManager, user)

	rec := hcovPostForm(t, router, cookie, "/api/dashboard", hcovCreateForm("dup", baseImage))
	hcovAssertAction(t, rec, http.StatusConflict, "already exists")
}

func TestHcovDashboardCreateEnforcesPerUserLimit(t *testing.T) {
	user := hcovUniqueName("hcovlim")
	hcovDefineOwnedDomain(t, user+vmname.Separator+"one", user)
	settings, baseImage := hcovVirtCreateSettings(t, hcovUniqueName("hcov-pool-lim"))
	if err := settings.OverwriteForTestInt(config.MAX_VDI_PER_USER, 1); err != nil {
		t.Fatalf("overwrite MAX_VDI_PER_USER: %v", err)
	}

	sessionManager := session.NewManager()
	router := getRemoteGatewayRotuer(sessionManager, settings)
	cookie := issueSessionCookie(t, sessionManager, user)

	rec := hcovPostForm(t, router, cookie, "/api/dashboard", hcovCreateForm("two", baseImage))
	hcovAssertAction(t, rec, http.StatusConflict, "VM limit reached")
}

// TestHcovDashboardCreateFailsOnStoragePoolPathConflict provokes the generic
// create-failure branch: the configured pool already exists and is active at a
// different path, which BootNewVM refuses deterministically.
func TestHcovDashboardCreateFailsOnStoragePoolPathConflict(t *testing.T) {
	poolName := hcovUniqueName("hcovconflict")
	hcovDefineActivePool(t, poolName, newLibvirtAccessibleTempDir(t, "hcov-pool-a-"))
	settings, baseImage := hcovVirtCreateSettings(t, poolName)

	sessionManager := session.NewManager()
	router := getRemoteGatewayRotuer(sessionManager, settings)
	cookie := issueSessionCookie(t, sessionManager, hcovUniqueName("hcovpoolc"))

	rec := hcovPostForm(t, router, cookie, "/api/dashboard", hcovCreateForm("clash", baseImage))
	hcovAssertAction(t, rec, http.StatusInternalServerError, "Failed to create VM.")
}

func TestHcovDashboardCreateFormValidationErrors(t *testing.T) {
	settings := config.NewSettingType(false)
	dir := t.TempDir()
	if err := settings.OverwriteForTestString(config.BASE_IMAGE_DIR, dir); err != nil {
		t.Fatalf("overwrite BASE_IMAGE_DIR: %v", err)
	}
	baseImage := hcovSeedBaseImage(t, dir)
	sessionManager := session.NewManager()
	router := getRemoteGatewayRotuer(sessionManager, settings)
	cookie := issueSessionCookie(t, sessionManager, hcovUniqueName("hcovform"))

	tests := []struct {
		name  string
		field string
		value string
		want  string
	}{
		{"invalid vm name", "vm_name", "BAD NAME", "vm name"},
		{"unsupported vcpu", "vm_vcpu", "3", "cpu selection"},
		{"unsupported memory", "vm_memory_mib", "123", "memory selection"},
		{"invalid guest username", "vm_username", "Bad User", "username must"},
		{"password mismatch", "vm_password_confirm", "Other1!", "passwords do not match"},
		{"missing base image", "vm_base_image", "", "base image is required"},
		{"unknown base image", "vm_base_image", "../hcov-base.img", "not available"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			form := hcovCreateForm("formvm", baseImage)
			form.Set(tc.field, tc.value)
			rec := hcovPostForm(t, router, cookie, "/api/dashboard", form)
			hcovAssertAction(t, rec, http.StatusBadRequest, tc.want)
		})
	}
}

func TestHcovValidateBaseImage(t *testing.T) {
	settings := config.NewSettingType(false)
	dir := t.TempDir()
	if err := settings.OverwriteForTestString(config.BASE_IMAGE_DIR, dir); err != nil {
		t.Fatalf("overwrite BASE_IMAGE_DIR: %v", err)
	}
	baseImage := hcovSeedBaseImage(t, dir)

	if _, err := validateBaseImage("", settings); err == nil || !strings.Contains(err.Error(), "required") {
		t.Fatalf("expected required error for empty selection, got %v", err)
	}
	if got, err := validateBaseImage(" "+baseImage+" ", settings); err != nil || got != baseImage {
		t.Fatalf("expected %q to validate, got (%q, %v)", baseImage, got, err)
	}
	if _, err := validateBaseImage("hcov-missing.img", settings); err == nil || !strings.Contains(err.Error(), "not available") {
		t.Fatalf("expected not-available error, got %v", err)
	}

	broken := config.NewSettingType(false)
	notADir := filepath.Join(t.TempDir(), "hcov-file")
	if err := os.WriteFile(notADir, []byte("x"), 0o644); err != nil {
		t.Fatalf("write blocker file: %v", err)
	}
	if err := broken.OverwriteForTestString(config.BASE_IMAGE_DIR, notADir); err != nil {
		t.Fatalf("overwrite BASE_IMAGE_DIR: %v", err)
	}
	if _, err := validateBaseImage(baseImage, broken); err == nil || !strings.Contains(err.Error(), "unable to list") {
		t.Fatalf("expected listing error, got %v", err)
	}
}
