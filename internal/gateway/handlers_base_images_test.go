package gateway

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/define42/devbox-gateway/internal/audit"
	"github.com/define42/devbox-gateway/internal/config"
	"github.com/define42/devbox-gateway/internal/dashboard"
	"github.com/define42/devbox-gateway/internal/identity"
	"github.com/define42/devbox-gateway/internal/session"
)

func baseImageTestSettings(t *testing.T) *config.Settings {
	t.Helper()
	settings := config.NewSettings(false)
	if err := settings.OverwriteForTestString(config.DATA_ROOT_DIR, t.TempDir()); err != nil {
		t.Fatalf("overwrite DATA_ROOT_DIR: %v", err)
	}
	return settings
}

func baseImageQCOW2TestData(payload string) []byte {
	return append([]byte("QFI\xfb"), []byte(payload)...)
}

func baseImageAdminCookie(t *testing.T, manager *session.Manager) *http.Cookie {
	t.Helper()
	return issueSessionCookieForUser(
		t,
		manager,
		&identity.User{Name: "admin", IsAdmin: true},
		"192.0.2.1:12345",
		testGuestPasswordHash,
	)
}

func baseImageUploadRequest(t *testing.T, field, name string, contents []byte) *http.Request {
	t.Helper()
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormFile(field, name)
	if err != nil {
		t.Fatalf("create multipart file: %v", err)
	}
	if _, err := part.Write(contents); err != nil {
		t.Fatalf("write multipart file: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close multipart request: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/admin/base-images", &body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	setSameOriginHeader(req)
	return req
}

func decodeBaseImageAction(t *testing.T, rec *httptest.ResponseRecorder) dashboard.ActionResponse {
	t.Helper()
	var response dashboard.ActionResponse
	if err := json.NewDecoder(rec.Body).Decode(&response); err != nil {
		t.Fatalf("decode action response: %v; body=%q", err, rec.Body.String())
	}
	return response
}

func getAdminBaseImages(
	t *testing.T,
	router http.Handler,
	cookie *http.Cookie,
) adminBaseImagesResponse {
	t.Helper()
	rec := hcovGet(t, router, cookie, "/api/admin/base-images")
	if rec.Code != http.StatusOK {
		t.Fatalf("expected list 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var response adminBaseImagesResponse
	if err := json.NewDecoder(rec.Body).Decode(&response); err != nil {
		t.Fatalf("decode list response: %v", err)
	}
	return response
}

type baseImageUploadValidationCase struct {
	name      string
	field     string
	file      string
	contents  []byte
	wantCode  int
	wantError string
}

func assertBaseImageUploadRejected(
	t *testing.T,
	router http.Handler,
	cookie *http.Cookie,
	testCase baseImageUploadValidationCase,
) {
	t.Helper()
	req := baseImageUploadRequest(t, testCase.field, testCase.file, testCase.contents)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != testCase.wantCode {
		t.Fatalf("expected %d, got %d: %s", testCase.wantCode, rec.Code, rec.Body.String())
	}
	action := decodeBaseImageAction(t, rec)
	if action.OK || action.Error == "" {
		t.Fatalf("expected error action, got %+v", action)
	}
	if testCase.wantError != "" && !strings.Contains(action.Error, testCase.wantError) {
		t.Fatalf("expected error containing %q, got %q", testCase.wantError, action.Error)
	}
}

func baseImageRouteRequest(t *testing.T, method, path string) *http.Request {
	t.Helper()
	if path == "/api/admin/base-images" && method == http.MethodPost {
		return baseImageUploadRequest(t, "base_image", "new.img", baseImageQCOW2TestData("data"))
	}
	req := httptest.NewRequest(method, path, strings.NewReader("base_image=old.img"))
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		setSameOriginHeader(req)
	}
	return req
}

func TestAdminBaseImageRoutesRequireAdmin(t *testing.T) {
	settings := baseImageTestSettings(t)
	manager := session.New()
	router := NewHandler(manager, settings)
	nonAdmin := issueSessionCookie(t, manager, "alice")

	tests := []struct {
		name   string
		method string
		path   string
	}{
		{name: "list", method: http.MethodGet, path: "/api/admin/base-images"},
		{name: "upload", method: http.MethodPost, path: "/api/admin/base-images"},
		{name: "delete", method: http.MethodPost, path: "/api/admin/base-images/delete"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			unauthenticated := httptest.NewRecorder()
			router.ServeHTTP(unauthenticated, baseImageRouteRequest(t, tt.method, tt.path))
			if unauthenticated.Code != http.StatusSeeOther {
				t.Fatalf("expected unauthenticated redirect, got %d: %s", unauthenticated.Code, unauthenticated.Body.String())
			}

			forbidden := httptest.NewRecorder()
			req := baseImageRouteRequest(t, tt.method, tt.path)
			req.AddCookie(nonAdmin)
			router.ServeHTTP(forbidden, req)
			if forbidden.Code != http.StatusForbidden {
				t.Fatalf("expected non-admin 403, got %d: %s", forbidden.Code, forbidden.Body.String())
			}
		})
	}

	if _, err := os.Stat(config.BaseImageDir(settings)); !os.IsNotExist(err) {
		t.Fatalf("unauthorized requests changed the image directory: %v", err)
	}
}

func TestAdminBaseImageUploadListAndDelete(t *testing.T) {
	auditOutput := captureStructuredLogs(t)
	settings := baseImageTestSettings(t)
	dir := config.BaseImageDir(settings)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("create image dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "z.raw"), baseImageQCOW2TestData("existing"), 0o644); err != nil {
		t.Fatalf("seed image: %v", err)
	}

	manager := session.New()
	router := NewHandler(manager, settings)
	cookie := baseImageAdminCookie(t, manager)
	uploaded := baseImageQCOW2TestData("uploaded bytes")
	upload := baseImageUploadRequest(t, "base_image", "a.qcow2", uploaded)
	upload.AddCookie(cookie)
	uploadRec := httptest.NewRecorder()
	router.ServeHTTP(uploadRec, upload)
	if uploadRec.Code != http.StatusCreated {
		t.Fatalf("expected upload 201, got %d: %s", uploadRec.Code, uploadRec.Body.String())
	}
	if action := decodeBaseImageAction(t, uploadRec); !action.OK {
		t.Fatalf("expected successful action, got %+v", action)
	}
	stored, err := os.ReadFile(filepath.Join(dir, "a.qcow2"))
	if err != nil {
		t.Fatalf("read uploaded image: %v", err)
	}
	if !bytes.Equal(stored, uploaded) {
		t.Fatalf("unexpected image bytes %q", stored)
	}

	list := getAdminBaseImages(t, router, cookie)
	if strings.Join(list.BaseImages, ",") != "a.qcow2,z.raw" {
		t.Fatalf("expected sorted images, got %v", list.BaseImages)
	}
	if list.MaxUploadBytes != maxBaseImageUploadBytes(settings) {
		t.Fatalf("expected upload limit %d, got %d", maxBaseImageUploadBytes(settings), list.MaxUploadBytes)
	}
	if list.AvailableStorageBytes <= 0 {
		t.Fatalf("expected positive available storage, got %d", list.AvailableStorageBytes)
	}

	deleteRec := hcovPostForm(t, router, cookie, "/api/admin/base-images/delete", url.Values{
		"base_image": {"a.qcow2"},
	})
	if deleteRec.Code != http.StatusOK {
		t.Fatalf("expected delete 200, got %d: %s", deleteRec.Code, deleteRec.Body.String())
	}
	if action := decodeBaseImageAction(t, deleteRec); !action.OK {
		t.Fatalf("expected successful action, got %+v", action)
	}
	if _, err := os.Stat(filepath.Join(dir, "a.qcow2")); !os.IsNotExist(err) {
		t.Fatalf("expected image deletion, got %v", err)
	}

	assertAdminBaseImageAuditRecords(t, auditOutput)
}

func assertAdminBaseImageAuditRecords(t *testing.T, auditOutput *synchronizedLogBuffer) {
	t.Helper()

	records := structuredAuditRecords(t, auditOutput)
	wantActions := []string{audit.ActionAdminBaseImageUpload, audit.ActionAdminBaseImageDelete}
	if len(records) != len(wantActions) {
		t.Fatalf("got %d base-image audit records, want %d: %#v", len(records), len(wantActions), records)
	}
	for i, wantAction := range wantActions {
		record := records[i]
		if record["action"] != wantAction || record["user"] != "admin" {
			t.Errorf("base-image audit record %d = %#v, want action=%q user=admin", i, record, wantAction)
		}
		if record["resource_type"] != "base_image" || record["resource"] != "a.qcow2" || record["administrator"] != true {
			t.Errorf("base-image audit resource context is incomplete: %#v", record)
		}
	}
}

func TestAdminBaseImageUploadValidation(t *testing.T) {
	settings := baseImageTestSettings(t)
	dir := config.BaseImageDir(settings)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("create image dir: %v", err)
	}
	originalData := baseImageQCOW2TestData("original")
	if err := os.WriteFile(filepath.Join(dir, "existing.img"), originalData, 0o644); err != nil {
		t.Fatalf("seed image: %v", err)
	}
	manager := session.New()
	router := NewHandler(manager, settings)
	cookie := baseImageAdminCookie(t, manager)

	tests := []baseImageUploadValidationCase{
		{name: "wrong field", field: "file", file: "new.img", contents: baseImageQCOW2TestData("data"), wantCode: http.StatusBadRequest},
		{name: "path traversal", field: "base_image", file: "../escape.img", contents: baseImageQCOW2TestData("data"), wantCode: http.StatusBadRequest},
		{name: "unsupported extension", field: "base_image", file: "new.iso", contents: baseImageQCOW2TestData("data"), wantCode: http.StatusBadRequest},
		{name: "empty", field: "base_image", file: "empty.raw", contents: nil, wantCode: http.StatusBadRequest},
		{name: "invalid QCOW2 header", field: "base_image", file: "invalid.img", contents: []byte("not qcow2"), wantCode: http.StatusBadRequest, wantError: "QCOW2 header"},
		{name: "duplicate", field: "base_image", file: "existing.img", contents: baseImageQCOW2TestData("replacement"), wantCode: http.StatusConflict},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertBaseImageUploadRejected(t, router, cookie, tt)
		})
	}

	original, err := os.ReadFile(filepath.Join(dir, "existing.img"))
	if err != nil {
		t.Fatalf("read original: %v", err)
	}
	if !bytes.Equal(original, originalData) {
		t.Fatalf("duplicate upload replaced original: %q", original)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read image dir: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != "existing.img" {
		t.Fatalf("failed uploads left artifacts: %v", entries)
	}
}

func TestAdminBaseImageMalformedUploadAndDeleteErrors(t *testing.T) {
	settings := baseImageTestSettings(t)
	manager := session.New()
	router := NewHandler(manager, settings)
	cookie := baseImageAdminCookie(t, manager)

	malformed := httptest.NewRequest(http.MethodPost, "/api/admin/base-images", strings.NewReader("not multipart"))
	malformed.Header.Set("Content-Type", "multipart/form-data")
	setSameOriginHeader(malformed)
	malformed.AddCookie(cookie)
	malformedRec := httptest.NewRecorder()
	router.ServeHTTP(malformedRec, malformed)
	if malformedRec.Code != http.StatusBadRequest {
		t.Fatalf("expected malformed upload 400, got %d: %s", malformedRec.Code, malformedRec.Body.String())
	}

	for _, tt := range []struct {
		name     string
		image    string
		wantCode int
	}{
		{name: "missing name", image: "", wantCode: http.StatusBadRequest},
		{name: "path traversal", image: "../escape.img", wantCode: http.StatusBadRequest},
		{name: "not found", image: "missing.img", wantCode: http.StatusNotFound},
	} {
		t.Run(tt.name, func(t *testing.T) {
			rec := hcovPostForm(t, router, cookie, "/api/admin/base-images/delete", url.Values{
				"base_image": {tt.image},
			})
			if rec.Code != tt.wantCode {
				t.Fatalf("expected %d, got %d: %s", tt.wantCode, rec.Code, rec.Body.String())
			}
		})
	}
}

func TestAdminBaseImageMutationsRequireSameOrigin(t *testing.T) {
	settings := baseImageTestSettings(t)
	dir := config.BaseImageDir(settings)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("create image dir: %v", err)
	}
	keepData := baseImageQCOW2TestData("keep")
	if err := os.WriteFile(filepath.Join(dir, "existing.img"), keepData, 0o644); err != nil {
		t.Fatalf("seed image: %v", err)
	}
	manager := session.New()
	router := NewHandler(manager, settings)
	cookie := baseImageAdminCookie(t, manager)

	upload := baseImageUploadRequest(t, "base_image", "new.img", baseImageQCOW2TestData("data"))
	upload.Header.Set("Origin", "http://evil.example.com")
	upload.AddCookie(cookie)
	uploadRec := httptest.NewRecorder()
	router.ServeHTTP(uploadRec, upload)
	if uploadRec.Code != http.StatusForbidden {
		t.Fatalf("expected cross-origin upload 403, got %d: %s", uploadRec.Code, uploadRec.Body.String())
	}

	deleteReq := httptest.NewRequest(http.MethodPost, "/api/admin/base-images/delete", strings.NewReader("base_image=existing.img"))
	deleteReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	deleteReq.AddCookie(cookie)
	deleteRec := httptest.NewRecorder()
	router.ServeHTTP(deleteRec, deleteReq)
	if deleteRec.Code != http.StatusForbidden {
		t.Fatalf("expected origin-less delete 403, got %d: %s", deleteRec.Code, deleteRec.Body.String())
	}

	if _, err := os.Stat(filepath.Join(dir, "new.img")); !os.IsNotExist(err) {
		t.Fatalf("cross-origin upload changed filesystem: %v", err)
	}
	if got, err := os.ReadFile(filepath.Join(dir, "existing.img")); err != nil || !bytes.Equal(got, keepData) {
		t.Fatalf("cross-origin delete changed image: %q, %v", got, err)
	}
}

func TestAdminBaseImageFilesystemErrorsAreGeneric(t *testing.T) {
	settings := baseImageTestSettings(t)
	broken := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(broken, []byte("x"), 0o644); err != nil {
		t.Fatalf("write broken base path: %v", err)
	}
	if err := settings.OverwriteForTestString(config.BASE_IMAGE_DIR, broken); err != nil {
		t.Fatalf("overwrite BASE_IMAGE_DIR: %v", err)
	}
	manager := session.New()
	router := NewHandler(manager, settings)
	cookie := baseImageAdminCookie(t, manager)

	list := hcovGet(t, router, cookie, "/api/admin/base-images")
	if list.Code != http.StatusInternalServerError || !strings.Contains(list.Body.String(), "Unable to load base images") {
		t.Fatalf("unexpected list failure: %d %s", list.Code, list.Body.String())
	}

	upload := baseImageUploadRequest(t, "base_image", "new.img", []byte("data"))
	upload.AddCookie(cookie)
	uploadRec := httptest.NewRecorder()
	router.ServeHTTP(uploadRec, upload)
	if uploadRec.Code != http.StatusInternalServerError {
		t.Fatalf("expected upload 500, got %d: %s", uploadRec.Code, uploadRec.Body.String())
	}
	if action := decodeBaseImageAction(t, uploadRec); action.Error != "Base image operation failed." {
		t.Fatalf("unexpected generic upload error: %+v", action)
	}

	deleteRec := hcovPostForm(t, router, cookie, "/api/admin/base-images/delete", url.Values{
		"base_image": {"old.img"},
	})
	if deleteRec.Code != http.StatusInternalServerError {
		t.Fatalf("expected delete 500, got %d: %s", deleteRec.Code, deleteRec.Body.String())
	}
}
