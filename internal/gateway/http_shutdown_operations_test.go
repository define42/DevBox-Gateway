package gateway

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/define42/devbox-gateway/internal/config"
	"github.com/define42/devbox-gateway/internal/identity"
	"github.com/define42/devbox-gateway/internal/session"
	"github.com/define42/devbox-gateway/internal/vmname"
)

// drainPausedResponse pauses provisioning at its first real disk-copy progress
// write so the test can expire shutdown's grace period while a volume exists.
type drainPausedResponse struct {
	http.ResponseWriter

	ctx     context.Context
	started chan<- context.Context
	once    sync.Once
}

func (w *drainPausedResponse) Write(p []byte) (int, error) {
	if !strings.HasPrefix(w.Header().Get("Content-Type"), "application/x-ndjson") {
		return w.ResponseWriter.Write(p)
	}
	w.once.Do(func() {
		w.started <- w.ctx
		<-w.ctx.Done()
	})
	return w.ResponseWriter.Write(p)
}

func (w *drainPausedResponse) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func TestHTTPShutdownCancelsVMCreationAndWaitsForRollback(t *testing.T) {
	settings, baseImage := hcovVirtCreateSettings(t, hcovUniqueName("drain-create-pool"))
	if err := settings.OverwriteForTestInt(config.VM_DISK_SIZE_GB, 1); err != nil {
		t.Fatal(err)
	}
	manager := session.New()
	cookie := issueSessionCookieFromIP(t, manager, "alice", "127.0.0.1:12345")
	started := make(chan context.Context, 1)
	completed := make(chan struct{})
	router := NewHandler(manager, settings)
	handler := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		defer close(completed)
		router.ServeHTTP(&drainPausedResponse{ResponseWriter: w, ctx: req.Context(), started: started}, req)
	})
	runtime, client, address := startHTTPDrainRuntime(t, handler, completedBeforeAuditClose(t, completed))
	client.Timeout = time.Minute
	shortName := hcovUniqueName("drain-create")
	name := "alice" + vmname.Separator + shortName
	t.Cleanup(func() { hcovCleanupDomain(name) })
	request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, address+"/api/dashboard",
		strings.NewReader(hcovCreateForm(shortName, baseImage).Encode()))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Accept", "application/x-ndjson")
	request.Header.Set("Origin", address)
	request.AddCookie(cookie)
	responseDone := startOperationDrainRequest(client, request)
	select {
	case <-started:
	case <-completed:
		t.Fatal("VM creation returned before disk-copy progress started")
	case <-time.After(30 * time.Second):
		t.Fatal("VM creation did not reach disk copying")
	}
	if _, err := os.Stat(filepath.Join(config.ImageDir(settings), name)); err != nil {
		t.Fatalf("disk-copy progress started without a VM volume: %v", err)
	}
	expireHTTPDrain(t, runtime)
	// Closing the client transport can complete responseDone before the server
	// handler has returned from rollback, so use the handler as the cleanup
	// barrier before inspecting libvirt state.
	select {
	case <-completed:
	case <-time.After(30 * time.Second):
		t.Fatal("VM creation did not finish rollback after cancellation")
	}
	<-responseDone
	if exists, _ := hcovDomainState(t, name); exists {
		t.Fatal("cancelled provisioning left a domain behind")
	}
	for _, volume := range []string{name, name + "_seed.iso"} {
		if _, err := os.Stat(filepath.Join(config.ImageDir(settings), volume)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("cancelled provisioning left volume %q: %v", volume, err)
		}
	}
	if err := runtime.Close(); err != nil {
		t.Fatalf("close runtime after cancelled creation: %v", err)
	}
}

func startOperationDrainRequest(client *http.Client, request *http.Request) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		response, err := client.Do(request)
		if err == nil {
			_, _ = io.Copy(io.Discard, response.Body)
			_ = response.Body.Close()
		}
	}()
	return done
}

func TestHTTPShutdownCancelsBaseImageUploadAndRemovesTemporaryFile(t *testing.T) {
	settings := baseImageTestSettings(t)
	manager := session.New()
	cookie := issueSessionCookieForUser(t, manager, &identity.User{Name: "admin", IsAdmin: true},
		"127.0.0.1:12345", testGuestPasswordHash)
	completed := make(chan struct{})
	router := NewHandler(manager, settings)
	handler := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		defer close(completed)
		router.ServeHTTP(w, req)
	})
	runtime, _, address := startHTTPDrainRuntime(t, handler, completedBeforeAuditClose(t, completed))
	client, err := tls.Dial("tcp", strings.TrimPrefix(address, "https://"), &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("connect upload: %v", err)
	}
	defer func() { _ = client.Close() }()
	if err := client.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	upload := baseImageUploadRequest(t, "base_image", "cancelled.qcow2", baseImageQCOW2TestData(strings.Repeat("data", 1<<15)))
	body, err := io.ReadAll(upload.Body)
	if err != nil {
		t.Fatal(err)
	}
	_ = upload.Body.Close()
	_, err = fmt.Fprintf(client, "POST /api/admin/base-images HTTP/1.1\r\nHost: %s\r\nOrigin: %s\r\nCookie: %s\r\nContent-Type: %s\r\nContent-Length: %d\r\n\r\n",
		strings.TrimPrefix(address, "https://"), address, cookie.String(), upload.Header.Get("Content-Type"), len(body))
	if err != nil {
		t.Fatalf("write upload headers: %v", err)
	}
	if _, err := client.Write(body[:len(body)/2]); err != nil {
		t.Fatalf("write partial upload: %v", err)
	}
	awaitPartialBaseImage(t, config.BaseImageDir(settings), completed)
	expireHTTPDrain(t, runtime)
	entries, err := os.ReadDir(config.BaseImageDir(settings))
	if err != nil || len(entries) != 0 {
		t.Fatalf("cancelled upload retained files: entries=%v error=%v", entries, err)
	}
	if err := runtime.Close(); err != nil {
		t.Fatalf("close runtime after cancelled upload: %v", err)
	}
}

func expireHTTPDrain(t *testing.T, runtime *gatewayRuntime) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	if err := runtime.httpServers.shutdown(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("HTTP drain = %v, want grace period deadline", err)
	}
}

func awaitPartialBaseImage(t *testing.T, dir string, completed <-chan struct{}) {
	t.Helper()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	timeout := time.NewTimer(2 * time.Second)
	defer timeout.Stop()
	for {
		entries, err := os.ReadDir(dir)
		if err == nil && len(entries) == 1 {
			return
		}
		select {
		case <-completed:
			t.Fatal("upload handler returned before receiving the complete file")
		case <-timeout.C:
			t.Fatal("partial upload did not create a private temporary file")
		case <-ticker.C:
		}
	}
}
