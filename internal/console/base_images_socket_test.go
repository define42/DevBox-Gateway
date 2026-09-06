package console

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/define42/devbox-gateway/internal/config"
	"github.com/define42/devbox-gateway/internal/virt"

	"github.com/gorilla/websocket"
)

func TestDashboardSocketsReceiveBaseImageChanges(t *testing.T) {
	settings := config.NewSettings(false)
	directory := t.TempDir()
	if err := settings.OverwriteForTestString(config.BASE_IMAGE_DIR, directory); err != nil {
		t.Fatalf("set base image directory: %v", err)
	}
	if err := os.WriteFile(filepath.Join(directory, "original.qcow2"), []byte("QFI\xfbimage"), 0o600); err != nil {
		t.Fatalf("seed base image: %v", err)
	}
	clients := []*websocket.Conn{
		newBaseImageDashboardClient(t, settings, "base-image-socket-alice"),
		newBaseImageDashboardClient(t, settings, "base-image-socket-bob"),
	}
	assertDashboardBaseImages(t, clients, "original.qcow2")

	storeDashboardBaseImage(t, settings, "uploaded.qcow2")
	assertDashboardBaseImages(t, clients, "original.qcow2", "uploaded.qcow2")
	if err := virt.DeleteBaseImage(settings, "original.qcow2"); err != nil {
		t.Fatalf("delete original image: %v", err)
	}
	assertDashboardBaseImages(t, clients, "uploaded.qcow2")
	if err := virt.DeleteBaseImage(settings, "uploaded.qcow2"); err != nil {
		t.Fatalf("delete final image: %v", err)
	}
	// Empty slices are omitted on the wire; the browser must receive a new
	// dashboard frame so it can clear its picker and disable VM creation.
	assertDashboardBaseImages(t, clients)
	storeDashboardBaseImage(t, settings, "restored.qcow2")
	assertDashboardBaseImages(t, clients, "restored.qcow2")
}

func newBaseImageDashboardClient(t *testing.T, settings *config.Settings, username string) *websocket.Conn {
	t.Helper()
	client, server, cleanup := newWebsocketPair(t)
	done := make(chan struct{})
	t.Cleanup(func() {
		cleanup()
		select {
		case <-done:
		case <-time.After(websocketTestTimeout):
			t.Error("dashboard bridge did not stop after socket cleanup")
		}
	})
	go func() {
		defer close(done)
		bridgeDashboardControlSocket(server, username, settings, time.Now().Add(time.Minute))
	}()
	return client
}

func storeDashboardBaseImage(t *testing.T, settings *config.Settings, name string) {
	t.Helper()
	if _, err := virt.StoreBaseImage(settings, name, strings.NewReader("QFI\xfbimage"), 64); err != nil {
		t.Fatalf("upload base image %s: %v", name, err)
	}
}

func assertDashboardBaseImages(t *testing.T, clients []*websocket.Conn, want ...string) {
	t.Helper()
	for _, client := range clients {
		awaitDashboardBaseImages(t, client, want)
	}
}

func awaitDashboardBaseImages(t *testing.T, client *websocket.Conn, want []string) {
	t.Helper()
	if err := client.SetReadDeadline(time.Now().Add(websocketTestTimeout)); err != nil {
		t.Fatalf("set dashboard read deadline: %v", err)
	}
	for {
		var message dashboardServerMessage
		if err := client.ReadJSON(&message); err != nil {
			t.Fatalf("dashboard did not publish base images %v: %v", want, err)
		}
		if message.Type == "dashboard" && message.Data != nil && slices.Equal(message.Data.BaseImages, want) {
			return
		}
	}
}
