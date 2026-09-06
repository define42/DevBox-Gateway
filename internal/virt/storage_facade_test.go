package virt

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/define42/devbox-gateway/internal/config"
)

func baseImageFacadeSettings(t *testing.T, worker *Inventory) *config.Settings {
	t.Helper()
	previous := inventoryInstance.Swap(worker)
	t.Cleanup(func() { inventoryInstance.Store(previous) })
	settings := config.NewSettings(false)
	if err := settings.OverwriteForTestString(config.BASE_IMAGE_DIR, t.TempDir()); err != nil {
		t.Fatalf("set base-image directory: %v", err)
	}
	return settings
}

func storeFacadeTestImage(settings *config.Settings, name string) error {
	_, err := StoreBaseImage(settings, name, strings.NewReader("QFI\xfbtest image"), 1024)
	return err
}

func subscribeToBaseImageChanges(t *testing.T, worker *Inventory) []<-chan struct{} {
	t.Helper()
	var subscribers []<-chan struct{}
	for range 2 {
		updates, unsubscribe := worker.SubscribeVMChanges()
		t.Cleanup(unsubscribe)
		subscribers = append(subscribers, updates)
	}
	return subscribers
}

func checkBaseImageNotifications(t *testing.T, subscribers []<-chan struct{}, want bool) {
	t.Helper()
	for i, updates := range subscribers {
		var notified bool
		select {
		case <-updates:
			notified = true
		default:
		}
		if notified != want {
			t.Errorf("subscriber %d notified=%v, want %v", i, notified, want)
		}
	}
}

func checkBaseImageListing(t *testing.T, settings *config.Settings, want []string) {
	t.Helper()
	images, err := ListBaseImages(settings)
	if err != nil {
		t.Fatalf("list base images: %v", err)
	}
	if !slices.Equal(images, want) {
		t.Errorf("base images=%v, want %v", images, want)
	}
}

func TestBaseImageMutationsNotifyAllSubscribers(t *testing.T) {
	worker := &Inventory{}
	settings := baseImageFacadeSettings(t, worker)
	subscribers := subscribeToBaseImageChanges(t, worker)

	if err := storeFacadeTestImage(settings, "z.qcow2"); err != nil {
		t.Fatalf("store first image: %v", err)
	}
	checkBaseImageNotifications(t, subscribers, true)
	checkBaseImageListing(t, settings, []string{"z.qcow2"})
	if err := storeFacadeTestImage(settings, "a.qcow2"); err != nil {
		t.Fatalf("store second image: %v", err)
	}
	checkBaseImageNotifications(t, subscribers, true)
	checkBaseImageListing(t, settings, []string{"a.qcow2", "z.qcow2"})

	if err := DeleteBaseImage(settings, "a.qcow2"); err != nil {
		t.Fatalf("delete first image: %v", err)
	}
	checkBaseImageNotifications(t, subscribers, true)
	checkBaseImageListing(t, settings, []string{"z.qcow2"})
	if err := DeleteBaseImage(settings, "z.qcow2"); err != nil {
		t.Fatalf("delete final image: %v", err)
	}
	checkBaseImageNotifications(t, subscribers, true)
	checkBaseImageListing(t, settings, nil)
	checkBaseImageNotifications(t, subscribers, false)
}

func TestRejectedBaseImageMutationsDoNotNotify(t *testing.T) {
	worker := &Inventory{}
	settings := baseImageFacadeSettings(t, worker)
	if err := storeFacadeTestImage(settings, "existing.qcow2"); err != nil {
		t.Fatalf("seed existing image: %v", err)
	}
	subscribers := subscribeToBaseImageChanges(t, worker)
	tests := []struct {
		name string
		run  func() error
		want error
	}{
		{
			name: "duplicate upload",
			run:  func() error { return storeFacadeTestImage(settings, "existing.qcow2") },
			want: ErrBaseImageExists,
		},
		{
			name: "invalid QCOW upload",
			run: func() error {
				_, err := StoreBaseImage(settings, "invalid.qcow2", strings.NewReader("not QCOW data"), 1024)
				return err
			},
			want: ErrInvalidBaseImageFormat,
		},
		{
			name: "missing deletion",
			run:  func() error { return DeleteBaseImage(settings, "missing.qcow2") },
			want: ErrBaseImageNotFound,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.run(); !errors.Is(err, tt.want) {
				t.Fatalf("mutation error=%v, want %v", err, tt.want)
			}
			checkBaseImageNotifications(t, subscribers, false)
			checkBaseImageListing(t, settings, []string{"existing.qcow2"})
		})
	}
}

func TestBaseImageMutationsDoNotStartInventory(t *testing.T) {
	settings := baseImageFacadeSettings(t, nil)
	if err := storeFacadeTestImage(settings, "desktop.qcow2"); err != nil {
		t.Fatalf("store image: %v", err)
	}
	if worker := peekInventory(); worker != nil {
		worker.Stop()
		t.Fatal("base-image upload started the inventory worker")
	}
	if err := DeleteBaseImage(settings, "desktop.qcow2"); err != nil {
		t.Fatalf("delete image: %v", err)
	}
	if worker := peekInventory(); worker != nil {
		worker.Stop()
		t.Fatal("base-image deletion started the inventory worker")
	}
}
