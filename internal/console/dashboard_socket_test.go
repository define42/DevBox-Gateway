package console

import (
	"errors"
	"testing"

	"github.com/define42/devbox-gateway/internal/dashboard"
)

func TestDashboardPongIncludesServerMemoryOnlyForAdminView(t *testing.T) {
	t.Parallel()

	wantMemory := dashboard.ServerMemory{
		UsedBytes:  32 * 1024 * 1024 * 1024,
		TotalBytes: 64 * 1024 * 1024 * 1024,
	}
	tests := []struct {
		name          string
		allVMs        bool
		readErr       error
		wantMemory    *dashboard.ServerMemory
		wantReadCalls int
	}{
		{
			name:          "admin view",
			allVMs:        true,
			wantMemory:    &wantMemory,
			wantReadCalls: 1,
		},
		{
			name:          "ordinary dashboard",
			allVMs:        false,
			wantReadCalls: 0,
		},
		{
			name:          "admin read failure",
			allVMs:        true,
			readErr:       errors.New("memory unavailable"),
			wantReadCalls: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			probe := 123.456
			readCalls := 0
			view := dashboardView{
				allVMs: tt.allVMs,
				readServerMemory: func() (dashboard.ServerMemory, error) {
					readCalls++
					return wantMemory, tt.readErr
				},
			}

			got := dashboardPong(view, &probe)
			assertDashboardPong(t, got, probe, tt.wantMemory)
			if readCalls != tt.wantReadCalls {
				t.Fatalf("dashboardPong() read memory %d times, want %d", readCalls, tt.wantReadCalls)
			}
		})
	}
}

func assertDashboardPong(t *testing.T, got dashboardServerMessage, wantID float64, wantMemory *dashboard.ServerMemory) {
	t.Helper()

	if got.Type != "pong" || got.ID == nil || *got.ID != wantID {
		t.Fatalf("dashboardPong() returned an invalid pong: %+v", got)
	}
	if got.ServerMemory == nil && wantMemory == nil {
		return
	}
	if got.ServerMemory == nil || wantMemory == nil || *got.ServerMemory != *wantMemory {
		t.Fatalf("dashboardPong() memory = %+v, want %+v", got.ServerMemory, wantMemory)
	}
}
