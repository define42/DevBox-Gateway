package console

import (
	"errors"
	"testing"

	"github.com/define42/devbox-gateway/internal/dashboard"
)

type dashboardPongTestCase struct {
	name                string
	allVMs              bool
	memoryErr           error
	diskErr             error
	wantMemory          *dashboard.ServerMemory
	wantDisk            *dashboard.ServerDisk
	wantMemoryReadCalls int
	wantDiskReadCalls   int
}

func dashboardPongTestCases(
	wantMemory *dashboard.ServerMemory,
	wantDisk *dashboard.ServerDisk,
) []dashboardPongTestCase {
	return []dashboardPongTestCase{
		{
			name:                "admin view",
			allVMs:              true,
			wantMemory:          wantMemory,
			wantDisk:            wantDisk,
			wantMemoryReadCalls: 1,
			wantDiskReadCalls:   1,
		},
		{name: "ordinary dashboard"},
		{
			name:                "memory failure keeps disk sample",
			allVMs:              true,
			memoryErr:           errors.New("memory unavailable"),
			wantDisk:            wantDisk,
			wantMemoryReadCalls: 1,
			wantDiskReadCalls:   1,
		},
		{
			name:                "disk failure keeps memory sample",
			allVMs:              true,
			diskErr:             errors.New("disk unavailable"),
			wantMemory:          wantMemory,
			wantMemoryReadCalls: 1,
			wantDiskReadCalls:   1,
		},
		{
			name:                "both reads fail",
			allVMs:              true,
			memoryErr:           errors.New("memory unavailable"),
			diskErr:             errors.New("disk unavailable"),
			wantMemoryReadCalls: 1,
			wantDiskReadCalls:   1,
		},
	}
}

func TestDashboardPongIncludesServerUsageOnlyForAdminView(t *testing.T) {
	t.Parallel()

	wantMemory := dashboard.ServerMemory{
		UsedBytes:  32 * 1024 * 1024 * 1024,
		TotalBytes: 64 * 1024 * 1024 * 1024,
	}
	wantDisk := dashboard.ServerDisk{
		UsedBytes:  150 * 1024 * 1024 * 1024,
		TotalBytes: 500 * 1024 * 1024 * 1024,
	}
	for _, tt := range dashboardPongTestCases(&wantMemory, &wantDisk) {
		t.Run(tt.name, func(t *testing.T) {
			probe := 123.456
			memoryReadCalls := 0
			diskReadCalls := 0
			view := dashboardView{
				allVMs: tt.allVMs,
				readServerMemory: func() (dashboard.ServerMemory, error) {
					memoryReadCalls++
					return wantMemory, tt.memoryErr
				},
				readServerDisk: func() (dashboard.ServerDisk, error) {
					diskReadCalls++
					return wantDisk, tt.diskErr
				},
			}

			got := dashboardPong(view, &probe)
			assertDashboardPong(t, got, probe, tt.wantMemory, tt.wantDisk)
			if memoryReadCalls != tt.wantMemoryReadCalls {
				t.Fatalf("dashboardPong() read memory %d times, want %d", memoryReadCalls, tt.wantMemoryReadCalls)
			}
			if diskReadCalls != tt.wantDiskReadCalls {
				t.Fatalf("dashboardPong() read disk %d times, want %d", diskReadCalls, tt.wantDiskReadCalls)
			}
		})
	}
}

func assertDashboardPong(
	t *testing.T,
	got dashboardServerMessage,
	wantID float64,
	wantMemory *dashboard.ServerMemory,
	wantDisk *dashboard.ServerDisk,
) {
	t.Helper()

	if got.Type != "pong" || got.ID == nil || *got.ID != wantID {
		t.Fatalf("dashboardPong() returned an invalid pong: %+v", got)
	}
	assertOptionalServerUsage(t, "memory", got.ServerMemory, wantMemory)
	assertOptionalServerUsage(t, "disk", got.ServerDisk, wantDisk)
}

func assertOptionalServerUsage[T comparable](t *testing.T, label string, got, want *T) {
	t.Helper()

	if got == nil && want == nil {
		return
	}
	if got == nil || want == nil || *got != *want {
		t.Fatalf("dashboardPong() %s = %+v, want %+v", label, got, want)
	}
}
