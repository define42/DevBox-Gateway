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

func TestDashboardPongIncludesServerCPUOnlyForAdminView(t *testing.T) {
	t.Parallel()

	wantCPU := dashboard.ServerCPU{UsagePercent: 42.5}
	tests := []struct {
		name          string
		allVMs        bool
		sampleErr     error
		wantCPU       *dashboard.ServerCPU
		wantReadCalls int
	}{
		{name: "admin view", allVMs: true, wantCPU: &wantCPU, wantReadCalls: 1},
		{name: "ordinary dashboard"},
		{name: "admin sample failure", allVMs: true, sampleErr: errors.New("CPU unavailable"), wantReadCalls: 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			probe := 123.456
			readCalls := 0
			view := dashboardView{
				allVMs: tt.allVMs,
				sampleServerCPU: func() (*dashboard.ServerCPU, error) {
					readCalls++
					return &wantCPU, tt.sampleErr
				},
			}

			got := dashboardPong(view, &probe)
			assertDashboardPong(t, got, probe, nil, nil)
			assertOptionalServerUsage(t, "CPU", got.ServerCPU, tt.wantCPU)
			if readCalls != tt.wantReadCalls {
				t.Fatalf("dashboardPong() sampled CPU %d times, want %d", readCalls, tt.wantReadCalls)
			}
		})
	}
}

func TestDashboardPongIncludesServerDiskIOOnlyForAdminView(t *testing.T) {
	t.Parallel()

	wantDiskIO := dashboard.ServerDiskIO{
		UsagePercent:        42.5,
		ReadBytesPerSecond:  12 * 1024 * 1024,
		WriteBytesPerSecond: 3 * 1024 * 1024,
	}
	tests := []struct {
		name            string
		allVMs          bool
		sample          *dashboard.ServerDiskIO
		sampleErr       error
		wantDiskIO      *dashboard.ServerDiskIO
		wantSampleCalls int
	}{
		{
			name:            "admin view",
			allVMs:          true,
			sample:          &wantDiskIO,
			wantDiskIO:      &wantDiskIO,
			wantSampleCalls: 1,
		},
		{name: "ordinary dashboard", sample: &wantDiskIO},
		{name: "admin baseline", allVMs: true, wantSampleCalls: 1},
		{
			name:            "admin sample failure",
			allVMs:          true,
			sample:          &wantDiskIO,
			sampleErr:       errors.New("disk I/O unavailable"),
			wantSampleCalls: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			probe := 123.456
			sampleCalls := 0
			view := dashboardView{
				allVMs: tt.allVMs,
				sampleServerDiskIO: func() (*dashboard.ServerDiskIO, error) {
					sampleCalls++
					return tt.sample, tt.sampleErr
				},
			}

			got := dashboardPong(view, &probe)
			assertDashboardPong(t, got, probe, nil, nil)
			assertOptionalServerUsage(t, "disk I/O", got.ServerDiskIO, tt.wantDiskIO)
			if sampleCalls != tt.wantSampleCalls {
				t.Fatalf("dashboardPong() sampled disk I/O %d times, want %d", sampleCalls, tt.wantSampleCalls)
			}
		})
	}
}

func TestDashboardPongKeepsOtherUsageWhenServerCPUFails(t *testing.T) {
	t.Parallel()

	wantMemory := dashboard.ServerMemory{UsedBytes: 1, TotalBytes: 2}
	wantDisk := dashboard.ServerDisk{UsedBytes: 3, TotalBytes: 4}
	wantDiskIO := dashboard.ServerDiskIO{UsagePercent: 25, ReadBytesPerSecond: 5, WriteBytesPerSecond: 6}
	view := dashboardView{
		allVMs:             true,
		readServerMemory:   func() (dashboard.ServerMemory, error) { return wantMemory, nil },
		readServerDisk:     func() (dashboard.ServerDisk, error) { return wantDisk, nil },
		sampleServerDiskIO: func() (*dashboard.ServerDiskIO, error) { return &wantDiskIO, nil },
		sampleServerCPU:    func() (*dashboard.ServerCPU, error) { return nil, errors.New("CPU unavailable") },
	}

	probe := 123.456
	got := dashboardPong(view, &probe)
	assertDashboardPong(t, got, probe, &wantMemory, &wantDisk)
	assertOptionalServerUsage(t, "disk I/O", got.ServerDiskIO, &wantDiskIO)
	if got.ServerCPU != nil {
		t.Fatalf("dashboardPong() CPU = %+v, want nil", got.ServerCPU)
	}
}

func TestDashboardPongKeepsOtherUsageWhenServerDiskIOFails(t *testing.T) {
	t.Parallel()

	wantMemory := dashboard.ServerMemory{UsedBytes: 1, TotalBytes: 2}
	wantDisk := dashboard.ServerDisk{UsedBytes: 3, TotalBytes: 4}
	wantCPU := dashboard.ServerCPU{UsagePercent: 50}
	view := dashboardView{
		allVMs:             true,
		readServerMemory:   func() (dashboard.ServerMemory, error) { return wantMemory, nil },
		readServerDisk:     func() (dashboard.ServerDisk, error) { return wantDisk, nil },
		sampleServerDiskIO: func() (*dashboard.ServerDiskIO, error) { return nil, errors.New("disk I/O unavailable") },
		sampleServerCPU:    func() (*dashboard.ServerCPU, error) { return &wantCPU, nil },
	}

	probe := 123.456
	got := dashboardPong(view, &probe)
	assertDashboardPong(t, got, probe, &wantMemory, &wantDisk)
	if got.ServerDiskIO != nil {
		t.Fatalf("dashboardPong() disk I/O = %+v, want nil", got.ServerDiskIO)
	}
	assertOptionalServerUsage(t, "CPU", got.ServerCPU, &wantCPU)
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
