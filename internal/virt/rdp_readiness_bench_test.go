package virt

import (
	"context"
	"fmt"
	"testing"
)

func BenchmarkInventoryRefreshRDPReadinessFanout(b *testing.B) {
	for _, vmCount := range []int{10, 100, 1_000} {
		b.Run(fmt.Sprintf("VMs_%d", vmCount), func(b *testing.B) {
			worker := &Inventory{}
			worker.setVMs(benchmarkInventoryVMs(vmCount))

			ctx := context.Background()
			probe := func(context.Context, string) bool { return true }

			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				worker.refreshRDPReadiness(ctx, "benchmark-owner", probe)
			}
		})
	}
}
