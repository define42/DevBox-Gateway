package virt

import (
	"fmt"
	"testing"

	"github.com/define42/devbox-gateway/internal/hash"
)

//nolint:gocognit // Nested size and hit/miss sub-benchmarks keep each measured scenario explicit.
func BenchmarkInventoryResolveVMNameByLabel(b *testing.B) {
	secret := []byte("deterministic-benchmark-routing-secret")
	for _, vmCount := range []int{10, 100, 1_000} {
		b.Run(fmt.Sprintf("VMs_%d", vmCount), func(b *testing.B) {
			worker := &Inventory{}
			vms := benchmarkInventoryVMs(vmCount)
			worker.setVMs(vms)
			targetName := vms[len(vms)-1].Name

			b.Run("HitLast", func(b *testing.B) {
				label := hash.RoutingLabel(secret, targetName)
				var got string
				var ok bool

				b.ReportAllocs()
				b.ResetTimer()
				for b.Loop() {
					got, ok = worker.ResolveVMNameByLabel(secret, label)
				}
				if !ok || got != targetName {
					b.Fatalf("ResolveVMNameByLabel() = %q, %v; want %q, true", got, ok, targetName)
				}
			})

			b.Run("Miss", func(b *testing.B) {
				label := hash.RoutingLabel(secret, "missing-vm")
				var got string
				var ok bool

				b.ReportAllocs()
				b.ResetTimer()
				for b.Loop() {
					got, ok = worker.ResolveVMNameByLabel(secret, label)
				}
				if ok || got != "" {
					b.Fatalf("ResolveVMNameByLabel() = %q, %v; want empty result", got, ok)
				}
			})
		})
	}
}

//nolint:gocognit // Nested size and hit/miss sub-benchmarks keep each measured scenario explicit.
func BenchmarkInventoryVMIP(b *testing.B) {
	for _, vmCount := range []int{10, 100, 1_000} {
		b.Run(fmt.Sprintf("VMs_%d", vmCount), func(b *testing.B) {
			worker := &Inventory{}
			vms := benchmarkInventoryVMs(vmCount)
			worker.setVMs(vms)
			target := vms[len(vms)-1]

			b.Run("HitLast", func(b *testing.B) {
				var got string
				var err error

				b.ReportAllocs()
				b.ResetTimer()
				for b.Loop() {
					got, err = worker.VMIP(target.Name)
				}
				if err != nil || got != target.PrimaryIP {
					b.Fatalf("VMIP() = %q, %v; want %q, nil", got, err, target.PrimaryIP)
				}
			})

			b.Run("Miss", func(b *testing.B) {
				var got string
				var err error

				b.ReportAllocs()
				b.ResetTimer()
				for b.Loop() {
					got, err = worker.VMIP("missing-vm")
				}
				if err == nil || got != "" {
					b.Fatalf("VMIP() = %q, %v; want empty result and an error", got, err)
				}
			})
		})
	}
}

func BenchmarkInventoryApplyWarmSnapshotSweep(b *testing.B) {
	for _, vmCount := range []int{10, 100, 1_000} {
		b.Run(fmt.Sprintf("VMs_%d", vmCount), func(b *testing.B) {
			worker := &Inventory{}
			outcome := benchmarkWarmSweepOutcome(vmCount)
			worker.applySweep(outcome)

			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				worker.applySweep(outcome)
			}
		})
	}
}

func benchmarkInventoryVMs(count int) []VMInfo {
	vms := make([]VMInfo, count)
	for i := range vms {
		vms[i] = VMInfo{
			Name:      fmt.Sprintf("benchmark-vm-%04d", i),
			Owner:     "benchmark-owner",
			CreatedAt: "2026-01-01T00:00:00Z",
			State:     "running",
			PrimaryIP: fmt.Sprintf("192.168.%d.%d", i/250, i%250+1),
		}
	}
	return vms
}

func benchmarkWarmSweepOutcome(count int) sweepOutcome {
	metadata := make(map[string]domainMetadataSnapshot, count)
	disks := make(map[string]domainDiskSnapshot, count)
	for i := range count {
		id := fmt.Sprintf("benchmark-uuid-%04d", i)
		metadata[id] = domainMetadataSnapshot{Owner: "benchmark-owner"}
		disks[id] = domainDiskSnapshot{UsedGB: 10, TotalGB: 20}
	}
	return sweepOutcome{
		identity: inventoryHostIdentity{
			URI:      "test:///benchmark",
			HostUUID: "00000000-0000-0000-0000-000000000001",
		},
		vms:      benchmarkInventoryVMs(count),
		metadata: metadata,
		disks:    disks,
	}
}
