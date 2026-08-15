package virt

import (
	"errors"
	"testing"

	"libvirt.org/go/libvirt"
)

func TestLoadDomainDiskSnapshotUsesVDAAndPreservesFallbacks(t *testing.T) {
	calls := 0
	disk, err := loadDomainDiskSnapshot(func(target string, flags uint32) (*libvirt.DomainBlockInfo, error) {
		calls++
		if target != "vda" || flags != 0 {
			t.Fatalf("GetBlockInfo(%q, %d), want (vda, 0)", target, flags)
		}
		return &libvirt.DomainBlockInfo{
			Capacity:   2 << 30,
			Allocation: 512 * 1024,
			Physical:   3 << 30,
		}, nil
	})
	if err != nil {
		t.Fatalf("load disk snapshot: %v", err)
	}
	if calls != 1 {
		t.Fatalf("GetBlockInfo calls = %d, want exactly 1", calls)
	}
	want := domainDiskSnapshot{UsedGB: 1, TotalGB: 2}
	if disk != want {
		t.Fatalf("disk snapshot = %+v, want %+v", disk, want)
	}
}

func TestLoadDomainDiskSnapshotRejectsErrorAndNilResult(t *testing.T) {
	wantErr := errors.New("block info unavailable")
	if _, err := loadDomainDiskSnapshot(func(string, uint32) (*libvirt.DomainBlockInfo, error) {
		return nil, wantErr
	}); !errors.Is(err, wantErr) {
		t.Fatalf("load error = %v, want wrapped %v", err, wantErr)
	}
	if _, err := loadDomainDiskSnapshot(func(string, uint32) (*libvirt.DomainBlockInfo, error) {
		return nil, nil
	}); err == nil {
		t.Fatal("expected nil successful block-info result to fail")
	}
}

func TestDomainDiskCacheSweepCachesSuccessfulZeroSnapshot(t *testing.T) {
	const domainUUID = "66666666-6666-6666-6666-666666666666"
	want := domainDiskSnapshot{}
	calls := 0

	firstSweep := newDomainDiskCacheSweep(nil)
	got, err := firstSweep.load(domainUUID, func() (domainDiskSnapshot, error) {
		calls++
		return want, nil
	})
	if err != nil || got != want {
		t.Fatalf("first zero load = %+v, %v; want %+v, nil", got, err, want)
	}
	if _, ok := firstSweep.retainedEntries()[domainUUID]; !ok {
		t.Fatal("successful 0/0 disk snapshot was not cached")
	}

	secondSweep := newDomainDiskCacheSweep(firstSweep.retainedEntries())
	got, err = secondSweep.load(domainUUID, func() (domainDiskSnapshot, error) {
		calls++
		return domainDiskSnapshot{UsedGB: 9, TotalGB: 10}, nil
	})
	if err != nil || got != want {
		t.Fatalf("cached zero load = %+v, %v; want %+v, nil", got, err, want)
	}
	if calls != 1 {
		t.Fatalf("disk loader calls = %d, want exactly 1", calls)
	}
}

func TestDomainDiskCacheSweepRetriesLoaderError(t *testing.T) {
	const domainUUID = "77777777-7777-7777-7777-777777777777"
	wantErr := errors.New("block info unavailable")
	want := domainDiskSnapshot{UsedGB: 1, TotalGB: 20}
	calls := 0

	firstSweep := newDomainDiskCacheSweep(nil)
	_, err := firstSweep.load(domainUUID, func() (domainDiskSnapshot, error) {
		calls++
		return domainDiskSnapshot{}, wantErr
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("first load error = %v, want %v", err, wantErr)
	}
	if len(firstSweep.retainedEntries()) != 0 {
		t.Fatalf("failed disk snapshot was cached: %+v", firstSweep.retainedEntries())
	}

	secondSweep := newDomainDiskCacheSweep(firstSweep.retainedEntries())
	got, err := secondSweep.load(domainUUID, func() (domainDiskSnapshot, error) {
		calls++
		return want, nil
	})
	if err != nil || got != want {
		t.Fatalf("retry load = %+v, %v; want %+v, nil", got, err, want)
	}
	if calls != 2 {
		t.Fatalf("disk loader calls = %d, want 2", calls)
	}
}

func TestDomainDiskCacheSweepDoesNotCacheWithoutUUID(t *testing.T) {
	calls := 0
	previous := map[string]domainDiskSnapshot(nil)
	for range 2 {
		sweep := newDomainDiskCacheSweep(previous)
		_, err := sweep.load(" ", func() (domainDiskSnapshot, error) {
			calls++
			return domainDiskSnapshot{UsedGB: 1, TotalGB: 2}, nil
		})
		if err != nil {
			t.Fatalf("load without UUID: %v", err)
		}
		previous = sweep.retainedEntries()
	}
	if calls != 2 {
		t.Fatalf("disk loader calls without UUID = %d, want 2", calls)
	}
	if len(previous) != 0 {
		t.Fatalf("disk snapshot without UUID was cached: %+v", previous)
	}
}

func TestDomainDiskCacheSweepInvalidatesReplacementAndPrunesRemoval(t *testing.T) {
	const oldUUID = "88888888-8888-8888-8888-888888888888"
	const newUUID = "99999999-9999-9999-9999-999999999999"
	oldDisk := domainDiskSnapshot{UsedGB: 1, TotalGB: 10}
	newDisk := domainDiskSnapshot{UsedGB: 2, TotalGB: 20}

	firstSweep := newDomainDiskCacheSweep(nil)
	if _, err := firstSweep.load(oldUUID, func() (domainDiskSnapshot, error) {
		return oldDisk, nil
	}); err != nil {
		t.Fatalf("load old same-name domain disk: %v", err)
	}

	secondSweep := newDomainDiskCacheSweep(firstSweep.retainedEntries())
	got, err := secondSweep.load(newUUID, func() (domainDiskSnapshot, error) {
		return newDisk, nil
	})
	if err != nil || got != newDisk {
		t.Fatalf("replacement load = %+v, %v; want %+v, nil", got, err, newDisk)
	}
	retained := secondSweep.retainedEntries()
	if len(retained) != 1 || retained[newUUID] != newDisk {
		t.Fatalf("replacement disk cache = %+v, want only new UUID", retained)
	}
	if _, ok := retained[oldUUID]; ok {
		t.Fatalf("old UUID %q survived replacement sweep", oldUUID)
	}

	removalSweep := newDomainDiskCacheSweep(retained)
	if got := removalSweep.retainedEntries(); len(got) != 0 {
		t.Fatalf("removed domain disk cache survived empty sweep: %+v", got)
	}
}
