package virt

import (
	"fmt"
	"strings"

	"libvirt.org/go/libvirt"
)

// domainDiskSnapshot is a successful GetBlockInfo result converted to the
// dashboard's GiB units. A zero value is a valid successful snapshot; cache
// membership, rather than its numeric fields, distinguishes it from failure.
type domainDiskSnapshot struct {
	UsedGB  int
	TotalGB int
}

type (
	domainBlockInfoGetter    func(string, uint32) (*libvirt.DomainBlockInfo, error)
	domainDiskSnapshotLoader func() (domainDiskSnapshot, error)
)

func loadDomainDiskSnapshot(getBlockInfo domainBlockInfoGetter) (domainDiskSnapshot, error) {
	info, err := getBlockInfo("vda", 0)
	if err != nil {
		return domainDiskSnapshot{}, fmt.Errorf("get vda block info: %w", err)
	}
	if info == nil {
		return domainDiskSnapshot{}, fmt.Errorf("get vda block info: empty result")
	}

	capacity := info.Capacity
	if capacity == 0 {
		capacity = info.Physical
	}
	if capacity == 0 {
		capacity = info.Allocation
	}

	allocation := info.Allocation
	if allocation == 0 {
		allocation = info.Physical
	}

	return domainDiskSnapshot{
		UsedGB:  bytesToGiBCeil(allocation),
		TotalGB: bytesToGiBCeil(capacity),
	}, nil
}

// domainDiskCacheSweep retains the first successful block-info snapshot for a
// domain UUID. VolumeGB and VolumeUsedGB intentionally remain that snapshot for
// the UUID's lifetime; same-UUID resize/allocation changes made inside the guest
// or by an external administrator appear only after a confirmed libvirt host
// change, gateway restart, or domain replacement. A same-host reconnect retains
// the snapshot. Building a fresh retained map each successful sweep prunes
// removed domains.
type domainDiskCacheSweep struct {
	previous map[string]domainDiskSnapshot
	retained map[string]domainDiskSnapshot
}

func newDomainDiskCacheSweep(previous map[string]domainDiskSnapshot) *domainDiskCacheSweep {
	return &domainDiskCacheSweep{
		previous: previous,
		retained: make(map[string]domainDiskSnapshot),
	}
}

func (sweep *domainDiskCacheSweep) load(
	domainUUID string,
	loader domainDiskSnapshotLoader,
) (domainDiskSnapshot, error) {
	domainUUID = strings.TrimSpace(domainUUID)
	if domainUUID != "" {
		if disk, ok := sweep.retained[domainUUID]; ok {
			return disk, nil
		}
		if disk, ok := sweep.previous[domainUUID]; ok {
			sweep.retained[domainUUID] = disk
			return disk, nil
		}
	}

	disk, err := loader()
	if err != nil {
		return domainDiskSnapshot{}, err
	}
	if domainUUID != "" {
		sweep.retained[domainUUID] = disk
	}
	return disk, nil
}

func (sweep *domainDiskCacheSweep) retainedEntries() map[string]domainDiskSnapshot {
	return sweep.retained
}
