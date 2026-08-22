package virt

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"
)

func TestVbtcovCreateUbuntuSeedISOToPoolSeedFailure(t *testing.T) {
	conn := newTestLibvirtConn(t)
	missing := filepath.Join(t.TempDir(), "cvbt-missing-tmp")
	t.Setenv("TMPDIR", missing)

	// The seed ISO build fails before any pool interaction.
	err := CreateUbuntuSeedISOToPool(conn, "cvbt-unused-pool", "cvbt-seed.iso", "cvbtguest", "$6$hash", "cvbt-host")
	vbtcovRequireErrContains(t, err, "create iso writer", "CreateUbuntuSeedISOToPool with broken TMPDIR")
}

func TestVbtcovCreateUbuntuSeedISOToPoolMissingPool(t *testing.T) {
	conn := newTestLibvirtConn(t)

	err := CreateUbuntuSeedISOToPool(conn, uniquePoolName("cvbt-nopool"), "cvbt-seed.iso", "cvbtguest", "$6$hash", "cvbt-host")
	vbtcovRequireErrContains(t, err, "not found", "CreateUbuntuSeedISOToPool into missing pool")
}

func TestVbtcovCreateUbuntuSeedISOToPoolDuplicateVolume(t *testing.T) {
	conn := newTestLibvirtConn(t)
	pool, poolName, _ := vbtcovEnsureTestPool(t, conn, "cvbt-seedvol-pool")

	volumeName := fmt.Sprintf("cvbt-seed-dup-%d.iso", time.Now().UnixNano())
	t.Cleanup(func() { _ = RemoveVolumes(conn, poolName, volumeName) })

	vol, err := createQCOW2Volume(nil, pool, volumeName, vbtcovTinyCapacity)
	if err != nil {
		t.Fatalf("create conflicting volume: %v", err)
	}
	_ = vol.Free()

	err = CreateUbuntuSeedISOToPool(conn, poolName, volumeName, "cvbtguest", "$6$hash", "cvbt-host")
	if err == nil {
		t.Fatal("expected CreateUbuntuSeedISOToPool to fail on duplicate volume name")
	}
}

func TestVbtcovUploadSeedISOErrors(t *testing.T) {
	conn := newTestLibvirtConn(t)
	pool, _, _ := vbtcovEnsureTestPool(t, conn, "cvbt-seedupl-pool")
	data := []byte("cvbt-seed-data")

	t.Run("closed connection fails stream creation", func(t *testing.T) {
		stale := vbtcovStaleVolHandle(t, pool, "cvbt-seedupl-closed")
		if err := uploadSeedISO(vbtcovClosedConn(t), stale, data); err == nil {
			t.Fatal("expected uploadSeedISO on closed connection to fail")
		}
	})

	t.Run("deleted volume fails upload start", func(t *testing.T) {
		stale := vbtcovStaleVolHandle(t, pool, "cvbt-seedupl-gone")
		err := uploadSeedISO(conn, stale, data)
		vbtcovRequireErrContains(t, err, "not found", "uploadSeedISO into deleted volume")
	})
}
