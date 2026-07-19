package virt

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func vbtcovSeedUserData() *SeedUserData {
	return &SeedUserData{Users: []SeedUser{{Name: "cvbtguest", Shell: "/bin/bash"}}}
}

func vbtcovSeedMetaData() *SeedMetaData {
	return &SeedMetaData{InstanceID: "cvbt-instance", LocalHostname: "cvbt-host"}
}

// vbtcovBreakTempDir points TMPDIR at a missing directory so iso9660.NewWriter
// (which stages into os.TempDir()) fails deterministically for this test.
func vbtcovBreakTempDir(t *testing.T) {
	t.Helper()

	missing := filepath.Join(t.TempDir(), "cvbt-missing-tmp")
	t.Setenv("TMPDIR", missing)
}

func TestVbtcovCreateSeedISOWriterFailure(t *testing.T) {
	vbtcovBreakTempDir(t)

	_, err := CreateSeedISO(vbtcovSeedUserData(), vbtcovSeedMetaData(), nil)
	vbtcovRequireErrContains(t, err, "create iso writer", "CreateSeedISO with broken TMPDIR")
}

func TestVbtcovCreateSeedISOWithoutNetworkConfig(t *testing.T) {
	t.Run("nil network config", func(t *testing.T) {
		data, err := CreateSeedISO(vbtcovSeedUserData(), vbtcovSeedMetaData(), nil)
		if err != nil {
			t.Fatalf("CreateSeedISO without network config: %v", err)
		}
		if len(data) == 0 {
			t.Fatal("expected non-empty iso without network config")
		}
	})

	t.Run("zero network config", func(t *testing.T) {
		data, err := CreateSeedISO(vbtcovSeedUserData(), vbtcovSeedMetaData(), &SeedNetworkConfig{})
		if err != nil {
			t.Fatalf("CreateSeedISO with zero network config: %v", err)
		}
		if len(data) == 0 {
			t.Fatal("expected non-empty iso with zero network config")
		}
	})
}

func TestVbtcovSeedISOYAMLBytes(t *testing.T) {
	t.Run("nil optional doc yields nothing", func(t *testing.T) {
		data, err := seedISOYAMLBytes("network-config", (*SeedNetworkConfig)(nil), false, "#cloud-config\n")
		if err != nil || data != nil {
			t.Fatalf("seedISOYAMLBytes(nil, optional) = %q, %v; want nil, nil", data, err)
		}
	})

	t.Run("nil required doc fails", func(t *testing.T) {
		_, err := seedISOYAMLBytes("user-data", (*SeedUserData)(nil), true, "#cloud-config\n")
		vbtcovRequireErrContains(t, err, "user-data is required", "seedISOYAMLBytes with nil required doc")
	})

	t.Run("zero required doc fails", func(t *testing.T) {
		_, err := seedISOYAMLBytes("user-data", &SeedUserData{}, true, "#cloud-config\n")
		vbtcovRequireErrContains(t, err, "user-data is required", "seedISOYAMLBytes with zero required doc")
	})

	t.Run("zero optional doc yields nothing", func(t *testing.T) {
		data, err := seedISOYAMLBytes("network-config", &SeedNetworkConfig{}, false, "#cloud-config\n")
		if err != nil || data != nil {
			t.Fatalf("seedISOYAMLBytes(zero, optional) = %q, %v; want nil, nil", data, err)
		}
	})

	t.Run("unmarshalable doc fails", func(t *testing.T) {
		fn := func() {}
		_, err := seedISOYAMLBytes("cvbt-doc", &fn, true, "")
		vbtcovRequireErrContains(t, err, "marshal cvbt-doc", "seedISOYAMLBytes with func value")
	})

	t.Run("prefix is prepended", func(t *testing.T) {
		data, err := seedISOYAMLBytes("meta-data", vbtcovSeedMetaData(), true, "#prefix\n")
		if err != nil {
			t.Fatalf("seedISOYAMLBytes with prefix: %v", err)
		}
		if !strings.HasPrefix(string(data), "#prefix\n") {
			t.Fatalf("expected data to start with prefix, got %q", data)
		}
	})
}

func TestVbtcovCreateUbuntuSeedISOToPoolSeedFailure(t *testing.T) {
	conn := newTestLibvirtConn(t)
	vbtcovBreakTempDir(t)

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
