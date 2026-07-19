package virt

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/iotest"
	"time"

	"libvirt.org/go/libvirt"
)

const vbtcovTinyCapacity = 4096

// vbtcovClosedConn returns a libvirt connection that has already been closed,
// so every call on it fails with an "invalid connection" error that is neither
// ERR_NO_STORAGE_POOL, ERR_NO_NETWORK, nor ERR_NO_DOMAIN.
func vbtcovClosedConn(t *testing.T) *libvirt.Connect {
	t.Helper()

	conn, err := libvirt.NewConnect(LibvirtURI())
	if err != nil {
		t.Fatalf("connect libvirt: %v", err)
	}
	if _, err := conn.Close(); err != nil {
		t.Fatalf("close libvirt connection: %v", err)
	}
	return conn
}

// vbtcovEnsureTestPool creates a unique, active dir pool for one test.
func vbtcovEnsureTestPool(t *testing.T, conn *libvirt.Connect, prefix string) (*libvirt.StoragePool, string, string) {
	t.Helper()

	poolPath := t.TempDir()
	poolName := uniquePoolName(prefix)
	t.Cleanup(func() { cleanupStoragePool(t, poolName) })

	pool, err := ensureStoragePool(conn, poolName, poolPath)
	if err != nil {
		t.Fatalf("ensureStoragePool %s: %v", poolName, err)
	}
	t.Cleanup(func() { _ = pool.Free() })
	return pool, poolName, filepath.Clean(poolPath)
}

// vbtcovStalePoolHandle defines a pool and undefines it again while keeping the
// handle, so pool operations fail with "no storage pool". The caller must free
// the handle exactly once (some callees free it on error).
func vbtcovStalePoolHandle(t *testing.T, conn *libvirt.Connect) *libvirt.StoragePool {
	t.Helper()

	poolName := uniquePoolName("cvbt-stale-pool")
	t.Cleanup(func() { cleanupStoragePool(t, poolName) })

	pool, err := conn.StoragePoolDefineXML(storagePoolDefinitionXML(poolName, t.TempDir()), 0)
	if err != nil {
		t.Fatalf("define storage pool %s: %v", poolName, err)
	}
	if err := pool.Undefine(); err != nil {
		_ = pool.Free()
		t.Fatalf("undefine storage pool %s: %v", poolName, err)
	}
	return pool
}

// vbtcovStaleVolHandle creates a volume and deletes it while keeping the
// handle, so volume operations fail with "no storage vol".
func vbtcovStaleVolHandle(t *testing.T, pool *libvirt.StoragePool, name string) *libvirt.StorageVol {
	t.Helper()

	vol, err := createQCOW2Volume(nil, pool, name, vbtcovTinyCapacity)
	if err != nil {
		t.Fatalf("create volume %s: %v", name, err)
	}
	t.Cleanup(func() { _ = vol.Free() })
	if err := vol.Delete(0); err != nil {
		t.Fatalf("delete volume %s: %v", name, err)
	}
	return vol
}

func vbtcovRequireErrContains(t *testing.T, err error, substr, doing string) {
	t.Helper()

	if err == nil {
		t.Fatalf("%s: expected error containing %q, got nil", doing, substr)
	}
	if !strings.Contains(err.Error(), substr) {
		t.Fatalf("%s: expected error containing %q, got %v", doing, substr, err)
	}
}

func vbtcovWriteTinyFile(t *testing.T, name string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte("cvbt-tiny-image"), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

// vbtcovBlockedDirPath returns a path whose parent is a regular file, so any
// MkdirAll on it fails deterministically (independent of user privileges).
func vbtcovBlockedDirPath(t *testing.T) string {
	t.Helper()

	blocker := filepath.Join(t.TempDir(), "cvbt-not-a-dir")
	if err := os.WriteFile(blocker, []byte("blocker"), 0o644); err != nil {
		t.Fatalf("write blocker file %s: %v", blocker, err)
	}
	return filepath.Join(blocker, "sub")
}

func TestVbtcovEnsureStoragePoolMkdirFailure(t *testing.T) {
	conn := newTestLibvirtConn(t)

	_, err := ensureStoragePool(conn, uniquePoolName("cvbt-mkdir-pool"), vbtcovBlockedDirPath(t))
	vbtcovRequireErrContains(t, err, "create storage pool path", "ensureStoragePool with file-blocked path")
}

func TestVbtcovEnsureStoragePoolIdempotent(t *testing.T) {
	conn := newTestLibvirtConn(t)
	_, poolName, poolPath := vbtcovEnsureTestPool(t, conn, "cvbt-idem-pool")

	// Second ensure on the same pool: the lookup finds it, the target path
	// matches, the pool is already running, and autostart is already enabled —
	// exercising every already-satisfied branch.
	again, err := ensureStoragePool(conn, poolName, poolPath)
	if err != nil {
		t.Fatalf("ensureStoragePool second call: %v", err)
	}
	defer func() { _ = again.Free() }()

	active, err := again.IsActive()
	if err != nil {
		t.Fatalf("check pool active: %v", err)
	}
	if !active {
		t.Fatal("expected pool to remain active")
	}
	autostart, err := again.GetAutostart()
	if err != nil {
		t.Fatalf("get pool autostart: %v", err)
	}
	if !autostart {
		t.Fatal("expected pool autostart to remain enabled")
	}
}

func TestVbtcovStartStoragePoolIfNeededErrors(t *testing.T) {
	conn := newTestLibvirtConn(t)

	t.Run("undefined pool fails activity check", func(t *testing.T) {
		stale := vbtcovStalePoolHandle(t, conn)
		defer func() { _ = stale.Free() }()

		err := startStoragePoolIfNeeded(stale, "cvbt-stale")
		vbtcovRequireErrContains(t, err, "is active", "startStoragePoolIfNeeded on undefined pool")
	})

	t.Run("unusable target path fails start", func(t *testing.T) {
		poolName := uniquePoolName("cvbt-nostart-pool")
		t.Cleanup(func() { cleanupStoragePool(t, poolName) })

		pool, err := conn.StoragePoolDefineXML(storagePoolDefinitionXML(poolName, vbtcovBlockedDirPath(t)), 0)
		if err != nil {
			t.Fatalf("define storage pool %s: %v", poolName, err)
		}
		defer func() { _ = pool.Free() }()

		err = startStoragePoolIfNeeded(pool, poolName)
		vbtcovRequireErrContains(t, err, "start storage pool", "startStoragePoolIfNeeded with file-blocked target path")
	})
}

func TestVbtcovLookupOrDefineStoragePoolLookupError(t *testing.T) {
	conn := vbtcovClosedConn(t)

	_, err := lookupOrDefineStoragePool(conn, uniquePoolName("cvbt-closed-pool"), "/cvbt-unused")
	vbtcovRequireErrContains(t, err, "lookup storage pool", "lookupOrDefineStoragePool on closed connection")
}

func TestVbtcovLookupOrDefineStoragePoolDefineFailure(t *testing.T) {
	conn := newTestLibvirtConn(t)

	// The name survives the not-found lookup but breaks the generated pool XML,
	// so StoragePoolDefineXML must fail.
	badName := fmt.Sprintf("cvbt<bad>-%d", time.Now().UnixNano())
	_, err := lookupOrDefineStoragePool(conn, badName, t.TempDir())
	vbtcovRequireErrContains(t, err, "define storage pool", "lookupOrDefineStoragePool with XML-breaking name")
}

func TestVbtcovReconcileStoragePoolTargetPathStaleHandle(t *testing.T) {
	conn := newTestLibvirtConn(t)
	// reconcileStoragePoolTargetPath frees the handle on this error path.
	stale := vbtcovStalePoolHandle(t, conn)

	_, err := reconcileStoragePoolTargetPath(conn, stale, "cvbt-stale", "/cvbt-unused")
	vbtcovRequireErrContains(t, err, "target path", "reconcileStoragePoolTargetPath on undefined pool")
}

func TestVbtcovReconcileStoragePoolTargetPathRedefineFailure(t *testing.T) {
	conn := newTestLibvirtConn(t)
	poolName := uniquePoolName("cvbt-redef-pool")
	t.Cleanup(func() { cleanupStoragePool(t, poolName) })

	pool, err := conn.StoragePoolDefineXML(storagePoolDefinitionXML(poolName, t.TempDir()), 0)
	if err != nil {
		t.Fatalf("define storage pool %s: %v", poolName, err)
	}

	// The configured path differs from the defined one (forcing the redefine)
	// and breaks the replacement XML, so the redefine must fail. The pool handle
	// is undefined and freed inside reconcileStoragePoolTargetPath.
	badPath := filepath.Join(t.TempDir(), "cvbt<bad>")
	_, err = reconcileStoragePoolTargetPath(conn, pool, poolName, badPath)
	vbtcovRequireErrContains(t, err, "redefine storage pool", "reconcileStoragePoolTargetPath with XML-breaking path")
}

func TestVbtcovStorageVolXMLHelpersStalePool(t *testing.T) {
	conn := newTestLibvirtConn(t)
	stale := vbtcovStalePoolHandle(t, conn)
	defer func() { _ = stale.Free() }()

	_, err := storagePoolTargetPath(stale)
	vbtcovRequireErrContains(t, err, "get storage pool xml", "storagePoolTargetPath on undefined pool")

	_, err = storageVolPathXML(stale, "disk.qcow2")
	vbtcovRequireErrContains(t, err, "get storage pool xml", "storageVolPathXML on undefined pool")

	_, err = storageVolCreateXMLWithSettings(nil, stale, "disk.qcow2", vbtcovTinyCapacity, "qcow2")
	vbtcovRequireErrContains(t, err, "get storage pool xml", "storageVolCreateXMLWithSettings on undefined pool")

	_, err = createQCOW2Volume(nil, stale, "disk.qcow2", vbtcovTinyCapacity)
	vbtcovRequireErrContains(t, err, "get storage pool xml", "createQCOW2Volume on undefined pool")

	// The error branch must return without logging or crashing.
	logStoragePoolTargetPath(stale, "cvbt-stale", "/cvbt-unused")
}

func TestVbtcovLogStoragePoolTargetPathMismatch(t *testing.T) {
	conn := newTestLibvirtConn(t)
	pool, poolName, _ := vbtcovEnsureTestPool(t, conn, "cvbt-logpath-pool")

	// Configured path differs from the pool's real target path: the function
	// only logs, so this just needs to not fail.
	logStoragePoolTargetPath(pool, poolName, "/cvbt-different-path")
}

func TestVbtcovConfigureStoragePoolAutostartTransientPool(t *testing.T) {
	conn := newTestLibvirtConn(t)
	poolName := uniquePoolName("cvbt-transient-pool")

	pool, err := conn.StoragePoolCreateXML(storagePoolDefinitionXML(poolName, t.TempDir()), 0)
	if err != nil {
		t.Fatalf("create transient storage pool %s: %v", poolName, err)
	}
	t.Cleanup(func() { _ = pool.Free() })
	t.Cleanup(func() { _ = pool.Destroy() })

	autostart, err := pool.GetAutostart()
	if err != nil {
		t.Fatalf("get autostart of transient pool: %v", err)
	}
	if autostart {
		t.Fatal("expected transient pool autostart to be false")
	}

	// SetAutostart fails for transient pools ("pool has no config file"); the
	// helper must swallow the failure and only log it.
	configureStoragePoolAutostart(pool, poolName)

	autostart, err = pool.GetAutostart()
	if err != nil {
		t.Fatalf("re-get autostart of transient pool: %v", err)
	}
	if autostart {
		t.Fatal("expected transient pool autostart to remain false")
	}
}

func TestVbtcovCreateQCOW2VolumeDuplicate(t *testing.T) {
	conn := newTestLibvirtConn(t)
	pool, poolName, _ := vbtcovEnsureTestPool(t, conn, "cvbt-dupvol-pool")
	t.Cleanup(func() { _ = RemoveVolumes(conn, poolName, "cvbt-dup-vol") })

	vol, err := createQCOW2Volume(nil, pool, "cvbt-dup-vol", vbtcovTinyCapacity)
	if err != nil {
		t.Fatalf("create first volume: %v", err)
	}
	_ = vol.Free()

	_, err = createQCOW2Volume(nil, pool, "cvbt-dup-vol", vbtcovTinyCapacity)
	vbtcovRequireErrContains(t, err, "create volume", "createQCOW2Volume with duplicate name")
}

func TestVbtcovCopyAndResizeVolumeMissingPool(t *testing.T) {
	conn := newTestLibvirtConn(t)
	source := vbtcovWriteTinyFile(t, "source.img")

	err := CopyAndResizeVolume(conn, uniquePoolName("cvbt-nopool"), "cvbt-vol", source, vbtcovTinyCapacity)
	vbtcovRequireErrContains(t, err, "lookup pool", "CopyAndResizeVolume into missing pool")
}

func TestVbtcovCopyAndResizeVolumeDuplicateVolume(t *testing.T) {
	conn := newTestLibvirtConn(t)
	pool, poolName, _ := vbtcovEnsureTestPool(t, conn, "cvbt-dupcopy-pool")
	t.Cleanup(func() { _ = RemoveVolumes(conn, poolName, "cvbt-dupcopy-vol") })

	vol, err := createQCOW2Volume(nil, pool, "cvbt-dupcopy-vol", vbtcovTinyCapacity)
	if err != nil {
		t.Fatalf("create conflicting volume: %v", err)
	}
	_ = vol.Free()

	source := vbtcovWriteTinyFile(t, "source.img")
	err = CopyAndResizeVolume(conn, poolName, "cvbt-dupcopy-vol", source, vbtcovTinyCapacity)
	vbtcovRequireErrContains(t, err, "create volume", "CopyAndResizeVolume with duplicate volume name")
}

func TestVbtcovRemoveVolumesMissingPool(t *testing.T) {
	conn := newTestLibvirtConn(t)

	err := RemoveVolumes(conn, uniquePoolName("cvbt-nopool"), "cvbt-vol")
	vbtcovRequireErrContains(t, err, "lookup storage pool", "RemoveVolumes from missing pool")
}

func TestVbtcovResizeVolumeIfNeeded(t *testing.T) {
	conn := newTestLibvirtConn(t)
	pool, poolName, _ := vbtcovEnsureTestPool(t, conn, "cvbt-resize-pool")

	t.Run("zero capacity is a no-op", func(t *testing.T) {
		stale := vbtcovStaleVolHandle(t, pool, "cvbt-resize-zero")
		if err := resizeVolumeIfNeeded(stale, 0); err != nil {
			t.Fatalf("resizeVolumeIfNeeded with zero capacity: %v", err)
		}
	})

	t.Run("capacity already sufficient", func(t *testing.T) {
		t.Cleanup(func() { _ = RemoveVolumes(conn, poolName, "cvbt-resize-keep") })
		vol, err := createQCOW2Volume(nil, pool, "cvbt-resize-keep", vbtcovTinyCapacity)
		if err != nil {
			t.Fatalf("create volume: %v", err)
		}
		defer func() { _ = vol.Free() }()

		if err := resizeVolumeIfNeeded(vol, 1); err != nil {
			t.Fatalf("resizeVolumeIfNeeded below existing capacity: %v", err)
		}
	})

	t.Run("deleted volume fails", func(t *testing.T) {
		stale := vbtcovStaleVolHandle(t, pool, "cvbt-resize-gone")
		err := resizeVolumeIfNeeded(stale, 2*vbtcovTinyCapacity)
		vbtcovRequireErrContains(t, err, "get volume info", "resizeVolumeIfNeeded on deleted volume")
	})
}

func TestVbtcovApplyStorageVolPermissionsErrors(t *testing.T) {
	conn := newTestLibvirtConn(t)
	pool, poolName, _ := vbtcovEnsureTestPool(t, conn, "cvbt-perm-pool")

	t.Run("deleted volume fails path lookup", func(t *testing.T) {
		stale := vbtcovStaleVolHandle(t, pool, "cvbt-perm-gone")
		err := applyStorageVolPermissions(nil, stale)
		vbtcovRequireErrContains(t, err, "get volume path", "applyStorageVolPermissions on deleted volume")
	})

	t.Run("missing backing file fails chmod", func(t *testing.T) {
		t.Cleanup(func() { _ = RemoveVolumes(conn, poolName, "cvbt-perm-nofile") })
		vol, err := createQCOW2Volume(nil, pool, "cvbt-perm-nofile", vbtcovTinyCapacity)
		if err != nil {
			t.Fatalf("create volume: %v", err)
		}
		defer func() { _ = vol.Free() }()

		volPath, err := vol.GetPath()
		if err != nil {
			t.Fatalf("get volume path: %v", err)
		}
		if err := os.Remove(volPath); err != nil {
			t.Fatalf("remove backing file %s: %v", volPath, err)
		}

		// ENOENT is not a permission error, so it must not be swallowed.
		err = applyStorageVolPermissions(nil, vol)
		vbtcovRequireErrContains(t, err, "chmod volume", "applyStorageVolPermissions with missing backing file")
	})
}

func TestVbtcovUploadFileToVolumeErrors(t *testing.T) {
	conn := newTestLibvirtConn(t)
	pool, _, _ := vbtcovEnsureTestPool(t, conn, "cvbt-upload-pool")
	source := vbtcovWriteTinyFile(t, "source.img")

	t.Run("closed connection fails stream creation", func(t *testing.T) {
		stale := vbtcovStaleVolHandle(t, pool, "cvbt-upload-closed")
		err := uploadFileToVolume(vbtcovClosedConn(t), stale, source)
		vbtcovRequireErrContains(t, err, "create stream", "uploadFileToVolume on closed connection")
	})

	t.Run("deleted volume fails upload start", func(t *testing.T) {
		stale := vbtcovStaleVolHandle(t, pool, "cvbt-upload-gone")
		err := uploadFileToVolume(conn, stale, source)
		vbtcovRequireErrContains(t, err, "start upload", "uploadFileToVolume into deleted volume")
	})
}

// vbtcovReaderFunc adapts a function to io.Reader for streamReaderChunks tests.
type vbtcovReaderFunc func(p []byte) (int, error)

func (f vbtcovReaderFunc) Read(p []byte) (int, error) { return f(p) }

func TestVbtcovStreamReaderChunks(t *testing.T) {
	readErr := errors.New("cvbt read failure")
	cases := []struct {
		name    string
		src     io.Reader
		nbytes  int
		want    string
		wantErr error
	}{
		{name: "non-positive request", src: strings.NewReader("abc"), nbytes: 0, want: ""},
		{name: "normal read", src: strings.NewReader("abc"), nbytes: 2, want: "ab"},
		{name: "eof without data", src: strings.NewReader(""), nbytes: 4, want: ""},
		{name: "eof with partial data", src: iotest.DataErrReader(strings.NewReader("xy")), nbytes: 4, want: "xy"},
		{name: "read error", src: iotest.ErrReader(readErr), nbytes: 4, wantErr: readErr},
		{
			name:   "zero bytes without error",
			src:    vbtcovReaderFunc(func([]byte) (int, error) { return 0, nil }),
			nbytes: 4,
			want:   "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := streamReaderChunks(tc.src)(nil, tc.nbytes)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("streamReaderChunks error = %v, want %v", err, tc.wantErr)
			}
			if tc.wantErr != nil {
				return
			}
			if string(got) != tc.want {
				t.Fatalf("streamReaderChunks data = %q, want %q", got, tc.want)
			}
		})
	}
}
