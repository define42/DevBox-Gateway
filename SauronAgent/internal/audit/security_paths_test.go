package audit

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"slices"
	"strings"
	"testing"
	"testing/fstest"

	"golang.org/x/sys/unix"
)

func TestSecurityPathSpecsCoverRequestedPaths(t *testing.T) {
	t.Parallel()
	groups := map[string][]string{
		"privilege_config":      {"/etc/sudoers", "/etc/sudoers.d", "/etc/polkit-1"},
		"authentication_config": {"/etc/pam.d", "/etc/security"},
		"ssh_config":            {"/etc/ssh/sshd_config", "/etc/ssh/sshd_config.d"},
		"privilege_use":         {"/usr/bin/sudo", "/usr/bin/su", "/usr/bin/pkexec", "/usr/bin/systemd-run"},
		"persistence":           {"/etc/systemd/system", "/usr/lib/systemd/system", "/etc/cron.d", "/var/spool/cron", "/etc/crontab", "/etc/rc.local", "/etc/ld.so.preload", "/etc/profile.d"},
		"kernel_config":         {"/etc/modprobe.d", "/etc/modules-load.d", "/etc/sysctl.d", "/etc/sysctl.conf"},
		"boot_config":           {"/etc/default", "/etc/grub.d"},
		"mac_policy":            {"/etc/selinux", "/etc/apparmor.d"},
		"crypto_policy":         {"/etc/crypto-policies"},
		"firewall":              {"/etc/firewalld", "/etc/nftables.conf"},
		"network_config":        {"/etc/hosts", "/etc/resolv.conf", "/etc/NetworkManager", "/etc/systemd/network"},
		"time_change":           {"/etc/localtime"},
		"time_config":           {"/etc/chrony.conf", "/etc/chrony.d"},
		"filesystem_config":     {"/etc/fstab"},
	}
	specs := securityPathSpecs()
	for key, paths := range groups {
		for _, path := range paths {
			t.Run(path, func(t *testing.T) {
				i := slices.IndexFunc(specs, func(s securityPathSpec) bool { return s.path == path && s.key == key })
				if i < 0 {
					t.Fatalf("no %s rule for %s", key, path)
				}
				want := uint32(unix.AUDIT_PERM_WRITE | unix.AUDIT_PERM_ATTR)
				if key == "privilege_use" {
					want = unix.AUDIT_PERM_EXEC
				}
				if specs[i].permissions != want {
					t.Fatalf("permissions=%d, want %d", specs[i].permissions, want)
				}
			})
		}
	}
}

func TestPathWatchRuleUsesDirectoryTreeAndExecutionPermissions(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, path, key    string
		directory          bool
		permissions, field uint32
	}{
		{name: "directory", path: "/etc/pam.d", key: "authentication_config", directory: true, permissions: unix.AUDIT_PERM_WRITE | unix.AUDIT_PERM_ATTR, field: unix.AUDIT_DIR},
		{name: "tool execution", path: "/usr/bin/sudo", key: "privilege_use", permissions: unix.AUDIT_PERM_EXEC, field: unix.AUDIT_WATCH},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rule := pathWatchRule(tc.path, tc.key, tc.permissions, tc.directory)
			payload, err := marshalKernelRule(rule)
			if err != nil {
				t.Fatal(err)
			}
			got, err := parseKernelRule(payload)
			if err != nil {
				t.Fatal(err)
			}
			if got.Fields[0] != tc.field || got.Values[1] != tc.permissions || got.buffer != tc.path+tc.key || !allSyscalls(got.Mask) {
				t.Fatalf("wrong directory/permission encoding: %+v", got)
			}
		})
	}
}

func discoveryFixture(data fstest.MapFS) policyDiscoveryFiles {
	return policyDiscoveryFiles{
		stat:    func(path string) (fs.FileInfo, error) { return fs.Stat(data, strings.TrimPrefix(path, "/")) },
		open:    func(path string) (io.ReadCloser, error) { return data.Open(strings.TrimPrefix(path, "/")) },
		resolve: func(path string) (string, error) { return path, nil },
	}
}

func TestDiscoverSecurityPathsFindsCustomAndRootHomes(t *testing.T) {
	t.Parallel()
	files := discoveryFixture(fstest.MapFS{
		"etc/passwd":           {Data: []byte("alice:x:1000:1000::/srv/users/alice:/bin/sh\nalias:x:1001:1001::/srv/users/alice:/bin/sh\nservice:x:999:999::/nonexistent:/sbin/nologin\n")},
		"srv/users/alice/.ssh": {Mode: fs.ModeDir | 0700},
		"root/.ssh":            {Mode: fs.ModeDir | 0700},
		"etc/pam.d":            {Mode: fs.ModeDir | 0755},
	})
	got, err := discoverSecurityPathRules(t.Context(), files)
	if err != nil {
		t.Fatal(err)
	}
	if got.sshDirectories != 2 || got.missingSSHDirectories != 1 {
		t.Fatalf("ssh=%d missing=%d", got.sshDirectories, got.missingSSHDirectories)
	}
	for _, path := range []string{"/srv/users/alice/.ssh", "/root/.ssh", "/etc/pam.d"} {
		if !slices.ContainsFunc(got.rules, func(r auditRule) bool { return r.Fields[0] == unix.AUDIT_DIR && strings.HasPrefix(r.buffer, path) }) {
			t.Errorf("missing directory rule for %s", path)
		}
	}
	if !slices.Contains(got.skippedPaths, "/etc/ssh/sshd_config.d") {
		t.Error("absent optional directory not reported")
	}
	if !slices.Contains(got.pendingFiles, "/etc/ld.so.preload") {
		t.Error("absent persistence file not watched for future creation")
	}
}

func TestDiscoveryWatchesSymlinkNamesAndTargets(t *testing.T) {
	t.Parallel()
	files := discoveryFixture(fstest.MapFS{
		"etc/resolv.conf":          {Data: []byte("not read")},
		"run/resolved/resolv.conf": {Data: []byte("not read")},
		"home/alice/.ssh":          {Mode: fs.ModeDir | 0700},
		"srv/ssh/alice":            {Mode: fs.ModeDir | 0700},
	})
	files.resolve = func(path string) (string, error) {
		if path == "/etc/resolv.conf" {
			return "/run/resolved/resolv.conf", nil
		}
		if path == "/home/alice/.ssh" {
			return "/srv/ssh/alice", nil
		}
		return path, nil
	}
	var result pathRuleDiscovery
	seen := make(map[securityPathSpec]bool)
	for _, spec := range []securityPathSpec{
		{path: "/etc/resolv.conf", key: "network_config", permissions: unix.AUDIT_PERM_WRITE},
		{path: "/run/resolved/resolv.conf", key: "network_config", permissions: unix.AUDIT_PERM_WRITE},
		{path: "/home/alice/.ssh", key: "ssh_keys", permissions: unix.AUDIT_PERM_WRITE, directory: true},
	} {
		if _, err := result.addPath(files, spec, seen); err != nil {
			t.Fatal(err)
		}
	}
	if len(result.rules) != 3 {
		t.Fatalf("rules=%d, want filename, deduplicated target, and canonical directory", len(result.rules))
	}
	if result.rules[2].buffer != "/srv/ssh/alice"+"ssh_keys" || result.rules[2].Fields[0] != unix.AUDIT_DIR {
		t.Fatal("SSH directory did not resolve to a recursive target watch")
	}
}

func TestDiscoveryFailsOnInaccessibleOrInvalidPaths(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name      string
		statErr   error
		directory bool
		mode      fs.FileMode
		resolved  string
		want      string
	}{
		{name: "inaccessible", statErr: fs.ErrPermission, want: "CAP_DAC_READ_SEARCH"},
		{name: "directory instead of file", mode: fs.ModeDir, want: "wrong file type"},
		{name: "file instead of directory", directory: true, want: "wrong file type"},
		{name: "symlink to root", directory: true, mode: fs.ModeDir, resolved: "/", want: "invalid watch target"},
		{name: "symlink error", resolved: "error", want: "inspecting managed path"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			files := discoveryFixture(fstest.MapFS{"watched": {Mode: tc.mode}})
			if tc.statErr != nil {
				files.stat = func(string) (fs.FileInfo, error) { return nil, tc.statErr }
			}
			files.resolve = func(string) (string, error) {
				if tc.resolved == "error" {
					return "", unix.ELOOP
				}
				return tc.resolved, nil
			}
			var result pathRuleDiscovery
			_, err := result.addPath(files, securityPathSpec{path: "/watched", key: "test", directory: tc.directory}, make(map[securityPathSpec]bool))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error=%v, want %s", err, tc.want)
			}
		})
	}
}

func TestLocalAccountHomesValidatesAndBoundsInput(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ name, data, want string }{
		{name: "malformed entry", data: "not an account", want: "malformed"},
		{name: "relative home", data: "alice:x:1:1::relative:/bin/sh", want: "invalid home"},
		{name: "NUL home", data: "alice:x:1:1::/home/ali\x00ce:/bin/sh", want: "invalid home"},
		{name: "too much data", data: strings.Repeat("x", maxPasswdBytes+1), want: "size limit"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := localAccountHomes(t.Context(), discoveryFixture(fstest.MapFS{"etc/passwd": {Data: []byte(tc.data)}}))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error=%v, want %s", err, tc.want)
			}
		})
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := localAccountHomes(ctx, policyDiscoveryFiles{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled discovery=%v", err)
	}
	if _, err := localAccountHomes(t.Context(), discoveryFixture(fstest.MapFS{})); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("missing passwd=%v", err)
	}
}
