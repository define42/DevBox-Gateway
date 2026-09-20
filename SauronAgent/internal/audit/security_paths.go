package audit

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"golang.org/x/sys/unix"
)

const (
	maxPasswdBytes    = 4 << 20
	maxSSHDirectories = 4096
)

type securityPathSpec struct {
	path        string
	key         string
	permissions uint32
	directory   bool
}

// These paths are part of the executable's policy, not an external rules file.
func securityPathSpecs() []securityPathSpec {
	const wa = unix.AUDIT_PERM_WRITE | unix.AUDIT_PERM_ATTR
	return []securityPathSpec{
		{path: "/etc/sudoers", key: "privilege_config", permissions: wa},
		{path: "/etc/sudoers.d", key: "privilege_config", permissions: wa, directory: true},
		{path: "/etc/pam.d", key: "authentication_config", permissions: wa, directory: true},
		{path: "/etc/security", key: "authentication_config", permissions: wa, directory: true},
		{path: "/etc/ssh/sshd_config", key: "ssh_config", permissions: wa},
		{path: "/etc/ssh/sshd_config.d", key: "ssh_config", permissions: wa, directory: true},
		{path: "/etc/polkit-1", key: "privilege_config", permissions: wa, directory: true},
		{path: "/usr/bin/sudo", key: "privilege_use", permissions: unix.AUDIT_PERM_EXEC},
		{path: "/usr/bin/su", key: "privilege_use", permissions: unix.AUDIT_PERM_EXEC},
		{path: "/usr/bin/pkexec", key: "privilege_use", permissions: unix.AUDIT_PERM_EXEC},
		{path: "/usr/bin/systemd-run", key: "privilege_use", permissions: unix.AUDIT_PERM_EXEC},
		{path: "/etc/systemd/system", key: "persistence", permissions: wa, directory: true},
		{path: "/usr/lib/systemd/system", key: "persistence", permissions: wa, directory: true},
		{path: "/etc/cron.d", key: "persistence", permissions: wa, directory: true},
		{path: "/var/spool/cron", key: "persistence", permissions: wa, directory: true},
		{path: "/etc/crontab", key: "persistence", permissions: wa},
		{path: "/etc/rc.local", key: "persistence", permissions: wa},
		{path: "/etc/ld.so.preload", key: "persistence", permissions: wa},
		{path: "/etc/profile.d", key: "persistence", permissions: wa, directory: true},
		{path: "/etc/modprobe.d", key: "kernel_config", permissions: wa, directory: true},
		{path: "/etc/modules-load.d", key: "kernel_config", permissions: wa, directory: true},
		{path: "/etc/default", key: "boot_config", permissions: wa, directory: true},
		{path: "/etc/grub.d", key: "boot_config", permissions: wa, directory: true},
		{path: "/etc/selinux", key: "mac_policy", permissions: wa, directory: true},
		{path: "/etc/apparmor.d", key: "mac_policy", permissions: wa, directory: true},
		{path: "/etc/crypto-policies", key: "crypto_policy", permissions: wa, directory: true},
		{path: "/etc/firewalld", key: "firewall", permissions: wa, directory: true},
		{path: "/etc/nftables.conf", key: "firewall", permissions: wa},
		{path: "/etc/sysctl.d", key: "kernel_config", permissions: wa, directory: true},
		{path: "/etc/sysctl.conf", key: "kernel_config", permissions: wa},
		{path: "/etc/hosts", key: "network_config", permissions: wa},
		{path: "/etc/resolv.conf", key: "network_config", permissions: wa},
		{path: "/etc/NetworkManager", key: "network_config", permissions: wa, directory: true},
		{path: "/etc/systemd/network", key: "network_config", permissions: wa, directory: true},
		{path: "/etc/localtime", key: "time_change", permissions: wa},
		{path: "/etc/chrony.conf", key: "time_config", permissions: wa},
		{path: "/etc/chrony.d", key: "time_config", permissions: wa, directory: true},
		{path: "/etc/fstab", key: "filesystem_config", permissions: wa},
	}
}

// Permission watches use the kernel's syscall classes for every ABI. Directory
// trees require AUDIT_DIR; AUDIT_WATCH alone does not recurse into a directory.
func pathWatchRule(path, key string, permissions uint32, directory bool) auditRule {
	rule := fileWatchRule(path, key)
	rule.Values[1] = permissions
	if directory {
		rule.Fields[0] = unix.AUDIT_DIR
	}
	return rule
}

// Only account metadata and path metadata are read. SSH keys, credentials, and
// the contents of the watched files are never opened by discovery.
type policyDiscoveryFiles struct {
	stat    func(string) (fs.FileInfo, error)
	open    func(string) (io.ReadCloser, error)
	resolve func(string) (string, error)
}

func systemPolicyDiscoveryFiles() policyDiscoveryFiles {
	return policyDiscoveryFiles{
		stat:    os.Stat,
		open:    func(path string) (io.ReadCloser, error) { return os.Open(path) },
		resolve: filepath.EvalSymlinks,
	}
}

type pathRuleDiscovery struct {
	rules                 []auditRule
	skippedPaths          []string
	pendingFiles          []string
	sshDirectories        int
	missingSSHDirectories int
}

func discoverSecurityPathRules(ctx context.Context, files policyDiscoveryFiles) (pathRuleDiscovery, error) {
	var result pathRuleDiscovery
	seen := make(map[securityPathSpec]bool)
	for _, spec := range securityPathSpecs() {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		if _, err := result.addPath(files, spec, seen); err != nil {
			return result, err
		}
	}
	homes, err := localAccountHomes(ctx, files)
	if err != nil {
		return result, err
	}
	for _, home := range homes {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		if result.sshDirectories >= maxSSHDirectories {
			return result, fmt.Errorf("audit: SSH directory discovery exceeds the %d-directory startup limit", maxSSHDirectories)
		}
		spec := securityPathSpec{
			path: filepath.Join(home, ".ssh"), key: "ssh_keys",
			permissions: unix.AUDIT_PERM_WRITE | unix.AUDIT_PERM_ATTR, directory: true,
		}
		present, err := result.addPath(files, spec, seen)
		if err != nil {
			return result, err
		}
		if present {
			result.sshDirectories++
		} else {
			result.missingSSHDirectories++
		}
	}
	return result, nil
}

func (r *pathRuleDiscovery) addPath(files policyDiscoveryFiles, spec securityPathSpec, seen map[securityPathSpec]bool) (bool, error) {
	info, err := files.stat(spec.path)
	if errors.Is(err, fs.ErrNotExist) {
		if !spec.directory {
			// Linux audit watches track the final filename through its parent,
			// including creation of an absent file such as /etc/ld.so.preload.
			parent, parentErr := files.stat(filepath.Dir(spec.path))
			if parentErr == nil && parent.IsDir() {
				r.appendPath(spec, seen)
				r.pendingFiles = append(r.pendingFiles, spec.path)
				return true, nil
			}
			if parentErr != nil && !errors.Is(parentErr, fs.ErrNotExist) {
				return false, pathDiscoveryError(spec.path, parentErr)
			}
			if parentErr == nil {
				return false, fmt.Errorf("audit: parent of managed path %q is not a directory", spec.path)
			}
		}
		if spec.key != "ssh_keys" {
			r.skippedPaths = append(r.skippedPaths, spec.path)
		}
		return false, nil
	}
	if err != nil {
		return false, pathDiscoveryError(spec.path, err)
	}
	if info.IsDir() != spec.directory || !spec.directory && !info.Mode().IsRegular() {
		return false, fmt.Errorf("audit: managed path %q has the wrong file type (directory=%t)", spec.path, spec.directory)
	}
	resolved, err := files.resolve(spec.path)
	if err != nil {
		return false, pathDiscoveryError(spec.path, err)
	}
	resolved = filepath.Clean(resolved)
	if !filepath.IsAbs(resolved) || resolved == "/" || strings.ContainsRune(resolved, '\x00') {
		return false, fmt.Errorf("audit: managed path %q resolves to an invalid watch target", spec.path)
	}
	if !spec.directory {
		// Watch both the configured filename (replacement of a symlink) and
		// its target (writes through the link, e.g. systemd-resolved output).
		r.appendPath(spec, seen)
	}
	spec.path = resolved
	r.appendPath(spec, seen)
	return true, nil
}

func (r *pathRuleDiscovery) appendPath(spec securityPathSpec, seen map[securityPathSpec]bool) {
	if seen[spec] {
		return
	}
	seen[spec] = true
	r.rules = append(r.rules, pathWatchRule(spec.path, spec.key, spec.permissions, spec.directory))
}

func pathDiscoveryError(path string, err error) error {
	if errors.Is(err, fs.ErrPermission) {
		return fmt.Errorf("audit: inspecting managed path %q: %w (private home directories require CAP_DAC_READ_SEARCH and ProtectHome=read-only)", path, err)
	}
	return fmt.Errorf("audit: inspecting managed path %q: %w", path, err)
}

func localAccountHomes(ctx context.Context, files policyDiscoveryFiles) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	f, err := files.open("/etc/passwd")
	if err != nil {
		return nil, fmt.Errorf("audit: discovering SSH home directories from /etc/passwd: %w", err)
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxPasswdBytes+1))
	if err != nil {
		return nil, fmt.Errorf("audit: reading /etc/passwd for SSH directory discovery: %w", err)
	}
	if len(data) > maxPasswdBytes {
		return nil, errors.New("audit: /etc/passwd exceeds the SSH directory discovery size limit")
	}
	homes := map[string]bool{"/root": true}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	line := 0
	for scanner.Scan() {
		line++
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		entry := scanner.Text()
		if entry == "" || strings.HasPrefix(entry, "#") {
			continue
		}
		fields := strings.Split(entry, ":")
		if len(fields) != 7 {
			return nil, fmt.Errorf("audit: malformed /etc/passwd entry at line %d", line)
		}
		if fields[5] == "" {
			continue
		}
		if !filepath.IsAbs(fields[5]) || strings.ContainsRune(fields[5], '\x00') {
			return nil, fmt.Errorf("audit: invalid home directory in /etc/passwd at line %d", line)
		}
		homes[filepath.Clean(fields[5])] = true
		if len(homes) > maxSSHDirectories {
			return nil, fmt.Errorf("audit: /etc/passwd exceeds the %d-home startup limit", maxSSHDirectories)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("audit: scanning /etc/passwd: %w", err)
	}
	paths := make([]string, 0, len(homes))
	for home := range homes {
		paths = append(paths, home)
	}
	slices.Sort(paths)
	return paths, nil
}
