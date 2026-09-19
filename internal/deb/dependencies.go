package deb

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

// binaryDependencies uses the build distribution's symbols database to find
// minimum package versions for the exact binary being packaged. Running in a
// private directory avoids consuming any unrelated debian/ metadata in the
// caller's checkout. The generic WritePackage remains usable for static tools.
func binaryDependencies(binary string) (string, error) {
	binary, err := filepath.Abs(binary)
	if err != nil {
		return "", fmt.Errorf("resolve binary for dependency scan: %w", err)
	}
	dir, err := os.MkdirTemp("", "devbox-deb-deps-")
	if err != nil {
		return "", fmt.Errorf("create dependency scan directory: %w", err)
	}
	defer os.RemoveAll(dir)
	if err := prepareDependencyControl(dir); err != nil {
		return "", err
	}
	staged, err := stageDependencyBinary(dir, binary)
	if err != nil {
		return "", err
	}
	cmd := exec.Command("dpkg-shlibdeps", "--warnings=1", "-O", "-e"+staged)
	cmd.Dir = dir
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("scan binary dependencies with dpkg-shlibdeps (install dpkg-dev in the build distribution): %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	// An executable linked against newer libraries can produce only a warning
	// for unresolved symbols and still exit successfully with weaker Depends.
	// Enable that warning and fail closed, regardless of the diagnostic locale.
	if stderr.Len() != 0 {
		return "", fmt.Errorf("dpkg-shlibdeps could not verify all binary dependencies: %s", strings.TrimSpace(stderr.String()))
	}
	return parseBinaryDependencies(string(output))
}

func prepareDependencyControl(dir string) error {
	debianDir := filepath.Join(dir, "debian")
	if err := os.Mkdir(debianDir, 0o750); err != nil {
		return fmt.Errorf("create dependency control directory: %w", err)
	}
	const control = "Source: devbox-gateway\nSection: net\nPriority: optional\nMaintainer: " + Maintainer + "\n\nPackage: devbox-gateway\nArchitecture: any\nDescription: DevBox Gateway dependency scan\n"
	if err := os.WriteFile(filepath.Join(debianDir, "control"), []byte(control), 0o600); err != nil {
		return fmt.Errorf("write dependency control: %w", err)
	}
	return nil
}

func stageDependencyBinary(dir, binary string) (string, error) {
	root := filepath.Join(dir, "debian", packageName)
	binDir := filepath.Join(root, "usr", "bin")
	for _, path := range []string{binDir, filepath.Join(root, "DEBIAN")} {
		if err := os.MkdirAll(path, 0o750); err != nil {
			return "", fmt.Errorf("create dependency scan package directory: %w", err)
		}
	}
	// dpkg-shlibdeps expects an installed package tree marked by DEBIAN/.
	// A symlink scans the exact source artifact without copying a large binary.
	staged := filepath.Join(binDir, packageName)
	if err := os.Symlink(binary, staged); err != nil {
		return "", fmt.Errorf("stage binary for dependency scan: %w", err)
	}
	return staged, nil
}

func parseBinaryDependencies(output string) (string, error) {
	depends, ok := strings.CutPrefix(strings.TrimSpace(output), "shlibs:Depends=")
	if !ok || strings.TrimSpace(depends) == "" || strings.ContainsAny(depends, "\r\n") {
		return "", fmt.Errorf("dpkg-shlibdeps returned missing or malformed dependencies: %q", output)
	}
	// shlibdeps produces package relations, optionally versioned or alternative.
	// Validate every relation before copying external output to the control file.
	relation := regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]*(?::[a-z0-9-]+)?(?: \((?:<<|<=|=|>=|>>) [0-9][A-Za-z0-9.+:~\-]*\))?$`)
	for dependency := range strings.SplitSeq(depends, ",") {
		for alternative := range strings.SplitSeq(dependency, "|") {
			if !relation.MatchString(strings.TrimSpace(alternative)) {
				return "", fmt.Errorf("dpkg-shlibdeps returned invalid dependency %q", alternative)
			}
		}
	}
	return depends, nil
}
