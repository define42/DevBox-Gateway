package rpm

import (
	"bytes"
	"fmt"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

// binaryDependencies preserves both SONAME and symbol-version requirements
// from the exact packaged binary, including libvirt and glibc. These are RPM
// capabilities rather than distribution-specific library package versions.
func binaryDependencies(binary string) ([]string, error) {
	binary, err := filepath.Abs(binary)
	if err != nil {
		return nil, fmt.Errorf("resolve binary for dependency scan: %w", err)
	}
	scanner, err := exec.LookPath("elfdeps")
	if err != nil {
		// Distribution packages install this helper outside PATH by default.
		scanner = "/usr/lib/rpm/elfdeps"
	}
	// #nosec G204 -- Scanner is only elfdeps from the build PATH or the fixed fallback; the absolute binary path is one argument, with no shell.
	cmd := exec.Command(scanner, "--requires", binary)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("scan binary dependencies with elfdeps (install rpm-build in the build distribution): %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return parseBinaryDependencies(string(output))
}

func parseBinaryDependencies(output string) ([]string, error) {
	output = strings.TrimSpace(output)
	if output == "" {
		return nil, fmt.Errorf("elfdeps returned no binary dependencies")
	}
	// elfdeps emits SONAME capabilities with optional symbol and architecture
	// suffixes, plus the runtime linker's GNU hash capability.
	capability := regexp.MustCompile(`^(?:[A-Za-z0-9_+.-]+\.so(?:\.[A-Za-z0-9_+.-]+)*(?:\([A-Za-z0-9_.+:-]*\))*|rtld\(GNU_HASH\))$`)
	dependencies := strings.Split(output, "\n")
	for i, dependency := range dependencies {
		dependency = strings.TrimSpace(dependency)
		if !capability.MatchString(dependency) {
			return nil, fmt.Errorf("elfdeps returned invalid dependency %q", dependency)
		}
		dependencies[i] = dependency
	}
	return dependencies, nil
}
