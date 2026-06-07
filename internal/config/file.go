package config

import (
	"bufio"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"
)

// ConfigFileEnv is the environment variable naming the config file path. It is a
// bootstrap-only variable: it locates the file that supplies every other
// setting.
const ConfigFileEnv = "CONFIG_FILE"

// DefaultConfigFile is the config file the gateway reads when CONFIG_FILE is
// unset. It matches the path the RPM installs and the systemd unit references.
const DefaultConfigFile = "/etc/rdp-tls-gateway/rdp-tls-gateway.conf"

// ConfigFilePath returns the config file path, honoring the CONFIG_FILE
// environment variable and falling back to DefaultConfigFile.
func ConfigFilePath() string {
	if p := strings.TrimSpace(os.Getenv(ConfigFileEnv)); p != "" {
		return p
	}
	return DefaultConfigFile
}

// LoadConfigFile reads KEY=VALUE pairs from path and applies them to the process
// environment for keys that are not already set, so an explicit environment
// variable always takes precedence over the file. A missing file is not an
// error: the gateway then runs purely on environment variables and built-in
// defaults, which keeps container and development workflows working unchanged.
//
// The format matches a systemd EnvironmentFile / shell-style ".env": blank lines
// and lines beginning with '#' are ignored, an optional leading "export " is
// stripped, and a value may be wrapped in matching single or double quotes.
//
// Call this before NewSettingType so the parsed values feed the normal
// environment-backed setting resolution.
func LoadConfigFile(path string) error {
	f, err := os.Open(path) //nolint:gosec // path is an operator-provided config file location.
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return err
	}
	defer func() { _ = f.Close() }()

	scanner := bufio.NewScanner(f)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		key, value, err := parseConfigLine(scanner.Text())
		if err != nil {
			return fmt.Errorf("%s:%d: %w", path, lineNo, err)
		}
		if key == "" {
			continue // blank or comment line
		}
		if _, ok := os.LookupEnv(key); ok {
			continue // an explicit environment variable wins over the file
		}
		if err := os.Setenv(key, value); err != nil {
			return fmt.Errorf("%s:%d: set %s: %w", path, lineNo, key, err)
		}
	}
	return scanner.Err()
}

// parseConfigLine parses a single KEY=VALUE config line. It returns an empty key
// for blank and comment lines. A leading "export " and matching surrounding
// quotes on the value are removed.
func parseConfigLine(line string) (key, value string, err error) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || strings.HasPrefix(trimmed, "#") {
		return "", "", nil
	}
	trimmed = strings.TrimPrefix(trimmed, "export ")

	eq := strings.IndexByte(trimmed, '=')
	if eq < 0 {
		return "", "", fmt.Errorf("missing '=' in %q", line)
	}
	key = strings.TrimSpace(trimmed[:eq])
	if key == "" {
		return "", "", fmt.Errorf("empty key in %q", line)
	}
	value = unquote(strings.TrimSpace(trimmed[eq+1:]))
	return key, value, nil
}

// unquote removes a single pair of matching surrounding single or double quotes.
func unquote(v string) string {
	if len(v) >= 2 {
		first, last := v[0], v[len(v)-1]
		if (first == '"' && last == '"') || (first == '\'' && last == '\'') {
			return v[1 : len(v)-1]
		}
	}
	return v
}
