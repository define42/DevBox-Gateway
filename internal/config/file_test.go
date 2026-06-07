package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestConfigFilePath(t *testing.T) {
	t.Setenv(ConfigFileEnv, "")
	if got := ConfigFilePath(); got != DefaultConfigFile {
		t.Fatalf("ConfigFilePath() = %q, want default %q", got, DefaultConfigFile)
	}

	t.Setenv(ConfigFileEnv, "  /tmp/custom.env  ")
	if got := ConfigFilePath(); got != "/tmp/custom.env" {
		t.Fatalf("ConfigFilePath() = %q, want %q", got, "/tmp/custom.env")
	}
}

func TestLoadConfigFileMissingIsNoError(t *testing.T) {
	if err := LoadConfigFile(filepath.Join(t.TempDir(), "absent.env")); err != nil {
		t.Fatalf("missing file should not error, got %v", err)
	}
}

func TestLoadConfigFileAppliesValues(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rdp-tls-gateway.conf")
	content := `# sample config
LISTEN_ADDR=:8443
export FRONT_DOMAIN=desktop.example.com
LDAP_USER_FILTER="(mail=%s)"
ACME_EMAIL='ops@example.com'

   # indented comment
RDP_DISABLE_CLIPBOARD=true
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	// Ensure none of the keys are set in the environment for this test.
	for _, k := range []string{LISTEN_ADDR, FRONT_DOMAIN, LDAP_USER_FILTER, ACME_EMAIL, RDP_DISABLE_CLIPBOARD} {
		t.Setenv(k, "")
		_ = os.Unsetenv(k)
	}

	if err := LoadConfigFile(path); err != nil {
		t.Fatalf("LoadConfigFile: %v", err)
	}

	cases := map[string]string{
		LISTEN_ADDR:           ":8443",
		FRONT_DOMAIN:          "desktop.example.com",
		LDAP_USER_FILTER:      "(mail=%s)",
		ACME_EMAIL:            "ops@example.com",
		RDP_DISABLE_CLIPBOARD: "true",
	}
	for k, want := range cases {
		if got := os.Getenv(k); got != want {
			t.Fatalf("env %s = %q, want %q", k, got, want)
		}
	}

	// And the settings layer picks them up.
	settings := NewSettingType(false)
	if got := settings.Get(LISTEN_ADDR); got != ":8443" {
		t.Fatalf("settings LISTEN_ADDR = %q, want :8443", got)
	}
	if !settings.GetBool(RDP_DISABLE_CLIPBOARD) {
		t.Fatalf("settings RDP_DISABLE_CLIPBOARD = false, want true")
	}
}

func TestLoadConfigFileEnvironmentWins(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rdp-tls-gateway.conf")
	if err := os.WriteFile(path, []byte("LISTEN_ADDR=:8443\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	t.Setenv(LISTEN_ADDR, ":9999")
	if err := LoadConfigFile(path); err != nil {
		t.Fatalf("LoadConfigFile: %v", err)
	}
	if got := os.Getenv(LISTEN_ADDR); got != ":9999" {
		t.Fatalf("env LISTEN_ADDR = %q, want :9999 (environment must win over file)", got)
	}
}

func TestLoadConfigFileMalformedLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.env")
	if err := os.WriteFile(path, []byte("LISTEN_ADDR :8443\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if err := LoadConfigFile(path); err == nil {
		t.Fatal("expected error for a line without '='")
	}
}

func TestParseConfigLine(t *testing.T) {
	cases := []struct {
		line    string
		key     string
		value   string
		wantErr bool
	}{
		{"", "", "", false},
		{"   ", "", "", false},
		{"# comment", "", "", false},
		{"  # indented comment", "", "", false},
		{"KEY=value", "KEY", "value", false},
		{"export KEY=value", "KEY", "value", false},
		{`KEY="quoted value"`, "KEY", "quoted value", false},
		{"KEY='quoted value'", "KEY", "quoted value", false},
		{"KEY=  spaced  ", "KEY", "spaced", false},
		{"KEY=", "KEY", "", false},
		{"noequals", "", "", true},
		{"=novalue", "", "", true},
	}
	for _, c := range cases {
		key, value, err := parseConfigLine(c.line)
		if (err != nil) != c.wantErr {
			t.Fatalf("parseConfigLine(%q) err = %v, wantErr %v", c.line, err, c.wantErr)
		}
		if err != nil {
			continue
		}
		if key != c.key || value != c.value {
			t.Fatalf("parseConfigLine(%q) = (%q, %q), want (%q, %q)", c.line, key, value, c.key, c.value)
		}
	}
}
