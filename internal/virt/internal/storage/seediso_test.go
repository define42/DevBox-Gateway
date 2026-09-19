package storage

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/define42/devbox-gateway/internal/backendidentity"
	"github.com/define42/devbox-gateway/internal/cloudinit"
	yaml "github.com/goccy/go-yaml"
)

func TestCloudInitSeedDataProvisionsPrivateIdentity(t *testing.T) {
	t.Parallel()
	credentials := testBackendCredentials(t)
	userData, _, _, err := cloudInitSeedData("alice", "$6$hash", "desktop", credentials)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := yaml.Marshal(userData)
	if err != nil {
		t.Fatal(err)
	}
	var decoded cloudinit.UserData
	if err := yaml.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	files := make(map[string]cloudinit.WriteFile)
	for _, file := range decoded.WriteFiles {
		files[file.Path] = file
	}
	key := files["/etc/xrdp/devbox-key.pem"]
	if key.Content != credentials.PrivateKeyPEM || key.Owner != "root:xrdp" || key.Permissions != "0640" || !key.Defer {
		t.Fatal("the private key must be deferred, intact, and readable only by root/xrdp")
	}
	if files["/etc/xrdp/devbox-cert.pem"].Content != credentials.CertificatePEM {
		t.Fatal("seed certificate must match the host's trusted certificate")
	}
	commands := strings.Join(decoded.RunCmd, "\n")
	if !strings.Contains(commands, "/usr/local/sbin/devbox-configure-rdp") || strings.Contains(commands, "PRIVATE KEY") {
		t.Fatal("run commands must configure xrdp without embedding private key material")
	}
}

func TestCloudInitSeedDataRejectsMissingOrMismatchedIdentity(t *testing.T) {
	t.Parallel()
	valid := testBackendCredentials(t)
	other := testBackendCredentials(t)
	for _, tc := range []struct {
		name        string
		credentials backendidentity.Credentials
	}{
		{name: "missing identity"},
		{name: "missing private key", credentials: backendidentity.Credentials{CertificatePEM: valid.CertificatePEM, ServerName: valid.ServerName}},
		{name: "mismatched private key", credentials: backendidentity.Credentials{
			CertificatePEM: valid.CertificatePEM, ServerName: valid.ServerName, PrivateKeyPEM: other.PrivateKeyPEM,
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, _, _, err := cloudInitSeedData("alice", "$6$hash", "desktop", tc.credentials); err == nil {
				t.Fatal("must reject invalid identity before creating the seed or contacting libvirt")
			}
		})
	}
}

func TestConfigureRDPScriptPreservesOtherSettings(t *testing.T) {
	t.Parallel()
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 is required to exercise the guest provisioning script")
	}
	path := filepath.Join(t.TempDir(), "xrdp.ini")
	initial := "[Globals]\nCertificate=old.pem\nkey_file=old-key.pem\nsecurity_layer=negotiate\nport=3389\n[Session]\ncertificate=keep.pem\nname=Desktop 100%\n"
	if err := os.WriteFile(path, []byte(initial), 0o600); err != nil {
		t.Fatal(err)
	}
	_, script, _ := strings.Cut(configureRDPScript, "python3 - <<'PY'\n")
	script, _, _ = strings.Cut(script, "\nPY\n")
	script = strings.Replace(script, "Path('/etc/xrdp/xrdp.ini')", "Path(__import__('sys').argv[1])", 1)
	cmd := exec.CommandContext(t.Context(), python, "-", path)
	cmd.Stdin = strings.NewReader(script)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("configure xrdp: %v: %s", err, output)
	}
	result, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(result), "old.pem") || strings.Contains(string(result), "old-key.pem") {
		t.Fatal("old certificate paths must be removed even when the INI option uses mixed case")
	}
	for _, expected := range []string{
		"certificate=/etc/xrdp/devbox-cert.pem", "key_file=/etc/xrdp/devbox-key.pem",
		"security_layer=tls", "ssl_protocols=TLSv1.2, TLSv1.3", "port=3389",
		"[Session]\ncertificate=keep.pem\nname=Desktop 100%",
	} {
		if !strings.Contains(string(result), expected) {
			t.Errorf("configured xrdp is missing %q", expected)
		}
	}
}

func testBackendCredentials(t *testing.T) backendidentity.Credentials {
	t.Helper()
	credentials, err := backendidentity.Generate("alice.desktop")
	if err != nil {
		t.Fatal(err)
	}
	return credentials
}
