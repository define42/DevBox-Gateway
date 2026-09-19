package sauronpkg

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/define42/devbox-gateway/internal/deb"
	"github.com/define42/devbox-gateway/internal/rpm"
	"github.com/google/rpmpack"
)

// stageTree writes a fake SauronAgent tree holding every manifest input, with
// the prebuilt binaries in <root>/bin as SauronAgent's `make build` leaves them.
func stageTree(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for _, f := range manifest(Options{Source: root}, "/unused") {
		if err := os.MkdirAll(filepath.Dir(f.source), 0o750); err != nil {
			t.Fatalf("mkdir for %s: %v", f.source, err)
		}
		if err := os.WriteFile(f.source, []byte("content of "+filepath.Base(f.source)), 0o600); err != nil {
			t.Fatalf("seed %s: %v", f.source, err)
		}
	}
	return root
}

// Every non-binary input must exist in the SauronAgent tree checked into this
// repository, so a rename upstream fails here instead of in the release job.
func TestManifestSourcesExistInSauronAgentTree(t *testing.T) {
	source := filepath.Join("..", "..", "SauronAgent")
	for _, f := range manifest(Options{Source: source}, "/unused") {
		if strings.HasPrefix(f.source, filepath.Join(source, "bin")+string(filepath.Separator)) {
			continue // built by `make sauron-build`, not checked in
		}
		info, err := os.Stat(f.source)
		if err != nil {
			t.Errorf("manifest input missing: %v", err)
			continue
		}
		if !info.Mode().IsRegular() {
			t.Errorf("manifest input %s is not a regular file", f.source)
		}
	}
}

// The layout must match SauronAgent's `make install PREFIX=/usr`: the units'
// ExecStart= and Documentation= lines and the docs' instructions all assume it.
func TestManifestMatchesMakeInstallLayout(t *testing.T) {
	want := map[string]struct {
		mode uint32
		kind kind
	}{
		"/usr/bin/sauronagent":                        {0o755, plainFile},
		"/usr/bin/sauronhost":                         {0o755, plainFile},
		"/usr/lib/systemd/system/sauronagent.service": {0o644, plainFile},
		"/usr/lib/systemd/system/sauronhost.service":  {0o644, plainFile},
		"/usr/lib/sysusers.d/sauronagent.conf":        {0o644, plainFile},
		"/usr/lib/tmpfiles.d/sauronagent.conf":        {0o644, plainFile},
		"/etc/sauronhost/sauronhost.yaml.example":     {0o644, configFile},
		"/usr/share/doc/sauronagent/README.md":        {0o644, docFile},
		"/usr/share/doc/sauronagent/protocol.md":      {0o644, docFile},
		"/usr/share/doc/sauronagent/security.md":      {0o644, docFile},
		"/usr/share/doc/sauronagent/deployment.md":    {0o644, docFile},
		"/usr/share/doc/sauronagent/qemu-vsock.md":    {0o644, docFile},
		"/usr/share/licenses/sauronagent/LICENSE":     {0o644, licenseFile},
	}
	files := manifest(Options{Source: "SauronAgent"}, rpmLicenseDest)
	if len(files) != len(want) {
		t.Fatalf("manifest has %d files, want %d", len(files), len(want))
	}
	for _, f := range files {
		w, ok := want[f.destination]
		if !ok {
			t.Errorf("unexpected manifest destination %q", f.destination)
			continue
		}
		if f.mode != w.mode || f.kind != w.kind {
			t.Errorf("%s = mode %#o kind %d, want mode %#o kind %d", f.destination, f.mode, f.kind, w.mode, w.kind)
		}
	}
	if files[0].destination != "/usr/bin/sauronagent" {
		t.Errorf("first manifest entry must be a binary (its mtime stamps the rpm), got %q", files[0].destination)
	}
}

func TestBinDirOverride(t *testing.T) {
	files := manifest(Options{Source: "src", BinDir: "prebuilt"}, rpmLicenseDest)
	if files[0].source != filepath.Join("prebuilt", "sauronagent") || files[1].source != filepath.Join("prebuilt", "sauronhost") {
		t.Fatalf("binaries not taken from BinDir: %q, %q", files[0].source, files[1].source)
	}
}

func TestRPMDescription(t *testing.T) {
	p := RPM(Options{Version: "1.2.3", Release: "4", Source: "SauronAgent"})
	if p.Arch != rpm.Arch(runtime.GOARCH) {
		t.Errorf("default arch = %q, want %q", p.Arch, rpm.Arch(runtime.GOARCH))
	}
	if want := "dist/sauronagent-1.2.3-4." + p.Arch + ".rpm"; p.Output != want {
		t.Errorf("default output = %q, want %q", p.Output, want)
	}
	if p.Name != Name || p.License != licenseTag || len(p.Requires) != 0 {
		t.Errorf("metadata = name %q license %q requires %v", p.Name, p.License, p.Requires)
	}
	types := map[string]rpmpack.FileType{}
	for _, f := range p.Files {
		types[f.Destination] = f.Type
	}
	if got := types["/etc/sauronhost/sauronhost.yaml.example"]; got != rpmpack.ConfigFile|rpmpack.NoReplaceFile {
		t.Errorf("example config type = %v, want %%config(noreplace)", got)
	}
	if _, ok := types["/etc/audit/rules.d/sauron.rules"]; ok {
		t.Error("audit rules must be configured by the agent, not packaged as a file")
	}
	if got := types["/usr/share/doc/sauronagent/README.md"]; got != rpmpack.DocFile {
		t.Errorf("README type = %v, want %%doc", got)
	}
	if got := types[rpmLicenseDest]; got != rpmpack.LicenceFile {
		t.Errorf("LICENSE type = %v, want %%license", got)
	}
	if got := types["/usr/bin/sauronagent"]; got != rpmpack.GenericFile {
		t.Errorf("binary type = %v, want generic", got)
	}

	explicit := RPM(Options{Version: "1", Release: "1", Arch: "aarch64", Output: "x.rpm"})
	if explicit.Arch != "aarch64" || explicit.Output != "x.rpm" {
		t.Errorf("explicit arch/output ignored: %q %q", explicit.Arch, explicit.Output)
	}
}

func TestDebDescription(t *testing.T) {
	p := Deb(Options{Version: "1.2.3", Source: "SauronAgent"})
	if p.Arch != deb.Arch(runtime.GOARCH) {
		t.Errorf("default arch = %q, want %q", p.Arch, deb.Arch(runtime.GOARCH))
	}
	if want := "dist/sauronagent_1.2.3_" + p.Arch + ".deb"; p.Output != want {
		t.Errorf("default output = %q, want %q", p.Output, want)
	}
	if p.Depends != "" {
		t.Errorf("static binaries need no Depends, got %q", p.Depends)
	}
	var conffiles []string
	var copyright bool
	for _, f := range p.Files {
		if f.Conffile {
			conffiles = append(conffiles, f.Destination)
		}
		copyright = copyright || f.Destination == debLicenseDest
	}
	if strings.Join(conffiles, " ") != "/etc/sauronhost/sauronhost.yaml.example" {
		t.Errorf("conffiles = %v", conffiles)
	}
	if !copyright {
		t.Errorf("license must be installed as %s", debLicenseDest)
	}

	explicit := Deb(Options{Version: "1", Arch: "arm64", Output: "x.deb"})
	if explicit.Arch != "arm64" || explicit.Output != "x.deb" {
		t.Errorf("explicit arch/output ignored: %q %q", explicit.Arch, explicit.Output)
	}
}

// The package holds both a guest agent and a hypervisor collector, so no
// scriptlet may enable or start a unit on its own: only the operator knows
// which of the two this machine runs.
func TestScriptsNeverEnableUnits(t *testing.T) {
	for name, script := range map[string]string{
		"rpm %post": rpmPostin, "rpm %preun": rpmPreun, "rpm %postun": rpmPostun,
		"deb postinst": debPostinst, "deb prerm": debPrerm, "deb postrm": debPostrm,
	} {
		for _, forbidden := range []string{"preset", "systemctl enable", "systemctl start", "systemctl restart", "firewall-cmd"} {
			if strings.Contains(script, forbidden) {
				t.Errorf("%s must not contain %q", name, forbidden)
			}
		}
		if out, err := exec.Command("sh", "-n", "-c", script).CombinedOutput(); err != nil {
			t.Errorf("%s is not valid sh: %v\n%s", name, err, out)
		}
	}
	for name, script := range map[string]string{"rpm %post": rpmPostin, "deb postinst": debPostinst} {
		if !strings.Contains(script, "systemd-sysusers "+sysusersConf) || !strings.Contains(script, "systemd-tmpfiles --create "+tmpfilesConf) {
			t.Errorf("%s must create the service accounts and directories", name)
		}
	}
}

func TestWriteRPM(t *testing.T) {
	root := stageTree(t)
	out := filepath.Join(t.TempDir(), "out.rpm")
	got, err := Write("rpm", Options{Version: "1.2.3", Release: "1", Arch: "x86_64", Source: root, Output: out})
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if got != out {
		t.Errorf("Write returned %q, want %q", got, out)
	}
	data, err := os.ReadFile(out) //nolint:gosec // reads the rpm the test just wrote to a temp dir.
	if err != nil {
		t.Fatalf("read rpm: %v", err)
	}
	if !bytes.HasPrefix(data, []byte{0xED, 0xAB, 0xEE, 0xDB}) {
		t.Fatalf("output does not start with the RPM lead magic")
	}
}

func TestWriteDeb(t *testing.T) {
	root := stageTree(t)
	out := filepath.Join(t.TempDir(), "out.deb")
	if _, err := Write("deb", Options{Version: "1.2.3", Arch: "amd64", Source: root, Output: out}); err != nil {
		t.Fatalf("Write: %v", err)
	}
	data, err := os.ReadFile(out) //nolint:gosec // reads the deb the test just wrote to a temp dir.
	if err != nil {
		t.Fatalf("read deb: %v", err)
	}

	control := debMember(t, data, "control.tar.gz")
	if !strings.Contains(control["control"], "Package: sauronagent\n") {
		t.Errorf("control missing package name:\n%s", control["control"])
	}
	if strings.Contains(control["control"], "Depends:") {
		t.Errorf("control must not carry an empty Depends field:\n%s", control["control"])
	}
	if control["conffiles"] != "/etc/sauronhost/sauronhost.yaml.example\n" {
		t.Errorf("conffiles = %q", control["conffiles"])
	}
	for _, script := range []string{"postinst", "prerm", "postrm"} {
		if !strings.HasPrefix(control[script], "#!/bin/sh\n") {
			t.Errorf("maintainer script %s missing or without shebang: %q", script, control[script])
		}
	}

	payload := debMember(t, data, "data.tar.gz")
	if _, ok := payload["etc/audit/rules.d/sauron.rules"]; ok {
		t.Error("audit rules must be configured by the agent, not packaged as a file")
	}
	for _, name := range []string{"usr/bin/sauronagent", "usr/bin/sauronhost", "usr/lib/systemd/system/sauronagent.service", "usr/share/doc/sauronagent/copyright"} {
		if _, ok := payload[name]; !ok {
			t.Errorf("data archive missing %s", name)
		}
	}
}

func TestWriteErrors(t *testing.T) {
	if _, err := Write("tar", Options{}); err == nil || !strings.Contains(err.Error(), "unknown package format") {
		t.Fatalf("Write(tar) error = %v, want unknown package format", err)
	}
	empty := t.TempDir()
	for _, format := range []string{"rpm", "deb"} {
		out := filepath.Join(t.TempDir(), "out."+format)
		if _, err := Write(format, Options{Version: "1", Release: "1", Source: empty, Output: out}); err == nil {
			t.Errorf("Write(%s) with no inputs: expected an error", format)
		}
	}
}

// debMember returns the regular files of a tar.gz member of a .deb, keyed by
// their name without a leading "./".
func debMember(t *testing.T, debData []byte, member string) map[string]string {
	t.Helper()
	if !bytes.HasPrefix(debData, []byte("!<arch>\n")) {
		t.Fatal("not an ar archive")
	}
	for off := len("!<arch>\n"); off+60 <= len(debData); {
		header := debData[off : off+60]
		var size int
		for _, c := range bytes.TrimSpace(header[48:58]) {
			size = size*10 + int(c-'0')
		}
		body := debData[off+60 : off+60+size]
		if strings.TrimSpace(string(header[:16])) == member {
			return tarFiles(t, body)
		}
		off += 60 + size + size%2
	}
	t.Fatalf("%s not found", member)
	return nil
}

func tarFiles(t *testing.T, gz []byte) map[string]string {
	t.Helper()
	gzipReader, err := gzip.NewReader(bytes.NewReader(gz))
	if err != nil {
		t.Fatalf("gzip: %v", err)
	}
	tarReader := tar.NewReader(gzipReader)
	files := map[string]string{}
	for {
		header, err := tarReader.Next()
		if errors.Is(err, io.EOF) {
			return files
		}
		if err != nil {
			t.Fatalf("tar: %v", err)
		}
		if header.Typeflag == tar.TypeReg {
			body, err := io.ReadAll(tarReader)
			if err != nil {
				t.Fatalf("read %s: %v", header.Name, err)
			}
			files[strings.TrimPrefix(header.Name, "./")] = string(body)
		}
	}
}
