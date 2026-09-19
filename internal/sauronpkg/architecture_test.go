package sauronpkg

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteRejectsMismatchedArchitecture(t *testing.T) {
	root := stageTree(t)
	for _, format := range []string{"rpm", "deb"} {
		t.Run(format, func(t *testing.T) {
			output := filepath.Join(t.TempDir(), "existing."+format)
			original := []byte("previous package")
			if err := os.WriteFile(output, original, 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := Write(format, Options{Source: root, Arch: "arm64", Output: output})
			if err == nil || !strings.Contains(err.Error(), "incompatible with package architecture") {
				t.Fatalf("Write mismatched %s = %v, want architecture rejection", format, err)
			}
			got, err := os.ReadFile(output)
			if err != nil || !bytes.Equal(got, original) {
				t.Fatalf("rejected package modified existing output: %q, %v", got, err)
			}
		})
	}
}

func TestWriteRejectsMismatchedSecondBinary(t *testing.T) {
	root := stageTree(t)
	filename := filepath.Join(root, "bin", "sauronhost")
	data, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	// Change the collector's CPU while retaining a valid ELF header; the guest
	// executable still matches the package, so both files must be inspected.
	var order binary.ByteOrder = binary.LittleEndian
	if data[elf.EI_DATA] == byte(elf.ELFDATA2MSB) {
		order = binary.BigEndian
	}
	order.PutUint16(data[18:20], uint16(elf.EM_AARCH64))
	if err := os.WriteFile(filename, data, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, format := range []string{"rpm", "deb"} {
		t.Run(format, func(t *testing.T) {
			output := filepath.Join(t.TempDir(), "new."+format)
			_, err := Write(format, Options{Source: root, Arch: "amd64", Output: output})
			if err == nil || !strings.Contains(err.Error(), "sauronhost") {
				t.Fatalf("Write mismatched collector = %v, want error naming sauronhost", err)
			}
			if _, err := os.Stat(output); !os.IsNotExist(err) {
				t.Fatalf("rejected package created an output: %v", err)
			}
		})
	}
}

func TestValidateBinariesRejectsInvalidInputs(t *testing.T) {
	for _, test := range []struct{ name, arch, want string }{
		{name: "unknown architecture", arch: "noarch", want: "unsupported"},
		{name: "missing executable", arch: "arm64", want: "sauronagent"},
		{name: "non-ELF executable", arch: "arm64", want: "read SauronAgent executable"},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			if test.name == "non-ELF executable" {
				if err := os.WriteFile(filepath.Join(dir, "sauronagent"), []byte("not ELF"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			err := validateBinaries(Options{BinDir: dir}, test.arch)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("validateBinaries = %v, want %q", err, test.want)
			}
		})
	}
}
