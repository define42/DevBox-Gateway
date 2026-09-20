package sauronpkg

import (
	"debug/elf"
	"fmt"
	"path/filepath"
)

type binaryArchitecture struct {
	machine elf.Machine
	class   elf.Class
	data    elf.Data
}

// rpmArchitecture and debArchitecture translate accepted CPU aliases before
// constructing metadata and default filenames. ELF validation alone cannot
// distinguish aliases that name the same CPU but are invalid package tags.
func rpmArchitecture(arch string) string {
	switch arch {
	case "amd64":
		return "x86_64"
	case "arm64":
		return "aarch64"
	case "386", "i386":
		return "i686"
	case "arm", "armhf", "armhfp":
		return "armv7hl"
	case "ppc64el":
		return "ppc64le"
	case "loong64":
		return "loongarch64"
	default:
		return arch
	}
}

func debArchitecture(arch string) string {
	switch arch {
	case "x86_64":
		return "amd64"
	case "aarch64":
		return "arm64"
	case "386", "i686":
		return "i386"
	case "arm", "armhfp", "armv7hl":
		return "armhf"
	case "ppc64le":
		return "ppc64el"
	case "loongarch64":
		return "loong64"
	default:
		return arch
	}
}

func packageArchitecture(arch string) (binaryArchitecture, error) {
	want := binaryArchitecture{class: elf.ELFCLASS64, data: elf.ELFDATA2LSB}
	switch arch {
	case "amd64", "x86_64":
		want.machine = elf.EM_X86_64
	case "arm64", "aarch64":
		want.machine = elf.EM_AARCH64
	case "386", "i386", "i686":
		want.machine, want.class = elf.EM_386, elf.ELFCLASS32
	case "arm", "armhf", "armhfp", "armv7hl":
		want.machine, want.class = elf.EM_ARM, elf.ELFCLASS32
	case "ppc64":
		want.machine, want.data = elf.EM_PPC64, elf.ELFDATA2MSB
	case "ppc64le", "ppc64el":
		want.machine = elf.EM_PPC64
	case "s390x":
		want.machine, want.data = elf.EM_S390, elf.ELFDATA2MSB
	case "riscv64":
		want.machine = elf.EM_RISCV
	case "loong64", "loongarch64":
		want.machine = elf.EM_LOONGARCH
	default:
		return binaryArchitecture{}, fmt.Errorf("unsupported SauronAgent package architecture %q", arch)
	}
	return want, nil
}

// validateBinaries prevents a direct packaging invocation or stale build output
// from labeling either executable with a different CPU architecture.
func validateBinaries(o Options, arch string) error {
	want, err := packageArchitecture(arch)
	if err != nil {
		return err
	}
	binDir := o.BinDir
	if binDir == "" {
		binDir = filepath.Join(o.Source, "bin")
	}
	for _, name := range []string{"sauronagent", "sauronhost"} {
		filename := filepath.Join(binDir, name)
		binary, err := elf.Open(filename)
		if err != nil {
			return fmt.Errorf("read SauronAgent executable %s: %w", filename, err)
		}
		_ = binary.Close()
		got := binaryArchitecture{binary.Machine, binary.Class, binary.Data}
		if got != want || (binary.Type != elf.ET_EXEC && binary.Type != elf.ET_DYN) {
			return fmt.Errorf("SauronAgent executable %s is %s/%s/%s (%s), incompatible with package architecture %q",
				filename, binary.Machine, binary.Class, binary.Data, binary.Type, arch)
		}
	}
	return nil
}
