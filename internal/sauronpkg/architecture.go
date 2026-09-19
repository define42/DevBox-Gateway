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

func packageArchitecture(arch string) (binaryArchitecture, error) {
	want := binaryArchitecture{class: elf.ELFCLASS64, data: elf.ELFDATA2LSB}
	switch arch {
	case "amd64", "x86_64":
		want.machine = elf.EM_X86_64
	case "arm64", "aarch64":
		want.machine = elf.EM_AARCH64
	case "386", "i386", "i686":
		want.machine, want.class = elf.EM_386, elf.ELFCLASS32
	case "arm", "armhf", "armhfp":
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
