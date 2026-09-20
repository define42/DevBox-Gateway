package audit

import (
	"errors"
	"fmt"
	"strings"

	"golang.org/x/sys/unix"
)

// securitySyscallRules audits both successful and failed changes, for every
// user. Each mask belongs to one ABI; amd64 also covers i386 compatibility.
func securitySyscallRules(goarch string) ([]auditRule, error) {
	native, err := securitySyscallsForArchitecture(goarch)
	if err != nil {
		return nil, err
	}
	tables := []securitySyscallTable{native}
	if goarch == "amd64" {
		compat, err := securitySyscallsForArchitecture("386")
		if err != nil {
			return nil, err
		}
		tables = append(tables, compat)
	}
	rules := make([]auditRule, 0, 9*len(tables))
	for _, table := range tables {
		for _, group := range []struct {
			key      string
			syscalls []uint32
		}{
			{key: "permission_change", syscalls: table.permission},
			{key: "ownership_change", syscalls: table.ownership},
			{key: "attribute_change", syscalls: table.attribute},
			{key: "privilege_change", syscalls: table.privilege},
			{key: "kernel_module", syscalls: table.module},
			{key: "kernel_replacement", syscalls: table.replacement},
			{key: "network_config", syscalls: table.network},
			{key: "time_change", syscalls: table.time},
			{key: "filesystem_mount", syscalls: table.mount},
		} {
			rule, err := keyedSyscallRule(table.arch, group.key, group.syscalls...)
			if err != nil {
				return nil, err
			}
			rules = append(rules, rule)
		}
	}
	return rules, nil
}

func keyedSyscallRule(arch uint32, key string, syscalls ...uint32) (auditRule, error) {
	if key == "" || len(key) > unix.AUDIT_MAX_KEY_LEN || strings.IndexByte(key, 0) >= 0 {
		return auditRule{}, errors.New("audit: invalid syscall rule key")
	}
	if len(syscalls) == 0 {
		return auditRule{}, errors.New("audit: syscall rule must select at least one syscall")
	}
	rule := auditRule{
		kernelRule: kernelRule{
			Flags: unix.AUDIT_FILTER_EXIT, Action: unix.AUDIT_ALWAYS,
			FieldCount: 2, BufferLength: uint32(len(key)),
		},
		buffer: key,
	}
	for _, number := range syscalls {
		// The top mask bits encode syscall classes, not syscall numbers.
		if number >= unix.AUDIT_BITMASK_SIZE*32-unix.AUDIT_SYSCALL_CLASSES {
			return auditRule{}, fmt.Errorf("audit: syscall %d exceeds the kernel audit syscall mask", number)
		}
		rule.Mask[number/32] |= 1 << (number % 32)
	}
	rule.Fields[0], rule.Values[0], rule.FieldFlags[0] = unix.AUDIT_ARCH, arch, unix.AUDIT_EQUAL
	rule.Fields[1], rule.Values[1], rule.FieldFlags[1] = unix.AUDIT_FILTERKEY, uint32(len(key)), unix.AUDIT_EQUAL
	return rule, nil
}

type securitySyscallTable struct {
	arch        uint32
	permission  []uint32
	ownership   []uint32
	attribute   []uint32
	privilege   []uint32
	module      []uint32
	replacement []uint32
	network     []uint32
	time        []uint32
	mount       []uint32
}

// These stable Linux ABI numbers are verified against golang.org/x/sys v0.48.0
// unix/zsysnum_linux_*.go. Explicit tables keep compatibility rules independent
// of the build target and avoid nonexistent legacy constants on newer ABIs.
//
// Modern calls (fchmodat2, *xattrat, mount_setattr, kexec_file_load and time64)
// may be absent from older kernels. Installing their mask bits is safe: Linux's
// audit_to_entry_common copies the mask without checking syscall availability.
// See https://github.com/torvalds/linux/blob/v6.12/kernel/auditfilter.c#L264-L280.
// No syscall is invoked to probe support.
func securitySyscallsForArchitecture(goarch string) (securitySyscallTable, error) {
	switch goarch {
	case "amd64":
		return securitySyscallTable{
			arch:        unix.AUDIT_ARCH_X86_64,
			permission:  []uint32{90, 91, 268, 452}, // chmod, fchmod, fchmodat, fchmodat2
			ownership:   []uint32{92, 93, 94, 260},  // chown, fchown, lchown, fchownat
			attribute:   []uint32{188, 189, 190, 197, 198, 199, 463, 466},
			privilege:   []uint32{105, 113, 117, 106, 114, 119, 126},
			module:      []uint32{175, 313, 176}, // init_module, finit_module, delete_module
			replacement: []uint32{246, 320},      // kexec_load, kexec_file_load
			network:     []uint32{170, 171},      // sethostname, setdomainname
			time:        []uint32{159, 164, 227, 305},
			mount:       []uint32{165, 166, 442}, // mount, umount2, mount_setattr
		}, nil
	case "386", "arm":
		table := securitySyscallTable{
			arch:        unix.AUDIT_ARCH_I386,
			permission:  []uint32{15, 94, 306, 452},
			ownership:   []uint32{182, 95, 16, 298, 212, 207, 198}, // also chown32, fchown32, lchown32
			attribute:   []uint32{226, 227, 228, 235, 236, 237, 463, 466},
			privilege:   []uint32{23, 70, 164, 46, 71, 170, 185, 213, 203, 208, 214, 204, 210},
			module:      []uint32{128, 350, 129},
			replacement: []uint32{283}, // i386 has no kexec_file_load syscall
			network:     []uint32{74, 121},
			time:        []uint32{124, 79, 264, 343, 404, 405}, // also clock_settime64, clock_adjtime64
			mount:       []uint32{21, 52, 442},
		}
		if goarch == "arm" {
			table.arch = unix.AUDIT_ARCH_ARM
			table.permission = []uint32{15, 94, 333, 452}
			table.ownership = []uint32{182, 95, 16, 325, 212, 207, 198}
			table.module = []uint32{128, 379, 129}
			table.replacement = []uint32{347, 401}
			table.time = []uint32{124, 79, 262, 372, 404, 405}
		}
		return table, nil
	case "arm64", "riscv64", "loong64":
		table := securitySyscallTable{
			arch:        unix.AUDIT_ARCH_AARCH64,
			permission:  []uint32{52, 53, 452}, // no legacy chmod in asm-generic ABIs
			ownership:   []uint32{55, 54},      // fchown, fchownat; no legacy chown/lchown
			attribute:   []uint32{5, 6, 7, 14, 15, 16, 463, 466},
			privilege:   []uint32{146, 145, 147, 144, 143, 149, 91},
			module:      []uint32{105, 273, 106},
			replacement: []uint32{104, 294},
			network:     []uint32{161, 162},
			time:        []uint32{171, 170, 112, 266},
			mount:       []uint32{40, 39, 442},
		}
		switch goarch {
		case "riscv64":
			table.arch = unix.AUDIT_ARCH_RISCV64
		case "loong64":
			table.arch = unix.AUDIT_ARCH_LOONGARCH64
		}
		return table, nil
	case "ppc64", "ppc64le":
		table := securitySyscallTable{
			arch:        unix.AUDIT_ARCH_PPC64,
			permission:  []uint32{15, 94, 297, 452},
			ownership:   []uint32{181, 95, 16, 289},
			attribute:   []uint32{209, 210, 211, 218, 219, 220, 463, 466},
			privilege:   []uint32{23, 70, 164, 46, 71, 169, 184},
			module:      []uint32{128, 353, 129},
			replacement: []uint32{268, 382},
			network:     []uint32{74, 121},
			time:        []uint32{124, 79, 245, 347},
			mount:       []uint32{21, 52, 442},
		}
		if goarch == "ppc64le" {
			table.arch = unix.AUDIT_ARCH_PPC64LE
		}
		return table, nil
	case "s390x":
		return securitySyscallTable{
			arch:        unix.AUDIT_ARCH_S390X,
			permission:  []uint32{15, 94, 299, 452},
			ownership:   []uint32{212, 207, 198, 291},
			attribute:   []uint32{224, 225, 226, 233, 234, 235, 463, 466},
			privilege:   []uint32{213, 203, 208, 214, 204, 210, 185},
			module:      []uint32{128, 344, 129},
			replacement: []uint32{277, 381},
			network:     []uint32{74, 121},
			time:        []uint32{124, 79, 259, 337},
			mount:       []uint32{21, 52, 442},
		}, nil
	default:
		return securitySyscallTable{}, fmt.Errorf("audit: automatic security syscall rules are unsupported on GOARCH=%s", goarch)
	}
}
