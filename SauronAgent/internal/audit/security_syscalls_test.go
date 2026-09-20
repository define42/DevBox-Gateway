package audit

import (
	"runtime"
	"slices"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestSecuritySyscallRulesArchitectures(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name        string
		arch        uint32
		permission  []uint32
		ownership   []uint32
		replacement []uint32
	}{
		{name: "amd64", arch: 0xc000003e, permission: []uint32{90, 91, 268, 452}, ownership: []uint32{92, 93, 94, 260}, replacement: []uint32{246, 320}},
		{name: "386", arch: 0x40000003, permission: []uint32{15, 94, 306, 452}, ownership: []uint32{16, 95, 182, 198, 207, 212, 298}, replacement: []uint32{283}},
		{name: "arm64", arch: 0xc00000b7, permission: []uint32{52, 53, 452}, ownership: []uint32{54, 55}, replacement: []uint32{104, 294}},
		{name: "arm", arch: 0x40000028, permission: []uint32{15, 94, 333, 452}, ownership: []uint32{16, 95, 182, 198, 207, 212, 325}, replacement: []uint32{347, 401}},
		{name: "riscv64", arch: 0xc00000f3, permission: []uint32{52, 53, 452}, ownership: []uint32{54, 55}, replacement: []uint32{104, 294}},
		{name: "ppc64", arch: 0x80000015, permission: []uint32{15, 94, 297, 452}, ownership: []uint32{16, 95, 181, 289}, replacement: []uint32{268, 382}},
		{name: "ppc64le", arch: 0xc0000015, permission: []uint32{15, 94, 297, 452}, ownership: []uint32{16, 95, 181, 289}, replacement: []uint32{268, 382}},
		{name: "s390x", arch: 0x80000016, permission: []uint32{15, 94, 299, 452}, ownership: []uint32{198, 207, 212, 291}, replacement: []uint32{277, 381}},
		{name: "loong64", arch: 0xc0000102, permission: []uint32{52, 53, 452}, ownership: []uint32{54, 55}, replacement: []uint32{104, 294}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			rules, err := securitySyscallRules(tc.name)
			if err != nil {
				t.Fatal(err)
			}
			count := 9
			if tc.name == "amd64" {
				count = 18
			}
			if len(rules) != count {
				t.Fatalf("rules=%d, want %d", len(rules), count)
			}
			seen := make(map[string]bool)
			for _, rule := range rules[:9] {
				if rule.Flags != unix.AUDIT_FILTER_EXIT || rule.Action != unix.AUDIT_ALWAYS || rule.FieldCount != 2 {
					t.Fatalf("rule %q must audit all users and outcomes at syscall exit: %+v", rule.buffer, rule.kernelRule)
				}
				if rule.Fields[0] != unix.AUDIT_ARCH || rule.Values[0] != tc.arch || rule.FieldFlags[0] != unix.AUDIT_EQUAL {
					t.Fatalf("rule %q has incorrect architecture constraint", rule.buffer)
				}
				if rule.Fields[1] != unix.AUDIT_FILTERKEY || rule.Values[1] != uint32(len(rule.buffer)) || rule.FieldFlags[1] != unix.AUDIT_EQUAL {
					t.Fatalf("rule %q has incorrect audit key", rule.buffer)
				}
				if seen[rule.buffer] {
					t.Fatalf("duplicate rule key %q", rule.buffer)
				}
				seen[rule.buffer] = true
				payload, err := marshalKernelRule(rule)
				if err != nil {
					t.Fatal(err)
				}
				decoded, err := parseKernelRule(payload)
				if err != nil || decoded != rule {
					t.Fatalf("wire round trip changed %q: error=%v", rule.buffer, err)
				}
			}
			for key, want := range map[string][]uint32{
				"permission_change":  tc.permission,
				"ownership_change":   tc.ownership,
				"kernel_replacement": tc.replacement,
			} {
				rule := securityRuleWithKey(t, rules[:9], key)
				if got := selectedSecuritySyscalls(rule); !slices.Equal(got, want) {
					t.Errorf("%s mask=%v, want %v", key, got, want)
				}
			}
		})
	}
	if _, err := securitySyscallRules("mips64"); err == nil {
		t.Fatal("unsupported architecture did not fail")
	}
}

func TestSecuritySyscallRulesMatchNativeLinuxABI(t *testing.T) {
	t.Parallel()
	rules, err := securitySyscallRules(runtime.GOARCH)
	if err != nil {
		t.Fatal(err)
	}
	// Only reference calls present in every supported native ABI. Legacy calls
	// and kexec_file_load (absent on i386) are verified by architecture above.
	for key, numbers := range map[string][]uint32{
		"permission_change": {unix.SYS_FCHMOD, unix.SYS_FCHMODAT, unix.SYS_FCHMODAT2},
		"ownership_change":  {unix.SYS_FCHOWN, unix.SYS_FCHOWNAT},
		"attribute_change": {
			unix.SYS_SETXATTR, unix.SYS_LSETXATTR, unix.SYS_FSETXATTR,
			unix.SYS_REMOVEXATTR, unix.SYS_LREMOVEXATTR, unix.SYS_FREMOVEXATTR,
			unix.SYS_SETXATTRAT, unix.SYS_REMOVEXATTRAT,
		},
		"privilege_change": {
			unix.SYS_SETUID, unix.SYS_SETREUID, unix.SYS_SETRESUID,
			unix.SYS_SETGID, unix.SYS_SETREGID, unix.SYS_SETRESGID, unix.SYS_CAPSET,
		},
		"kernel_module":      {unix.SYS_INIT_MODULE, unix.SYS_FINIT_MODULE, unix.SYS_DELETE_MODULE},
		"kernel_replacement": {unix.SYS_KEXEC_LOAD},
		"network_config":     {unix.SYS_SETHOSTNAME, unix.SYS_SETDOMAINNAME},
		"time_change":        {unix.SYS_ADJTIMEX, unix.SYS_SETTIMEOFDAY, unix.SYS_CLOCK_SETTIME, unix.SYS_CLOCK_ADJTIME},
		"filesystem_mount":   {unix.SYS_MOUNT, unix.SYS_UMOUNT2, unix.SYS_MOUNT_SETATTR},
	} {
		t.Run(key, func(t *testing.T) {
			t.Parallel()
			selected := selectedSecuritySyscalls(securityRuleWithKey(t, rules[:9], key))
			for _, number := range numbers {
				if !slices.Contains(selected, number) {
					t.Errorf("native %s syscall %d is not audited", runtime.GOARCH, number)
				}
			}
		})
	}
}

func TestSecuritySyscallRulesCompatibilityABI(t *testing.T) {
	t.Parallel()
	amd64, err := securitySyscallRules("amd64")
	if err != nil {
		t.Fatal(err)
	}
	i386, err := securitySyscallRules("386")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(amd64[9:], i386) {
		t.Fatal("amd64 compatibility rules differ from native i386 rules")
	}
	for _, arch := range []string{"386", "arm"} {
		t.Run(arch, func(t *testing.T) {
			t.Parallel()
			rules, err := securitySyscallRules(arch)
			if err != nil {
				t.Fatal(err)
			}
			privilege := selectedSecuritySyscalls(securityRuleWithKey(t, rules, "privilege_change"))
			for _, number := range []uint32{213, 203, 208, 214, 204, 210} {
				if !slices.Contains(privilege, number) {
					t.Errorf("32-bit UID/GID syscall %d is not audited", number)
				}
			}
			clock := selectedSecuritySyscalls(securityRuleWithKey(t, rules, "time_change"))
			for _, number := range []uint32{404, 405} {
				if !slices.Contains(clock, number) {
					t.Errorf("time64 syscall %d is not audited", number)
				}
			}
		})
	}
}

func TestKeyedSyscallRuleValidation(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name     string
		key      string
		syscalls []uint32
	}{
		{name: "empty key", syscalls: []uint32{1}},
		{name: "oversized key", key: strings.Repeat("x", unix.AUDIT_MAX_KEY_LEN+1), syscalls: []uint32{1}},
		{name: "NUL in key", key: "key\x00other", syscalls: []uint32{1}},
		{name: "empty mask", key: "test"},
		{name: "reserved class bit", key: "test", syscalls: []uint32{unix.AUDIT_BITMASK_SIZE*32 - unix.AUDIT_SYSCALL_CLASSES}},
		{name: "outside mask", key: "test", syscalls: []uint32{unix.AUDIT_BITMASK_SIZE * 32}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, err := keyedSyscallRule(unix.AUDIT_ARCH_X86_64, tc.key, tc.syscalls...); err == nil {
				t.Fatal("invalid rule accepted")
			}
		})
	}
	// Modern ABI numbers remain valid policy even on a kernel without these
	// implementations; constructing policy must not invoke the selected calls.
	rule, err := keyedSyscallRule(unix.AUDIT_ARCH_X86_64, "test", 442, 452, 463, 466, 466)
	if err != nil {
		t.Fatal(err)
	}
	if got := selectedSecuritySyscalls(rule); !slices.Equal(got, []uint32{442, 452, 463, 466}) {
		t.Fatalf("selected syscalls=%v", got)
	}
}

func securityRuleWithKey(t *testing.T, rules []auditRule, key string) auditRule {
	t.Helper()
	for _, rule := range rules {
		if rule.buffer == key {
			return rule
		}
	}
	t.Fatalf("missing %q rule", key)
	return auditRule{}
}

func selectedSecuritySyscalls(rule auditRule) []uint32 {
	var numbers []uint32
	for number := uint32(0); number < unix.AUDIT_BITMASK_SIZE*32; number++ {
		if rule.Mask[number/32]&(1<<(number%32)) != 0 {
			numbers = append(numbers, number)
		}
	}
	return numbers
}
