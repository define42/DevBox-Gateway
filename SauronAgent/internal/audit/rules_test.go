package audit

import (
	"context"
	"encoding/binary"
	"errors"
	"slices"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestEnsureExecutionRulesInstallsAndReusesPolicy(t *testing.T) {
	t.Parallel()
	wanted, err := executionRules("amd64", 59, 322)
	if err != nil {
		t.Fatal(err)
	}
	kernel := &fakeAuditKernel{enabled: 0}
	client := &auditControlClient{transport: kernel}
	if err := ensureExecutionRules(t.Context(), client, wanted); err != nil {
		t.Fatal(err)
	}
	if kernel.enabled != 1 || kernel.added != 2 || kernel.sets != 1 {
		t.Fatalf("enabled=%d added=%d sets=%d; want 1, 2, 1", kernel.enabled, kernel.added, kernel.sets)
	}
	if kernel.changedOtherStatus {
		t.Fatal("setup changed status fields other than AUDIT_STATUS_ENABLED")
	}
	if err := ensureExecutionRules(t.Context(), client, wanted); err != nil {
		t.Fatal(err)
	}
	if kernel.added != 2 || kernel.sets != 1 {
		t.Fatalf("restart changed policy: added=%d sets=%d", kernel.added, kernel.sets)
	}
}

func TestEnsureExecutionRulesExistingPolicy(t *testing.T) {
	t.Parallel()
	wanted, _ := executionRules("amd64", 59, 322)
	limited := wanted[0]
	limited.Fields[2], limited.Values[2], limited.FieldFlags[2] = unix.AUDIT_UID, 1000, unix.AUDIT_EQUAL
	limited.FieldCount = 3
	neverTask := kernelRule{Flags: unix.AUDIT_FILTER_TASK, Action: unix.AUDIT_NEVER}
	for _, tc := range []struct {
		name     string
		enabled  uint32
		rules    []kernelRule
		wantAdds int
		wantErr  string
	}{
		{name: "already enabled", enabled: 1, wantAdds: 2},
		{name: "one architecture covered", enabled: 1, rules: wanted[:1], wantAdds: 1},
		{name: "user-limited coverage is insufficient", enabled: 1, rules: []kernelRule{limited}, wantAdds: 2},
		{name: "immutable with coverage", enabled: 2, rules: wanted},
		{name: "immutable missing rules", enabled: 2, wantErr: "immutable"},
		{name: "never task blocks all changes", rules: []kernelRule{neverTask}, wantErr: "never,task"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			kernel := &fakeAuditKernel{enabled: tc.enabled, rules: slices.Clone(tc.rules)}
			err := ensureExecutionRules(t.Context(), &auditControlClient{transport: kernel}, wanted)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("error=%v, want %q", err, tc.wantErr)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			if kernel.added != tc.wantAdds || kernel.sets != 0 {
				t.Fatalf("added=%d sets=%d; want %d, 0", kernel.added, kernel.sets, tc.wantAdds)
			}
			if !slices.Equal(kernel.rules[:len(tc.rules)], tc.rules) {
				t.Fatal("existing policy was changed")
			}
		})
	}
}

func TestEnsureExecutionRulesFailures(t *testing.T) {
	t.Parallel()
	wanted, _ := executionRules("arm64", 221, 281)
	for _, tc := range []struct {
		name   string
		kernel fakeAuditKernel
		want   string
	}{
		{name: "permission denied", kernel: fakeAuditKernel{failType: unix.AUDIT_GET, failCode: unix.EPERM}, want: "CAP_AUDIT_CONTROL"},
		{name: "list failure", kernel: fakeAuditKernel{failType: unix.AUDIT_LIST_RULES, failCode: unix.EINVAL}, want: "listing"},
		{name: "add failure", kernel: fakeAuditKernel{failType: unix.AUDIT_ADD_RULE, failCode: unix.EINVAL}, want: "installing"},
		{name: "enable failure", kernel: fakeAuditKernel{failType: unix.AUDIT_SET, failCode: unix.EPERM}, want: "enabling"},
		{name: "rules disappeared", kernel: fakeAuditKernel{enabled: 1, discardRules: true}, want: "missing after installation"},
		{name: "enable did not take effect", kernel: fakeAuditKernel{discardEnable: true}, want: "still disabled"},
		{name: "invalid status", kernel: fakeAuditKernel{enabled: 99}, want: "unexpected kernel audit enabled"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := ensureExecutionRules(t.Context(), &auditControlClient{transport: &tc.kernel}, wanted)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error=%v, want %q", err, tc.want)
			}
		})
	}
}

func TestEnsureExecutionRulesConcurrentInstallation(t *testing.T) {
	t.Parallel()
	wanted, _ := executionRules("arm64", 221, 281)
	kernel := &fakeAuditKernel{enabled: 1, addExists: true}
	if err := ensureExecutionRules(t.Context(), &auditControlClient{transport: kernel}, wanted); err != nil {
		t.Fatal(err)
	}
	if len(kernel.rules) != 1 {
		t.Fatalf("rules=%d, want 1", len(kernel.rules))
	}
}

func TestEnsureExecutionRulesCanceled(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := EnsureExecutionRules(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v, want context.Canceled", err)
	}
}

func TestExecutionRulesArchitectures(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name     string
		execve   uint32
		execveat uint32
		arch     uint32
		count    int
	}{
		{name: "amd64", execve: 59, execveat: 322, arch: 0xc000003e, count: 2},
		{name: "386", execve: 11, execveat: 358, arch: 0x40000003, count: 1},
		{name: "arm64", execve: 221, execveat: 281, arch: 0xc00000b7, count: 1},
		{name: "arm", execve: 11, execveat: 387, arch: 0x40000028, count: 1},
		{name: "riscv64", execve: 221, execveat: 281, arch: 0xc00000f3, count: 1},
		{name: "ppc64", execve: 11, execveat: 362, arch: 0x80000015, count: 1},
		{name: "ppc64le", execve: 11, execveat: 362, arch: 0xc0000015, count: 1},
		{name: "s390x", execve: 11, execveat: 354, arch: 0x80000016, count: 1},
		{name: "loong64", execve: 221, execveat: 281, arch: 0xc0000102, count: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			rules, err := executionRules(tc.name, tc.execve, tc.execveat)
			if err != nil {
				t.Fatal(err)
			}
			if len(rules) != tc.count || rules[0].Values[0] != tc.arch {
				t.Fatalf("rules=%+v", rules)
			}
			if rules[0].Mask[tc.execve/32]&(1<<(tc.execve%32)) == 0 || rules[0].Mask[tc.execveat/32]&(1<<(tc.execveat%32)) == 0 {
				t.Fatal("native execution syscalls are missing")
			}
			if tc.count == 2 && (rules[1].Values[0] != 0x40000003 || rules[1].Mask[0] != 1<<11 || rules[1].Mask[11] != 1<<6) {
				t.Fatal("i386 compatibility rule uses incorrect architecture or syscall numbers")
			}
		})
	}
	if _, err := executionRules("unknown", 1, 2); err == nil {
		t.Fatal("unsupported architecture accepted")
	}
	if _, err := executionRules("amd64", 1, 2048); err == nil {
		t.Fatal("out-of-range syscall accepted")
	}
}

func TestExecutionRuleWireFormat(t *testing.T) {
	t.Parallel()
	payload, err := marshalKernelRule(executionRule(unix.AUDIT_ARCH_X86_64, 59, 322))
	if err != nil {
		t.Fatal(err)
	}
	if len(payload) != 1044 {
		t.Fatalf("rule size=%d, want 1040 byte UAPI prefix and 4 byte key", len(payload))
	}
	for _, tc := range []struct {
		name   string
		offset int
		value  uint32
	}{
		{name: "exit filter", offset: 0, value: 4},
		{name: "always action", offset: 4, value: 2},
		{name: "field count", offset: 8, value: 2},
		{name: "execve mask", offset: 16, value: 1 << 27},
		{name: "execveat mask", offset: 52, value: 1 << 2},
		{name: "arch field", offset: 268, value: 11},
		{name: "key field", offset: 272, value: 210},
		{name: "arch value", offset: 524, value: 0xc000003e},
		{name: "key length", offset: 528, value: 4},
		{name: "arch operator", offset: 780, value: 0x40000000},
		{name: "key operator", offset: 784, value: 0x40000000},
		{name: "buffer length", offset: 1036, value: 4},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := binary.NativeEndian.Uint32(payload[tc.offset:]); got != tc.value {
				t.Fatalf("offset %d=%#x, want %#x", tc.offset, got, tc.value)
			}
		})
	}
	if string(payload[1040:]) != "exec" {
		t.Fatalf("key=%q", payload[1040:])
	}
}

func TestParseKernelRuleRejectsMalformedPayloads(t *testing.T) {
	t.Parallel()
	valid, _ := marshalKernelRule(executionRule(unix.AUDIT_ARCH_X86_64, 59, 322))
	tooManyFields := slices.Clone(valid)
	binary.NativeEndian.PutUint32(tooManyFields[8:12], 65)
	badBuffer := slices.Clone(valid)
	binary.NativeEndian.PutUint32(badBuffer[1036:1040], 5)
	for _, tc := range []struct {
		name    string
		payload []byte
	}{
		{name: "truncated prefix", payload: valid[:1039]},
		{name: "too many fields", payload: tooManyFields},
		{name: "truncated string", payload: valid[:1043]},
		{name: "wrong string length", payload: badBuffer},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, err := parseKernelRule(tc.payload); err == nil {
				t.Fatal("malformed rule accepted")
			}
		})
	}
}

func TestMissingExecutionRulesAcceptsSplitAndKeylessCoverage(t *testing.T) {
	t.Parallel()
	wanted, _ := executionRules("arm64", 221, 281)
	first, second := wanted[0], wanted[0]
	first.FieldCount, second.FieldCount = 1, 1
	first.BufferLength, second.BufferLength = 0, 0
	first.Mask[281/32] = 0
	second.Mask[221/32] = 0
	missing, err := missingExecutionRules([]kernelRule{first, second}, wanted)
	if err != nil || len(missing) != 0 {
		t.Fatalf("missing=%v error=%v", missing, err)
	}
}

func TestMissingExecutionRulesRejectsSuppressions(t *testing.T) {
	t.Parallel()
	wanted, _ := executionRules("amd64", 59, 322)
	neverExec := wanted[0]
	neverExec.Action = unix.AUDIT_NEVER
	filteredNever := neverExec
	filteredNever.FieldCount = 3
	filteredNever.Fields[2], filteredNever.Values[2], filteredNever.FieldFlags[2] = unix.AUDIT_UID, 1000, unix.AUDIT_EQUAL
	otherArch := neverExec
	otherArch.Values[0] = unix.AUDIT_ARCH_ARM
	otherSyscall := neverExec
	otherSyscall.Mask = [unix.AUDIT_BITMASK_SIZE]uint32{1}
	excludeAll := kernelRule{Flags: unix.AUDIT_FILTER_EXCLUDE, Action: unix.AUDIT_ALWAYS}
	excludeExec := excludeAll
	excludeExec.FieldCount = 1
	excludeExec.Fields[0], excludeExec.Values[0], excludeExec.FieldFlags[0] = unix.AUDIT_MSGTYPE, unix.AUDIT_EXECVE, unix.AUDIT_EQUAL
	excludeOther := excludeExec
	excludeOther.Values[0] = unix.AUDIT_AVC
	for _, tc := range []struct {
		name    string
		rule    kernelRule
		wantErr string
	}{
		{name: "never exec", rule: neverExec, wantErr: "never,exit"},
		{name: "never exec for some users", rule: filteredNever, wantErr: "never,exit"},
		{name: "never unrelated architecture", rule: otherArch},
		{name: "never unrelated syscall", rule: otherSyscall},
		{name: "exclude always still suppresses", rule: excludeAll, wantErr: "exclude"},
		{name: "exclude execution records", rule: excludeExec, wantErr: "exclude"},
		{name: "exclude unrelated records", rule: excludeOther},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := missingExecutionRules([]kernelRule{tc.rule}, wanted)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("error=%v, want %q", err, tc.wantErr)
				}
			} else if err != nil {
				t.Fatal(err)
			}
		})
	}
}

// fakeAuditKernel speaks wire netlink so these tests exercise the complete
// startup handshake, including acknowledgements and post-install verification.
// It never opens a socket or changes the host audit policy.
type fakeAuditKernel struct {
	enabled            uint32
	rules              []kernelRule
	queue              [][]byte
	added              int
	sets               int
	changedOtherStatus bool
	failType           uint16
	failCode           unix.Errno
	discardRules       bool
	discardEnable      bool
	addExists          bool
}

func (k *fakeAuditKernel) send(request []byte) error {
	typ := binary.NativeEndian.Uint16(request[4:6])
	seq := binary.NativeEndian.Uint32(request[8:12])
	payload := request[unix.NLMSG_HDRLEN:]
	if typ == k.failType {
		k.queue = append(k.queue, controlACK(request, k.failCode))
		return nil
	}
	ack := controlACK(request, 0)
	switch typ {
	case unix.AUDIT_GET:
		status := make([]byte, 40)
		binary.NativeEndian.PutUint32(status[4:8], k.enabled)
		k.queue = append(k.queue, controlMessage(typ, seq, status))
	case unix.AUDIT_LIST_RULES:
		for _, rule := range k.rules {
			data := make([]byte, auditRuleSize+int(rule.BufferLength))
			if _, err := binary.Encode(data, binary.NativeEndian, rule); err != nil {
				return err
			}
			copy(data[auditRuleSize:], auditRuleKey)
			k.queue = append(k.queue, controlMessage(typ, seq, data))
		}
		k.queue = append(k.queue, controlMessage(unix.NLMSG_DONE, seq, nil))
	case unix.AUDIT_ADD_RULE:
		rule, err := parseKernelRule(payload)
		if err != nil {
			return err
		}
		k.added++
		if !k.discardRules {
			k.rules = append(k.rules, rule)
		}
		if k.addExists {
			ack = controlACK(request, unix.EEXIST)
		}
	case unix.AUDIT_SET:
		k.sets++
		k.changedOtherStatus = binary.NativeEndian.Uint32(payload[:4]) != unix.AUDIT_STATUS_ENABLED
		for _, b := range payload[8:] {
			k.changedOtherStatus = k.changedOtherStatus || b != 0
		}
		if !k.discardEnable {
			k.enabled = binary.NativeEndian.Uint32(payload[4:8])
		}
	default:
		return errors.New("unexpected audit command, policy may be overwritten")
	}
	k.queue = append(k.queue, ack)
	return nil
}

func (k *fakeAuditKernel) receive(buffer []byte) (int, unix.Sockaddr, error) {
	if len(k.queue) == 0 {
		return 0, nil, unix.EAGAIN
	}
	data := k.queue[0]
	k.queue = k.queue[1:]
	return copy(buffer, data), &unix.SockaddrNetlink{Family: unix.AF_NETLINK}, nil
}

func controlMessage(typ uint16, sequence uint32, payload []byte) []byte {
	data := make([]byte, unix.NLMSG_HDRLEN+len(payload))
	binary.NativeEndian.PutUint32(data[:4], uint32(len(data)))
	binary.NativeEndian.PutUint16(data[4:6], typ)
	binary.NativeEndian.PutUint32(data[8:12], sequence)
	copy(data[unix.NLMSG_HDRLEN:], payload)
	return data
}

func controlACK(request []byte, errno unix.Errno) []byte {
	payload := make([]byte, 4+unix.NLMSG_HDRLEN)
	binary.NativeEndian.PutUint32(payload[:4], uint32(-int32(errno)))
	copy(payload[4:], request[:unix.NLMSG_HDRLEN])
	return controlMessage(unix.NLMSG_ERROR, binary.NativeEndian.Uint32(request[8:12]), payload)
}
