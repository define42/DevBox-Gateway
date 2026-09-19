package audit

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"runtime"
	"time"

	"golang.org/x/sys/unix"
)

const (
	auditRuleSize = 4 * (4 + unix.AUDIT_BITMASK_SIZE + 3*unix.AUDIT_MAX_FIELDS)
	auditRuleKey  = "exec"
)

// kernelRule is the fixed prefix of Linux's audit_rule_data UAPI structure.
// String fields follow this prefix and are sized by BufferLength.
type kernelRule struct {
	Flags        uint32
	Action       uint32
	FieldCount   uint32
	Mask         [unix.AUDIT_BITMASK_SIZE]uint32
	Fields       [unix.AUDIT_MAX_FIELDS]uint32
	Values       [unix.AUDIT_MAX_FIELDS]uint32
	FieldFlags   [unix.AUDIT_MAX_FIELDS]uint32
	BufferLength uint32
}

// EnsureExecutionRules enables Linux auditing and installs unconditional
// execve/execveat exit rules for this architecture (including i386 on amd64).
// It requires CAP_AUDIT_CONTROL, uses no external tools, and never claims the
// audit daemon PID. Existing rules are preserved and reused across restarts.
// The caller should subscribe to audit events before calling this function.
//
// Rules remain active after the agent exits. Immutable policy is accepted only
// when it already provides execution coverage. Suppressing task rules produce
// an actionable error instead of silently starting without that coverage.
func EnsureExecutionRules(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return err
	}
	wanted, err := executionRules(runtime.GOARCH, unix.SYS_EXECVE, unix.SYS_EXECVEAT)
	if err != nil {
		return err
	}
	socket, err := openControlSocket()
	if err != nil {
		return controlError("opening rule-control socket", err)
	}
	defer socket.close()
	client := auditControlClient{transport: socket}
	return ensureExecutionRules(ctx, &client, wanted)
}

func ensureExecutionRules(ctx context.Context, client *auditControlClient, wanted []kernelRule) error {
	enabled, err := client.enabled(ctx)
	if err != nil {
		return err
	}
	rules, err := client.rules(ctx)
	if err != nil {
		return err
	}
	missing, err := missingExecutionRules(rules, wanted)
	if err != nil {
		return err
	}
	if enabled == 2 && len(missing) != 0 {
		return errors.New("audit: kernel audit policy is immutable and execution rules are missing; configure execve/execveat rules before locking the policy and reboot the VM")
	}
	for _, rule := range missing {
		payload, err := marshalKernelRule(rule)
		if err != nil {
			return err
		}
		_, err = client.exchange(ctx, unix.AUDIT_ADD_RULE, payload)
		// Another controller may have installed the identical rule since the
		// dump. Only accept EEXIST provisionally; verify the resulting policy.
		if err != nil && !errors.Is(err, unix.EEXIST) {
			return controlError("installing execution rule", err)
		}
	}
	if enabled == 0 {
		// Set only ENABLED. In particular, do not set AUDIT_STATUS_PID or
		// change an administrator's failure mode, rate limit, or backlog.
		status := make([]byte, 40)
		binary.NativeEndian.PutUint32(status[0:4], unix.AUDIT_STATUS_ENABLED)
		binary.NativeEndian.PutUint32(status[4:8], 1)
		if _, err := client.exchange(ctx, unix.AUDIT_SET, status); err != nil {
			return controlError("enabling kernel auditing", err)
		}
	}
	return verifyExecutionRules(ctx, client, wanted)
}

func verifyExecutionRules(ctx context.Context, client *auditControlClient, wanted []kernelRule) error {
	enabled, err := client.enabled(ctx)
	if err != nil {
		return err
	}
	if enabled == 0 {
		return errors.New("audit: kernel auditing is still disabled after execution-rule setup")
	}
	rules, err := client.rules(ctx)
	if err != nil {
		return err
	}
	missing, err := missingExecutionRules(rules, wanted)
	if err != nil {
		return err
	}
	if len(missing) != 0 {
		return errors.New("audit: execution rules are missing after installation; another audit policy manager may be changing them")
	}
	return nil
}

// Native syscall numbers are supplied by x/sys/unix for the compiled target.
// Only the i386 compatibility ABI needs an explicit syscall table here.
func executionRules(goarch string, execve, execveat uint32) ([]kernelRule, error) {
	var arch uint32
	switch goarch {
	case "amd64":
		arch = unix.AUDIT_ARCH_X86_64
	case "386":
		arch = unix.AUDIT_ARCH_I386
	case "arm64":
		arch = unix.AUDIT_ARCH_AARCH64
	case "arm":
		arch = unix.AUDIT_ARCH_ARM
	case "riscv64":
		arch = unix.AUDIT_ARCH_RISCV64
	case "ppc64":
		arch = unix.AUDIT_ARCH_PPC64
	case "ppc64le":
		arch = unix.AUDIT_ARCH_PPC64LE
	case "s390x":
		arch = unix.AUDIT_ARCH_S390X
	case "loong64":
		arch = unix.AUDIT_ARCH_LOONGARCH64
	default:
		return nil, fmt.Errorf("audit: automatic execution rules are unsupported on GOARCH=%s", goarch)
	}
	if execve >= unix.AUDIT_BITMASK_SIZE*32 || execveat >= unix.AUDIT_BITMASK_SIZE*32 {
		return nil, errors.New("audit: execution syscall numbers exceed the kernel audit rule mask")
	}
	rules := []kernelRule{executionRule(arch, execve, execveat)}
	if goarch == "amd64" {
		rules = append(rules, executionRule(unix.AUDIT_ARCH_I386, 11, 358))
	}
	return rules, nil
}

func executionRule(arch, execve, execveat uint32) kernelRule {
	rule := kernelRule{
		Flags: unix.AUDIT_FILTER_EXIT, Action: unix.AUDIT_ALWAYS,
		FieldCount: 2, BufferLength: uint32(len(auditRuleKey)),
	}
	rule.Mask[execve/32] |= 1 << (execve % 32)
	rule.Mask[execveat/32] |= 1 << (execveat % 32)
	rule.Fields[0], rule.Values[0], rule.FieldFlags[0] = unix.AUDIT_ARCH, arch, unix.AUDIT_EQUAL
	rule.Fields[1], rule.Values[1], rule.FieldFlags[1] = unix.AUDIT_FILTERKEY, uint32(len(auditRuleKey)), unix.AUDIT_EQUAL
	return rule
}

func marshalKernelRule(rule kernelRule) ([]byte, error) {
	payload := make([]byte, auditRuleSize+len(auditRuleKey))
	if _, err := binary.Encode(payload, binary.NativeEndian, rule); err != nil {
		return nil, fmt.Errorf("audit: encoding execution rule: %w", err)
	}
	copy(payload[auditRuleSize:], auditRuleKey)
	return payload, nil
}

func parseKernelRule(payload []byte) (kernelRule, error) {
	var rule kernelRule
	if _, err := binary.Decode(payload, binary.NativeEndian, &rule); err != nil {
		return rule, fmt.Errorf("audit: decoding kernel audit rule: %w", err)
	}
	if rule.FieldCount > unix.AUDIT_MAX_FIELDS || uint64(rule.BufferLength) != uint64(len(payload)-auditRuleSize) {
		return rule, errors.New("audit: malformed kernel audit rule fields or string buffer")
	}
	return rule, nil
}

func missingExecutionRules(existing, wanted []kernelRule) ([]kernelRule, error) {
	if err := checkExecutionSuppressions(existing, wanted); err != nil {
		return nil, err
	}
	var missing []kernelRule
	for _, desired := range wanted {
		covered := [unix.AUDIT_BITMASK_SIZE]uint32{}
		for _, rule := range existing {
			if unconditionalExecutionRule(rule, desired.Values[0]) {
				for i, mask := range rule.Mask {
					covered[i] |= mask
				}
			}
		}
		for i, mask := range desired.Mask {
			if mask&covered[i] != mask {
				missing = append(missing, desired)
				break
			}
		}
	}
	return missing, nil
}

func checkExecutionSuppressions(existing, wanted []kernelRule) error {
	for _, rule := range existing {
		switch rule.Flags &^ unix.AUDIT_FILTER_PREPEND {
		case unix.AUDIT_FILTER_TASK:
			if rule.Action == unix.AUDIT_NEVER {
				return errors.New("audit: existing never,task rule suppresses process auditing; remove that rule from the VM audit policy and reboot so existing processes receive audit contexts")
			}
		case unix.AUDIT_FILTER_EXIT:
			if rule.Action == unix.AUDIT_NEVER && overlapsExecution(rule, wanted) {
				return errors.New("audit: existing never,exit rule can suppress execution events; revise the conflicting VM audit policy before starting SauronAgent")
			}
		case unix.AUDIT_FILTER_EXCLUDE:
			// The kernel treats this filter as exclusion regardless of action.
			if excludesExecutionRecords(rule) {
				return errors.New("audit: existing exclude rule can suppress execution records; revise the conflicting VM audit policy before starting SauronAgent")
			}
		}
	}
	return nil
}

func overlapsExecution(rule kernelRule, wanted []kernelRule) bool {
	for _, desired := range wanted {
		if !mayMatchArchitecture(rule, desired.Values[0]) {
			continue
		}
		for i, mask := range rule.Mask {
			if mask&desired.Mask[i] != 0 {
				return true
			}
		}
	}
	return false
}

func mayMatchArchitecture(rule kernelRule, arch uint32) bool {
	for i := uint32(0); i < rule.FieldCount; i++ {
		if rule.Fields[i] != unix.AUDIT_ARCH {
			continue
		}
		if rule.FieldFlags[i] == unix.AUDIT_EQUAL && rule.Values[i] != arch {
			return false
		}
		if rule.FieldFlags[i] == unix.AUDIT_NOT_EQUAL && rule.Values[i] == arch {
			return false
		}
	}
	return true
}

func excludesExecutionRecords(rule kernelRule) bool {
	for i := uint32(0); i < rule.FieldCount; i++ {
		if rule.Fields[i] != unix.AUDIT_MSGTYPE || rule.FieldFlags[i] != unix.AUDIT_EQUAL {
			continue
		}
		switch rule.Values[i] {
		case unix.AUDIT_SYSCALL, unix.AUDIT_EXECVE, unix.AUDIT_PROCTITLE, unix.AUDIT_PATH, unix.AUDIT_CWD, unix.AUDIT_EOE:
		default:
			// A message-type equality that only excludes unrelated events is
			// safe. Other selectors could match some executing processes.
			return false
		}
	}
	return true
}

func unconditionalExecutionRule(rule kernelRule, arch uint32) bool {
	if rule.Action != unix.AUDIT_ALWAYS || rule.Flags&^unix.AUDIT_FILTER_PREPEND != unix.AUDIT_FILTER_EXIT {
		return false
	}
	for i := uint32(0); i < rule.FieldCount; i++ {
		switch rule.Fields[i] {
		case unix.AUDIT_ARCH:
			if rule.FieldFlags[i] != unix.AUDIT_EQUAL || rule.Values[i] != arch {
				return false
			}
		case unix.AUDIT_FILTERKEY:
			// Keys label events; they do not narrow execution coverage.
		default:
			return false
		}
	}
	return true
}

func controlError(operation string, err error) error {
	if isPermission(err) {
		return fmt.Errorf("audit: %s: %w (SauronAgent needs CAP_AUDIT_CONTROL; also check whether kernel audit policy is immutable)", operation, err)
	}
	return fmt.Errorf("audit: %s: %w", operation, err)
}
