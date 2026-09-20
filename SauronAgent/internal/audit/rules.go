package audit

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"path/filepath"
	"runtime"
	"time"

	"golang.org/x/sys/unix"
)

const (
	auditRuleSize     = 4 * (4 + unix.AUDIT_BITMASK_SIZE + 3*unix.AUDIT_MAX_FIELDS)
	executionRuleKey  = "exec"
	identityRuleKey   = "sauron_identity"
	credentialRuleKey = "sauron_credentials"
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

// auditRule retains the variable string buffer that follows audit_rule_data's
// fixed prefix. String fields refer to consecutive, non-NUL-terminated slices
// of this buffer in field order.
type auditRule struct {
	kernelRule
	buffer string
}

// EnsureManagedRules enables Linux auditing and installs the built-in process
// execution rules and identity/credential file watches. It requires
// CAP_AUDIT_CONTROL, uses no external tools, and never claims the audit daemon
// PID. Existing rules are preserved and reused across restarts. The caller
// should subscribe to audit events before calling this function.
//
// Rules remain active after the agent exits. Immutable policy is accepted only
// when it already provides the complete managed baseline. Suppressing task or
// exit rules produce an actionable error instead of silently starting without
// the promised coverage.
func EnsureManagedRules(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return err
	}
	wanted, err := managedRules(runtime.GOARCH, unix.SYS_EXECVE, unix.SYS_EXECVEAT)
	if err != nil {
		return err
	}
	socket, err := openControlSocket()
	if err != nil {
		return controlError("opening rule-control socket", err)
	}
	defer socket.close()
	client := auditControlClient{transport: socket}
	return ensureManagedRules(ctx, &client, wanted)
}

// EnsureExecutionRules is retained for callers of the original execution-only
// API. The managed baseline now also includes identity and credential watches.
func EnsureExecutionRules(ctx context.Context) error {
	return EnsureManagedRules(ctx)
}

func ensureManagedRules(ctx context.Context, client *auditControlClient, wanted []auditRule) error {
	enabled, err := client.enabled(ctx)
	if err != nil {
		return err
	}
	rules, err := client.rules(ctx)
	if err != nil {
		return err
	}
	missing, err := missingManagedRules(rules, wanted)
	if err != nil {
		return err
	}
	if enabled == 2 && len(missing) != 0 {
		return errors.New("audit: kernel audit policy is immutable and managed rules are missing; configure the execution rules and identity/credential watches before locking the policy and reboot the VM")
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
			return controlError("installing "+managedRuleDescription(rule), err)
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
	return verifyManagedRules(ctx, client, wanted)
}

func verifyManagedRules(ctx context.Context, client *auditControlClient, wanted []auditRule) error {
	enabled, err := client.enabled(ctx)
	if err != nil {
		return err
	}
	if enabled == 0 {
		return errors.New("audit: kernel auditing is still disabled after managed-rule setup")
	}
	rules, err := client.rules(ctx)
	if err != nil {
		return err
	}
	missing, err := missingManagedRules(rules, wanted)
	if err != nil {
		return err
	}
	if len(missing) != 0 {
		return errors.New("audit: managed rules are missing after installation; another audit policy manager may be changing them")
	}
	return nil
}

func managedRules(goarch string, execve, execveat uint32) ([]auditRule, error) {
	rules, err := executionRules(goarch, execve, execveat)
	if err != nil {
		return nil, err
	}
	return append(rules, identityCredentialWatchRules()...), nil
}

// Native syscall numbers are supplied by x/sys/unix for the compiled target.
// Only the i386 compatibility ABI needs an explicit syscall table here.
func executionRules(goarch string, execve, execveat uint32) ([]auditRule, error) {
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
	rules := []auditRule{executionRule(arch, execve, execveat)}
	if goarch == "amd64" {
		rules = append(rules, executionRule(unix.AUDIT_ARCH_I386, 11, 358))
	}
	return rules, nil
}

func executionRule(arch, execve, execveat uint32) auditRule {
	rule := auditRule{
		kernelRule: kernelRule{
			Flags: unix.AUDIT_FILTER_EXIT, Action: unix.AUDIT_ALWAYS,
			FieldCount: 2, BufferLength: uint32(len(executionRuleKey)),
		},
		buffer: executionRuleKey,
	}
	rule.Mask[execve/32] |= 1 << (execve % 32)
	rule.Mask[execveat/32] |= 1 << (execveat % 32)
	rule.Fields[0], rule.Values[0], rule.FieldFlags[0] = unix.AUDIT_ARCH, arch, unix.AUDIT_EQUAL
	rule.Fields[1], rule.Values[1], rule.FieldFlags[1] = unix.AUDIT_FILTERKEY, uint32(len(executionRuleKey)), unix.AUDIT_EQUAL
	return rule
}

func identityCredentialWatchRules() []auditRule {
	specs := [...]struct {
		path string
		key  string
	}{
		{path: "/etc/passwd", key: identityRuleKey},
		{path: "/etc/shadow", key: credentialRuleKey},
		{path: "/etc/group", key: identityRuleKey},
		{path: "/etc/gshadow", key: credentialRuleKey},
		{path: "/etc/security/opasswd", key: credentialRuleKey},
	}
	rules := make([]auditRule, 0, len(specs))
	for _, spec := range specs {
		rules = append(rules, fileWatchRule(spec.path, spec.key))
	}
	return rules
}

func fileWatchRule(path, key string) auditRule {
	rule := auditRule{
		kernelRule: kernelRule{
			Flags: unix.AUDIT_FILTER_EXIT | unix.AUDIT_FILTER_PREPEND, Action: unix.AUDIT_ALWAYS,
			FieldCount: 3, BufferLength: uint32(len(path) + len(key)),
		},
		buffer: path + key,
	}
	for i := range rule.Mask {
		rule.Mask[i] = ^uint32(0)
	}
	rule.Fields[0], rule.Values[0], rule.FieldFlags[0] = unix.AUDIT_WATCH, uint32(len(path)), unix.AUDIT_EQUAL
	rule.Fields[1], rule.Values[1], rule.FieldFlags[1] = unix.AUDIT_PERM, unix.AUDIT_PERM_WRITE|unix.AUDIT_PERM_ATTR, unix.AUDIT_EQUAL
	rule.Fields[2], rule.Values[2], rule.FieldFlags[2] = unix.AUDIT_FILTERKEY, uint32(len(key)), unix.AUDIT_EQUAL
	return rule
}

func marshalKernelRule(rule auditRule) ([]byte, error) {
	if rule.FieldCount > unix.AUDIT_MAX_FIELDS || uint64(rule.BufferLength) != uint64(len(rule.buffer)) {
		return nil, errors.New("audit: malformed kernel audit rule fields or string buffer")
	}
	payload := make([]byte, auditRuleSize+len(rule.buffer))
	if _, err := binary.Encode(payload[:auditRuleSize], binary.NativeEndian, rule.kernelRule); err != nil {
		return nil, fmt.Errorf("audit: encoding kernel audit rule: %w", err)
	}
	copy(payload[auditRuleSize:], rule.buffer)
	return payload, nil
}

func parseKernelRule(payload []byte) (auditRule, error) {
	var rule auditRule
	if len(payload) < auditRuleSize {
		return rule, errors.New("audit: truncated kernel audit rule")
	}
	if _, err := binary.Decode(payload[:auditRuleSize], binary.NativeEndian, &rule.kernelRule); err != nil {
		return rule, fmt.Errorf("audit: decoding kernel audit rule: %w", err)
	}
	if rule.FieldCount > unix.AUDIT_MAX_FIELDS || uint64(rule.BufferLength) != uint64(len(payload)-auditRuleSize) {
		return rule, errors.New("audit: malformed kernel audit rule fields or string buffer")
	}
	rule.buffer = string(payload[auditRuleSize:])
	return rule, nil
}

func missingManagedRules(existing, wanted []auditRule) ([]auditRule, error) {
	executionWanted := make([]auditRule, 0, len(wanted))
	watchWanted := make([]auditRule, 0, len(wanted))
	for _, rule := range wanted {
		if hasRuleField(rule, unix.AUDIT_WATCH) {
			path, key, _, ok := fileWatchRuleParts(rule)
			if !ok || path == "" || key == "" {
				return nil, errors.New("audit: malformed managed file watch")
			}
			watchWanted = append(watchWanted, rule)
			continue
		}
		executionWanted = append(executionWanted, rule)
	}

	missing, err := missingExecutionRules(existing, executionWanted)
	if err != nil {
		return nil, err
	}
	if err := checkFileWatchSuppressions(existing, watchWanted); err != nil {
		return nil, err
	}
	if err := checkFileWatchKeyOrdering(existing, watchWanted, executionWanted); err != nil {
		return nil, err
	}
	for _, desired := range watchWanted {
		if !fileWatchRulesCover(existing, desired) {
			missing = append(missing, desired)
		}
	}
	return missing, nil
}

func missingExecutionRules(existing, wanted []auditRule) ([]auditRule, error) {
	if err := checkExecutionSuppressions(existing, wanted); err != nil {
		return nil, err
	}
	var missing []auditRule
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

func fileWatchCovers(existing, desired auditRule) bool {
	existingPath, existingKey, existingPerms, ok := fileWatchRuleParts(existing)
	if !ok {
		return false
	}
	desiredPath, desiredKey, desiredPerms, ok := fileWatchRuleParts(desired)
	return ok && existingPath == desiredPath && auditKeyContains(existingKey, desiredKey) && existingPerms&desiredPerms == desiredPerms
}

func fileWatchRulesCover(existing []auditRule, desired auditRule) bool {
	desiredPath, desiredKey, desiredPerms, ok := fileWatchRuleParts(desired)
	if !ok {
		return false
	}
	var covered uint32
	for _, rule := range existing {
		path, key, permissions, ok := fileWatchRuleParts(rule)
		if ok && path == desiredPath && auditKeyContains(key, desiredKey) {
			covered |= permissions
		}
	}
	return covered&desiredPerms == desiredPerms
}

func auditKeyContains(keys, wanted string) bool {
	for len(keys) != 0 {
		end := 0
		for end < len(keys) && keys[end] != '\x01' {
			end++
		}
		if keys[:end] == wanted {
			return true
		}
		if end == len(keys) {
			break
		}
		keys = keys[end+1:]
	}
	return false
}

func fileWatchRuleParts(rule auditRule) (path, key string, permissions uint32, ok bool) {
	if rule.Action != unix.AUDIT_ALWAYS || rule.Flags&^unix.AUDIT_FILTER_PREPEND != unix.AUDIT_FILTER_EXIT || rule.FieldCount < 2 || rule.FieldCount > 3 || !allSyscalls(rule.Mask) {
		return "", "", 0, false
	}
	var havePath, haveKey, havePermissions bool
	bufferOffset := 0
	for i := uint32(0); i < rule.FieldCount; i++ {
		field := rule.Fields[i] &^ unix.AUDIT_OPERATORS
		var stringValue string
		if auditStringField(field) {
			length := uint64(rule.Values[i])
			end := uint64(bufferOffset) + length
			if end > uint64(len(rule.buffer)) {
				return "", "", 0, false
			}
			stringValue = rule.buffer[bufferOffset:int(end)]
			bufferOffset = int(end)
		}
		if rule.FieldFlags[i] != unix.AUDIT_EQUAL {
			return "", "", 0, false
		}
		switch field {
		case unix.AUDIT_WATCH:
			if havePath {
				return "", "", 0, false
			}
			path, havePath = stringValue, true
		case unix.AUDIT_PERM:
			if havePermissions {
				return "", "", 0, false
			}
			permissions, havePermissions = rule.Values[i], true
		case unix.AUDIT_FILTERKEY:
			if haveKey {
				return "", "", 0, false
			}
			key, haveKey = stringValue, true
		default:
			return "", "", 0, false
		}
	}
	if bufferOffset != len(rule.buffer) || uint64(rule.BufferLength) != uint64(len(rule.buffer)) {
		return "", "", 0, false
	}
	return path, key, permissions, havePath && havePermissions && (haveKey || rule.FieldCount == 2)
}

func auditStringField(field uint32) bool {
	return field >= unix.AUDIT_SUBJ_USER && field <= unix.AUDIT_OBJ_LEV_HIGH && field != unix.AUDIT_PPID ||
		field == unix.AUDIT_WATCH || field == unix.AUDIT_DIR || field == unix.AUDIT_FILTERKEY || field == unix.AUDIT_EXE
}

func allSyscalls(mask [unix.AUDIT_BITMASK_SIZE]uint32) bool {
	// The final word contains reserved syscall classes that kernels may
	// normalize. auditctl likewise ignores it when identifying a -w watch.
	for _, word := range mask[:unix.AUDIT_BITMASK_SIZE-1] {
		if word != ^uint32(0) {
			return false
		}
	}
	return true
}

func hasRuleField(rule auditRule, wanted uint32) bool {
	for i := uint32(0); i < rule.FieldCount; i++ {
		if rule.Fields[i]&^unix.AUDIT_OPERATORS == wanted {
			return true
		}
	}
	return false
}

func managedRuleDescription(rule auditRule) string {
	path, _, _, ok := fileWatchRuleParts(rule)
	if ok {
		return fmt.Sprintf("file watch for %q", path)
	}
	return "process-execution rule"
}

func checkFileWatchSuppressions(existing, wanted []auditRule) error {
	for _, rule := range existing {
		if rule.Action != unix.AUDIT_NEVER {
			continue
		}
		switch rule.Flags &^ unix.AUDIT_FILTER_PREPEND {
		case unix.AUDIT_FILTER_EXIT:
			for _, desired := range wanted {
				for i, mask := range rule.Mask {
					if mask&desired.Mask[i] != 0 {
						return errors.New("audit: existing never,exit rule can suppress managed file-watch events; revise the conflicting VM audit policy before starting SauronAgent")
					}
				}
			}
		case unix.AUDIT_FILTER_FS:
			for _, desired := range wanted {
				path, _, _, ok := fileWatchRuleParts(desired)
				if ok && filesystemRuleMayMatchPath(rule, path) {
					return fmt.Errorf("audit: existing never,filesystem rule can suppress managed file-watch events for %q; revise the conflicting VM audit policy before starting SauronAgent", path)
				}
			}
		}
	}
	return nil
}

func filesystemRuleMayMatchPath(rule auditRule, path string) bool {
	filesystemType, known := nearestFilesystemType(path)
	if !known {
		return true
	}
	for i := uint32(0); i < rule.FieldCount; i++ {
		if rule.Fields[i]&^unix.AUDIT_OPERATORS != unix.AUDIT_FSTYPE {
			continue
		}
		switch rule.FieldFlags[i] {
		case unix.AUDIT_EQUAL:
			if rule.Values[i] != filesystemType {
				return false
			}
		case unix.AUDIT_NOT_EQUAL:
			if rule.Values[i] == filesystemType {
				return false
			}
		default:
			return true
		}
	}
	return true
}

func nearestFilesystemType(path string) (uint32, bool) {
	for {
		var status unix.Statfs_t
		if err := unix.Statfs(path, &status); err == nil {
			return uint32(status.Type), true
		}
		parent := filepath.Dir(path)
		if parent == path {
			return 0, false
		}
		path = parent
	}
}

func checkFileWatchKeyOrdering(existing, wanted, executionWanted []auditRule) error {
	permissions := [...]uint32{unix.AUDIT_PERM_WRITE, unix.AUDIT_PERM_ATTR}
	for _, desired := range wanted {
		desiredPath, desiredKey, desiredPerms, ok := fileWatchRuleParts(desired)
		// A missing rule will be inserted at the head of the exit filter and
		// therefore outrank every existing rule. Ordering only needs checking
		// when an existing watch is being reused.
		if !ok || !fileWatchRulesCover(existing, desired) {
			continue
		}
		for _, permission := range permissions {
			if desiredPerms&permission == 0 {
				continue
			}
			for _, rule := range existing {
				if rule.Action != unix.AUDIT_ALWAYS || rule.Flags&^unix.AUDIT_FILTER_PREPEND != unix.AUDIT_FILTER_EXIT || !hasAnySyscall(rule.Mask) {
					continue
				}
				path, key, rulePerms, ok := fileWatchRuleParts(rule)
				if ok {
					if path != desiredPath || rulePerms&permission == 0 {
						continue
					}
					if !auditKeyContains(key, desiredKey) {
						return conflictingFileWatchKeyError(desiredPath, desiredKey)
					}
					break
				}
				if onlyManagedExecutionSyscalls(rule, executionWanted) {
					continue
				}
				key, hasKey := auditRuleFilterKey(rule)
				if !hasKey || !auditKeyContains(key, desiredKey) {
					return conflictingFileWatchKeyError(desiredPath, desiredKey)
				}
			}
		}
	}
	return nil
}

func conflictingFileWatchKeyError(path, key string) error {
	return fmt.Errorf("audit: existing higher-priority exit rule can hide key %q for file watch %q; revise the conflicting VM audit policy before starting SauronAgent", key, path)
}

func hasAnySyscall(mask [unix.AUDIT_BITMASK_SIZE]uint32) bool {
	for _, word := range mask {
		if word != 0 {
			return true
		}
	}
	return false
}

func onlyManagedExecutionSyscalls(rule auditRule, wanted []auditRule) bool {
	arch, ok := ruleArchitecture(rule)
	if !ok || !unconditionalExecutionRule(rule, arch) {
		return false
	}
	for _, desired := range wanted {
		if desired.Values[0] != arch {
			continue
		}
		matched := false
		for i, mask := range rule.Mask {
			if mask&^desired.Mask[i] != 0 {
				matched = false
				break
			}
			matched = matched || mask != 0
		}
		if matched {
			return true
		}
	}
	return false
}

func ruleArchitecture(rule auditRule) (uint32, bool) {
	for i := uint32(0); i < rule.FieldCount; i++ {
		if rule.Fields[i]&^unix.AUDIT_OPERATORS != unix.AUDIT_ARCH {
			continue
		}
		return rule.Values[i], rule.FieldFlags[i] == unix.AUDIT_EQUAL
	}
	return 0, false
}

func auditRuleFilterKey(rule auditRule) (string, bool) {
	bufferOffset := 0
	key := ""
	found := false
	for i := uint32(0); i < rule.FieldCount; i++ {
		field := rule.Fields[i] &^ unix.AUDIT_OPERATORS
		if !auditStringField(field) {
			continue
		}
		end := uint64(bufferOffset) + uint64(rule.Values[i])
		if end > uint64(len(rule.buffer)) {
			return "", false
		}
		if field == unix.AUDIT_FILTERKEY {
			if found {
				return "", false
			}
			key, found = rule.buffer[bufferOffset:int(end)], true
		}
		bufferOffset = int(end)
	}
	if bufferOffset != len(rule.buffer) || uint64(rule.BufferLength) != uint64(len(rule.buffer)) {
		return "", false
	}
	return key, found
}

func checkExecutionSuppressions(existing, wanted []auditRule) error {
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

func overlapsExecution(rule auditRule, wanted []auditRule) bool {
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

func mayMatchArchitecture(rule auditRule, arch uint32) bool {
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

func excludesExecutionRecords(rule auditRule) bool {
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

func unconditionalExecutionRule(rule auditRule, arch uint32) bool {
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
