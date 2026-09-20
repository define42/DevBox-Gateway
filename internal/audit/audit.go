// Package audit emits structured records for security-relevant user actions.
package audit

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	// ActionUserLogin records a gateway login outcome.
	ActionUserLogin = "user.login"
	// ActionUserLogout records a gateway logout.
	ActionUserLogout = "user.logout"

	// ActionVMCreate records a VM creation outcome.
	ActionVMCreate = "vm.create"
	// ActionVMStart records a VM start outcome.
	ActionVMStart = "vm.start"
	// ActionVMStop records a VM stop outcome.
	ActionVMStop = "vm.stop"
	// ActionVMReboot records a VM reboot outcome.
	ActionVMReboot = "vm.reboot"
	// ActionVMRemove records a VM removal outcome.
	ActionVMRemove = "vm.remove"

	// ActionConnectionConnect records a successful user connection.
	ActionConnectionConnect = "connection.connect"
	// ActionConnectionDisconnect records a user disconnection.
	ActionConnectionDisconnect = "connection.disconnect"

	// ActionAdminBaseImageUpload records an administrator base-image upload outcome.
	ActionAdminBaseImageUpload = "admin.base_image.upload"
	// ActionAdminBaseImageDelete records an administrator base-image deletion outcome.
	ActionAdminBaseImageDelete = "admin.base_image.delete"

	// ProtocolNoVNC identifies a noVNC connection.
	ProtocolNoVNC = "novnc"
	// ProtocolSerial identifies a serial-console connection.
	ProtocolSerial = "serial"
	// ProtocolRDP identifies an RDP connection.
	ProtocolRDP = "rdp"

	// ResultSuccess records a completed action.
	ResultSuccess = "success"
	// ResultFailure records an action that did not complete.
	ResultFailure = "failure"

	// OperationLoginOriginRejected identifies a login rejected by the
	// same-origin gate before credentials are processed.
	OperationLoginOriginRejected = "origin_rejected"
	// OperationLoginMalformedRequest identifies a login request whose form
	// could not be parsed safely.
	OperationLoginMalformedRequest = "malformed_request"
	// OperationLoginMissingCredentials identifies a login request without both
	// a username and password.
	OperationLoginMissingCredentials = "missing_credentials"
	// OperationLoginRateLimited identifies a login rejected by brute-force
	// protection.
	OperationLoginRateLimited = "rate_limited"
	// OperationLoginInvalidUsername identifies a login with a username outside
	// the gateway's accepted identity syntax.
	OperationLoginInvalidUsername = "invalid_username"
	// OperationLoginAuthenticationFailed identifies credentials rejected by the
	// configured identity provider.
	OperationLoginAuthenticationFailed = "authentication_failed"
	// OperationLoginSessionFailed identifies an authenticated login whose
	// browser session could not be established or persisted.
	OperationLoginSessionFailed = "session_failed"

	// OperationLogoutExplicit identifies a user-requested logout.
	OperationLogoutExplicit = "explicit"
	// OperationLogoutTimeout identifies automatic session expiry.
	OperationLogoutTimeout = "timeout"
	// OperationLogoutClientIPChanged identifies a session invalidated after its
	// request source no longer matched the address bound at login.
	OperationLogoutClientIPChanged = "client_ip_changed"
)

// Event describes one security-relevant user action.
type Event struct {
	Action        string
	User          string
	Result        string
	SourceIP      string
	VM            string
	ResourceType  string
	Resource      string
	Protocol      string
	Operation     string
	Administrator bool
	Duration      time.Duration
}

// Options selects where audit records are written.
type Options struct {
	// FilePath is the append-only JSON Lines audit file used when HEC is
	// disabled. It is required in file-only mode and ignored in HEC-only mode.
	FilePath string
	// HEC forwards records exclusively to a Splunk HTTP Event Collector when
	// its Endpoint is set. Records are durably spooled until HEC accepts them.
	HEC HECConfig
	// SpoolDir and SpoolMaxBytes configure the persistent application-audit
	// buffer. HEC mode requires a directory and a positive byte limit; file-only
	// mode ignores both fields.
	SpoolDir      string
	SpoolMaxBytes int64
}

// configuredSink owns the audit destinations and the process logging state
// that was active before Configure installed the audit logger.
type configuredSink struct {
	file              *os.File
	forwarder         *hecForwarder
	previousLogger    *slog.Logger
	previousLogWriter io.Writer
	once              sync.Once
	closeErr          error
}

// Configure directs audit records exclusively to Splunk HEC when its Endpoint
// is set, or to options.FilePath as newline-delimited JSON otherwise.
//
// HEC-only mode never opens or modifies FilePath and does not fall back to it
// during delivery failures. HEC delivery happens in the background from a
// bounded disk spool. Writes wait for space instead of evicting pending events.
// File-only mode requires FilePath, opens it in append mode with mode 0640 when
// absent, and creates missing parent directories with mode 0750. Ordinary log
// package output keeps its existing destination. Keep the returned closer open
// while audit records can be emitted; closing it restores the previous logging
// state and attempts a bounded HEC drain (retaining pending records) or closes
// the file. Storage failures are reported through the operational log.
func Configure(options Options) (io.Closer, error) {
	var file *os.File
	var forwarder *hecForwarder
	var handler slog.Handler
	if strings.TrimSpace(options.HEC.Endpoint) != "" {
		var err error
		if forwarder, err = newHECForwarder(options.HEC, options.SpoolDir, options.SpoolMaxBytes); err != nil {
			return nil, fmt.Errorf("configure splunk hec forwarding: %w", err)
		}
		forwarder.start()
		handler = slog.NewJSONHandler(forwarder, nil)
	} else {
		var err error
		file, err = openAuditFile(options.FilePath)
		if err != nil {
			return nil, err
		}
		handler = slog.NewJSONHandler(file, nil)
	}

	previousLogger := slog.Default()
	previousLogWriter := log.Writer()
	slog.SetDefault(slog.New(handler))
	// slog.SetDefault also routes the standard log package through slog. Keep
	// operational log.Printf output on the destination selected by the caller.
	log.SetOutput(previousLogWriter)

	return &configuredSink{
		file:              file,
		forwarder:         forwarder,
		previousLogger:    previousLogger,
		previousLogWriter: previousLogWriter,
	}, nil
}

func openAuditFile(path string) (*os.File, error) {
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("configure audit JSON file: path is empty")
	}
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o750); err != nil {
		return nil, fmt.Errorf("create audit log directory %q: %w", directory, err)
	}
	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640) // #nosec G302,G304 -- operator-configured path; group-readable mode allows a log collector to ingest the audit stream
	if err != nil {
		return nil, fmt.Errorf("open audit log file %q: %w", path, err)
	}
	return file, nil
}

// BeginShutdown bounds capacity waits before the gateway drains workers that
// may be blocked logging. Already persisted events remain safe for replay.
func (sink *configuredSink) BeginShutdown() {
	if sink.forwarder != nil {
		sink.forwarder.beginShutdown()
	}
}

// Close restores the previous process logging state and attempts delivery of
// pending HEC events or closes the audit file. Pending HEC records remain on disk.
func (sink *configuredSink) Close() error {
	sink.once.Do(func() {
		slog.SetDefault(sink.previousLogger)
		log.SetOutput(sink.previousLogWriter)
		var forwarderErr error
		if sink.forwarder != nil {
			forwarderErr = sink.forwarder.Close()
		}
		var fileErr error
		if sink.file != nil {
			fileErr = sink.file.Close()
		}
		sink.closeErr = errors.Join(forwarderErr, fileErr)
	})
	return sink.closeErr
}

// Log emits event as one structured Info record through the default slog logger.
func Log(ctx context.Context, event Event) {
	result := event.Result
	if result == "" {
		result = ResultSuccess
	}
	attrs := []slog.Attr{
		slog.String("action", event.Action),
		slog.String("user", event.User),
		slog.String("result", result),
	}
	attrs = appendOptionalString(attrs, "source_ip", event.SourceIP)
	attrs = appendOptionalString(attrs, "vm", event.VM)
	attrs = appendOptionalString(attrs, "resource_type", event.ResourceType)
	attrs = appendOptionalString(attrs, "resource", event.Resource)
	attrs = appendOptionalString(attrs, "protocol", event.Protocol)
	attrs = appendOptionalString(attrs, "operation", event.Operation)
	if event.Administrator {
		attrs = append(attrs, slog.Bool("administrator", true))
	}
	if event.Duration > 0 {
		attrs = append(attrs, slog.Int64("duration_ms", event.Duration.Milliseconds()))
	}

	slog.LogAttrs(ctx, slog.LevelInfo, "audit", attrs...)
}

func appendOptionalString(attrs []slog.Attr, key, value string) []slog.Attr {
	if value == "" {
		return attrs
	}
	return append(attrs, slog.String(key, value))
}
