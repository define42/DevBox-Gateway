// Package audit emits structured records for security-relevant user actions.
package audit

import (
	"context"
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

// configuredJSONFile owns an audit file and the process logging state that was
// active before ConfigureJSONFile installed the audit logger.
type configuredJSONFile struct {
	file              *os.File
	previousLogger    *slog.Logger
	previousLogWriter io.Writer
	once              sync.Once
	closeErr          error
}

// ConfigureJSONFile directs audit records to path as newline-delimited JSON.
//
// The file is opened in append mode and created with mode 0640 when absent.
// Missing parent directories are created with mode 0750. Ordinary log package
// output continues to use its existing destination. The returned closer must
// remain open while audit records can be emitted; closing it restores the
// previous slog logger and standard log destination before closing the file.
func ConfigureJSONFile(path string) (io.Closer, error) {
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

	previousLogger := slog.Default()
	previousLogWriter := log.Writer()
	slog.SetDefault(slog.New(slog.NewJSONHandler(file, nil)))
	// slog.SetDefault also routes the standard log package through slog. Keep
	// operational log.Printf output on the destination selected by the caller.
	log.SetOutput(previousLogWriter)

	return &configuredJSONFile{
		file:              file,
		previousLogger:    previousLogger,
		previousLogWriter: previousLogWriter,
	}, nil
}

// Close restores the previous process logging state and closes the audit file.
func (file *configuredJSONFile) Close() error {
	file.once.Do(func() {
		slog.SetDefault(file.previousLogger)
		log.SetOutput(file.previousLogWriter)
		file.closeErr = file.file.Close()
	})
	return file.closeErr
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
