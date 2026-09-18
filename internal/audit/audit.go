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
	// FilePath is the append-only JSON Lines audit file. It is required and
	// remains the durable record even when HEC forwarding is enabled.
	FilePath string
	// HEC additionally forwards every record to a Splunk HTTP Event Collector
	// when its Endpoint is set.
	HEC HECConfig
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

// Configure directs audit records to options.FilePath as newline-delimited
// JSON and, when options.HEC.Endpoint is set, also to a Splunk HEC.
//
// The file is opened in append mode and created with mode 0640 when absent.
// Missing parent directories are created with mode 0750. HEC delivery happens
// in the background and never blocks or fails audit logging. Ordinary log
// package output continues to use its existing destination. The returned
// closer must remain open while audit records can be emitted; closing it
// restores the previous slog logger and standard log destination, flushes
// queued HEC events, and closes the file.
func Configure(options Options) (io.Closer, error) {
	path := options.FilePath
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("configure audit JSON file: path is empty")
	}

	var forwarder *hecForwarder
	if strings.TrimSpace(options.HEC.Endpoint) != "" {
		var err error
		if forwarder, err = newHECForwarder(options.HEC); err != nil {
			return nil, fmt.Errorf("configure splunk hec forwarding: %w", err)
		}
	}

	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o750); err != nil {
		return nil, fmt.Errorf("create audit log directory %q: %w", directory, err)
	}

	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640) // #nosec G302,G304 -- operator-configured path; group-readable mode allows a log collector to ingest the audit stream
	if err != nil {
		return nil, fmt.Errorf("open audit log file %q: %w", path, err)
	}

	handler := slog.Handler(slog.NewJSONHandler(file, nil))
	if forwarder != nil {
		forwarder.start()
		handler = slog.NewMultiHandler(handler, slog.NewJSONHandler(forwarder, nil))
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

// Close restores the previous process logging state, flushes queued HEC
// events, and closes the audit file.
func (sink *configuredSink) Close() error {
	sink.once.Do(func() {
		slog.SetDefault(sink.previousLogger)
		log.SetOutput(sink.previousLogWriter)
		var forwarderErr error
		if sink.forwarder != nil {
			forwarderErr = sink.forwarder.Close()
		}
		sink.closeErr = errors.Join(forwarderErr, sink.file.Close())
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
