// Package logging sets up SauronAgent's diagnostic logging.
//
// This is deliberately separate from the audit events the agent forwards.
// Diagnostic logs describe the agent's own health; audit events describe the
// guest. Conflating them would mean a host outage could only be discovered by
// reading a log file inside the guest that an intruder can edit.
package logging

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"

	"github.com/define42/SauronAgent/internal/config"
)

// New builds a slog.Logger from a logging configuration, returning the logger
// and a closer for the output file when one was opened.
func New(cfg config.LoggingSection) (*slog.Logger, io.Closer, error) {
	var level slog.Level
	switch strings.ToLower(cfg.Level) {
	case "debug":
		level = slog.LevelDebug
	case "info":
		level = slog.LevelInfo
	case "warn", "warning":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		return nil, nil, fmt.Errorf("unknown log level %q", cfg.Level)
	}

	var (
		w      io.Writer
		closer io.Closer
	)
	switch cfg.Output {
	case "", "stderr":
		w = os.Stderr
	case "stdout":
		w = os.Stdout
	default:
		f, err := os.OpenFile(cfg.Output, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
		if err != nil {
			return nil, nil, fmt.Errorf("opening log file %s: %w", cfg.Output, err)
		}
		w, closer = f, f
	}

	opts := &slog.HandlerOptions{Level: level}
	var handler slog.Handler
	switch strings.ToLower(cfg.Format) {
	case "json":
		handler = slog.NewJSONHandler(w, opts)
	case "text", "":
		handler = slog.NewTextHandler(w, opts)
	default:
		if closer != nil {
			_ = closer.Close()
		}
		return nil, nil, fmt.Errorf("unknown log format %q", cfg.Format)
	}
	return slog.New(handler), closer, nil
}

// Discard returns a logger that writes nothing, for use in tests.
func Discard() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError + 1}))
}
