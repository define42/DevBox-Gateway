package config

import (
	"bytes"
	"fmt"
	"io"
	"slices"
)

func strictReader(data []byte) io.Reader { return bytes.NewReader(data) }

var (
	validLevels  = []string{"debug", "info", "warn", "error"}
	validFormats = []string{"text", "json"}
)

func validateLogging(l LoggingSection) error {
	if !slices.Contains(validLevels, l.Level) {
		return fmt.Errorf("logging.level must be one of %v, got %q", validLevels, l.Level)
	}
	if !slices.Contains(validFormats, l.Format) {
		return fmt.Errorf("logging.format must be one of %v, got %q", validFormats, l.Format)
	}
	if l.Output == "" {
		return fmt.Errorf("logging.output must be set")
	}
	return nil
}
