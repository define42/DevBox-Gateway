// Package config defines and loads the YAML configuration for both the guest
// agent and the host collector.
package config

import (
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"
)

// Duration wraps time.Duration with YAML support for Go duration strings such
// as "30s" or "2m30s".
type Duration time.Duration

// UnmarshalYAML implements yaml.Unmarshaler.
func (d *Duration) UnmarshalYAML(unmarshal func(any) error) error {
	var s string
	if err := unmarshal(&s); err != nil {
		// Allow a bare number, interpreted as seconds.
		var n int64
		if err2 := unmarshal(&n); err2 != nil {
			return fmt.Errorf("duration must be a string like \"30s\": %w", err)
		}
		*d = Duration(time.Duration(n) * time.Second)
		return nil
	}
	parsed, err := time.ParseDuration(strings.TrimSpace(s))
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", s, err)
	}
	*d = Duration(parsed)
	return nil
}

// MarshalYAML implements yaml.Marshaler.
func (d Duration) MarshalYAML() (any, error) { return d.Duration().String(), nil }

// Duration returns the wrapped time.Duration.
func (d Duration) Duration() time.Duration { return time.Duration(d) }

// String implements fmt.Stringer.
func (d Duration) String() string { return d.Duration().String() }

// Size is a byte quantity that accepts human-readable YAML values such as
// "1GiB", "512MB" or a plain integer count of bytes.
type Size int64

var sizeUnits = []struct {
	suffix string
	mult   int64
}{
	// Longest suffixes first so that "GiB" is not matched as "B".
	{"KIB", 1 << 10}, {"MIB", 1 << 20}, {"GIB", 1 << 30}, {"TIB", 1 << 40},
	{"KB", 1000}, {"MB", 1000 * 1000}, {"GB", 1000 * 1000 * 1000}, {"TB", 1000 * 1000 * 1000 * 1000},
	{"K", 1 << 10}, {"M", 1 << 20}, {"G", 1 << 30}, {"T", 1 << 40},
	{"B", 1},
}

// ParseSize parses a byte quantity such as "1GiB" or "1048576".
func ParseSize(s string) (Size, error) {
	trimmed := strings.TrimSpace(s)
	if trimmed == "" {
		return 0, fmt.Errorf("empty size")
	}
	upper := strings.ToUpper(trimmed)
	for _, u := range sizeUnits {
		if !strings.HasSuffix(upper, u.suffix) {
			continue
		}
		numPart := strings.TrimSpace(upper[:len(upper)-len(u.suffix)])
		if numPart == "" {
			continue
		}
		value, err := strconv.ParseFloat(numPart, 64)
		if err != nil {
			return 0, fmt.Errorf("invalid size %q: %w", s, err)
		}
		if value < 0 {
			return 0, fmt.Errorf("invalid size %q: must not be negative", s)
		}
		scaled := value * float64(u.mult)
		if scaled > math.MaxInt64 {
			return 0, fmt.Errorf("invalid size %q: overflows int64", s)
		}
		return Size(scaled), nil
	}
	n, err := strconv.ParseInt(upper, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid size %q: want a byte count or a value like \"1GiB\"", s)
	}
	if n < 0 {
		return 0, fmt.Errorf("invalid size %q: must not be negative", s)
	}
	return Size(n), nil
}

// UnmarshalYAML implements yaml.Unmarshaler.
func (z *Size) UnmarshalYAML(unmarshal func(any) error) error {
	var s string
	if err := unmarshal(&s); err == nil {
		parsed, perr := ParseSize(s)
		if perr != nil {
			return perr
		}
		*z = parsed
		return nil
	}
	var n int64
	if err := unmarshal(&n); err != nil {
		return fmt.Errorf("size must be a byte count or a value like \"1GiB\"")
	}
	if n < 0 {
		return fmt.Errorf("size must not be negative")
	}
	*z = Size(n)
	return nil
}

// MarshalYAML implements yaml.Marshaler.
func (z Size) MarshalYAML() (any, error) { return z.String(), nil }

// Bytes returns the size as a plain byte count.
func (z Size) Bytes() int64 { return int64(z) }

// String renders the size using binary units.
func (z Size) String() string {
	n := int64(z)
	switch {
	case n >= 1<<40:
		return fmt.Sprintf("%.4gTiB", float64(n)/float64(int64(1)<<40))
	case n >= 1<<30:
		return fmt.Sprintf("%.4gGiB", float64(n)/float64(int64(1)<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.4gMiB", float64(n)/float64(int64(1)<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.4gKiB", float64(n)/float64(int64(1)<<10))
	default:
		return fmt.Sprintf("%dB", n)
	}
}
