package output

import (
	"errors"

	"github.com/define42/SauronAgent/internal/config"
)

// errNoOutputs reports a collector configured to write events nowhere.
//
// This is treated as a configuration error rather than an empty fan-out on
// purpose. A collector with no sink accepts guest connections, acknowledges
// every event and discards all of it, which looks exactly like a healthy
// deployment right up to the incident where the evidence is needed.
var errNoOutputs = errors.New("output: no output is enabled; enable at least one of output.stdout, output.file or output.syslog")

// Build constructs every enabled sink in cfg and fans events out to all of
// them. It fails if nothing is enabled.
func Build(cfg config.OutputSection) (Sink, error) {
	var sinks []Sink
	// A sink that has already been opened holds a file descriptor or a daemon
	// connection, so a later constructor failing must not leak it.
	fail := func(err error) (Sink, error) {
		for _, s := range sinks {
			_ = s.Close()
		}
		return nil, err
	}

	if cfg.Stdout.Enabled {
		s, err := NewStdout(cfg.Stdout)
		if err != nil {
			return fail(err)
		}
		sinks = append(sinks, s)
	}
	if cfg.File.Enabled {
		s, err := NewFile(cfg.File)
		if err != nil {
			return fail(err)
		}
		sinks = append(sinks, s)
	}
	if cfg.Syslog.Enabled {
		s, err := NewSyslog(cfg.Syslog)
		if err != nil {
			return fail(err)
		}
		sinks = append(sinks, s)
	}
	if len(sinks) == 0 {
		return nil, errNoOutputs
	}
	return NewMulti(sinks...), nil
}
