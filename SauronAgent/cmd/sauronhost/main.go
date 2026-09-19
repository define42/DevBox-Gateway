// Command sauronhost is the hypervisor-side collector. It listens on
// AF_VSOCK, identifies each guest by the CID its connection arrives on,
// validates and enriches the events it receives and writes them to the
// configured sinks.
//
// Usage:
//
//	sauronhost -config /etc/sauronhost/sauronhost.yaml
//	sauronhost -check-config -config /etc/sauronhost/sauronhost.yaml
//	sauronhost -version
//
// It runs on the KVM host, not inside a VM, and holds no capability at all:
// everything it parses was written by a guest that must be assumed hostile.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/define42/SauronAgent/internal/config"
	"github.com/define42/SauronAgent/internal/host"
	"github.com/define42/SauronAgent/internal/identity"
	"github.com/define42/SauronAgent/internal/logging"
	"github.com/define42/SauronAgent/internal/metrics"
	"github.com/define42/SauronAgent/internal/output"
)

// progName prefixes everything written to the terminal.
const progName = "sauronhost"

// Exit statuses.
//
// The shipped unit is Restart=always with the start rate limit disabled: a
// collector that has stopped is a hypervisor whose guests are all silently
// unmonitored, so a non-zero status here means "restart me and keep saying so
// in the journal".
const (
	exitOK      = 0
	exitFailure = 1
	// exitUsage follows the flag package's own convention for a command line
	// that could not be parsed.
	exitUsage = 2
)

func main() {
	os.Exit(run(context.Background(), os.Args[1:], os.Stdout, os.Stderr))
}

// run is main's body with its arguments and output streams passed in, so the
// tests can drive the whole startup path in process. It returns the exit
// status; it never calls os.Exit itself, except on the second signal, where
// exiting immediately is the point.
func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet(progName, flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.Usage = func() { usage(stderr, flags) }

	configPath := flags.String("config", "", "configuration `file` to load")
	showVersion := flags.Bool("version", false, "print the version and exit")
	checkConfig := flags.Bool("check-config", false, "load and validate the configuration, report the result and exit")

	switch err := flags.Parse(args); {
	case errors.Is(err, flag.ErrHelp):
		return exitOK
	case err != nil:
		// flag has already written the error and the usage to stderr.
		return exitUsage
	}
	// A stray argument is far more likely to be a mistyped flag than something
	// the operator wanted ignored, and this program's flags decide which VMs
	// are collected at all.
	if flags.NArg() > 0 {
		fmt.Fprintf(stderr, "%s: unexpected argument %q\n", progName, flags.Arg(0))
		flags.Usage()
		return exitUsage
	}

	if *showVersion {
		fmt.Fprintf(stdout, "%s %s\n", progName, identity.Version)
		fmt.Fprintf(stdout, "%s %s/%s\n", runtime.Version(), runtime.GOOS, runtime.GOARCH)
		return exitOK
	}

	// The CID map in this file is the only authoritative statement of which VM
	// an event came from. A collector that started on a configuration it did
	// not fully understand could mislabel an audit trail, so anything the
	// loader rejects is fatal.
	cfg, err := config.LoadHost(*configPath)
	if err != nil {
		fmt.Fprintf(stderr, "%s: %v\n", progName, err)
		return exitFailure
	}

	if *checkConfig {
		fmt.Fprintf(stdout, "%s: %s is valid\n", progName, configDescription(*configPath))
		writeSummary(stdout, cfg)
		return exitOK
	}

	if *configPath == "" {
		// The defaults listen on VMADDR_CID_ANY with an empty CID map, so
		// every guest arrives unknown. Usable for a smoke test, wrong for a
		// deployment, and silence about it would hide a mispointed unit.
		fmt.Fprintf(stderr, "%s: no -config given; running on the built-in defaults, "+
			"which map no VMs at all\n", progName)
	}

	logger, closer, err := logging.New(cfg.Logging)
	if err != nil {
		fmt.Fprintf(stderr, "%s: %v\n", progName, err)
		return exitFailure
	}
	if closer != nil {
		defer func() { _ = closer.Close() }()
	}

	// Logged before anything is opened, so that a collector that fails to
	// start still says in the journal what it was trying to be.
	logStartup(logger, cfg)

	// Build the sinks before the listener: a collector that accepts guests and
	// then discovers it has nowhere to write them would acknowledge events it
	// is about to lose. Build refuses a configuration with no sink enabled for
	// the same reason.
	sink, err := output.Build(cfg.Output)
	if err != nil {
		logger.Error("no usable output", "error", err)
		fmt.Fprintf(stderr, "%s: %v\n", progName, err)
		return exitFailure
	}

	counters := &metrics.Host{}
	srv, err := host.New(host.Options{
		Config:  cfg,
		Sink:    sink,
		Metrics: counters,
		Logger:  logger,
	})
	if err != nil {
		// The server never took ownership of the sink, so this is the one path
		// that has to close it here.
		if cerr := sink.Close(); cerr != nil {
			logger.Error("closing the output after a failed start", "error", cerr)
		}
		logger.Error("collector failed to start", "error", err)
		fmt.Fprintf(stderr, "%s: %v\n", progName, err)
		if hint := startupHint(cfg, err); hint != "" {
			fmt.Fprintf(stderr, "%s: %s\n", progName, hint)
			logger.Error("startup hint", "hint", hint)
		}
		return exitFailure
	}

	ctx, stop := installSignalHandler(ctx, stderr)
	defer stop()

	runErr := srv.Run(ctx)

	// Close flushes and closes the sinks. Losing the tail of the log on a
	// restart would be exactly the silent evidence loss this collector exists
	// to prevent, and it is also what a buffered file sink would do if the
	// process simply exited. Close is idempotent, so calling it after Run has
	// already torn down is free.
	closeErr := srv.Close()

	snap := counters.Snapshot()
	if err := errors.Join(runErr, closeErr); err != nil {
		logger.Error("sauronhost stopped with an error",
			"error", err,
			"events_received", snap.EventsReceived,
			"events_output", snap.EventsOutput,
			"output_errors", snap.OutputErrors)
		fmt.Fprintf(stderr, "%s: %v\n", progName, err)
		return exitFailure
	}
	if snap.OutputErrors > 0 || snap.StreamsLost > 0 {
		// Neither is lost evidence by itself -- a refused write is not
		// acknowledged, so the guest still holds the event -- but both mean
		// this collector was not doing its job for part of the run.
		logger.Warn("the collector did not deliver everything it received",
			"output_errors", snap.OutputErrors,
			"streams_lost", snap.StreamsLost,
			"frame_errors", snap.FrameErrors)
	}
	logger.Info("sauronhost stopped",
		"connections_accepted", snap.ConnectionsAccepted,
		"events_received", snap.EventsReceived,
		"events_duplicate", snap.EventsDuplicate,
		"events_output", snap.EventsOutput,
		"output_errors", snap.OutputErrors,
		"streams_lost", snap.StreamsLost)
	return exitOK
}

// usage prints the command line, naming the path the shipped unit uses.
func usage(w io.Writer, flags *flag.FlagSet) {
	fmt.Fprintf(w, "usage: %s [-config file] [-check-config] [-version]\n", progName)
	fmt.Fprintf(w, "\nSauronHost collects audit events from guest VMs over AF_VSOCK.\n")
	fmt.Fprintf(w, "It runs on the hypervisor. The shipped systemd unit runs:\n")
	fmt.Fprintf(w, "\n  %s -config /etc/sauronhost/sauronhost.yaml\n\n", progName)
	flags.PrintDefaults()
}

// configDescription names the configuration being reported on, including the
// case where there is no file at all.
func configDescription(path string) string {
	if path == "" {
		return "the built-in default configuration"
	}
	return path
}

// writeSummary prints what -check-config reports on top of "valid": the
// listener, how many VMs are mapped and where events will be written. A file
// that parses can still be wrong in ways only a human notices -- a CID map
// that is a VM short, or every sink disabled -- and these are the lines that
// make that visible.
func writeSummary(w io.Writer, cfg config.Host) {
	fmt.Fprintf(w, "  hypervisor: %s\n", cfg.Host.Name)
	fmt.Fprintf(w, "  listen:     %s\n", listenDescription(cfg))
	fmt.Fprintf(w, "  vms:        %d mapped, %d expected to be always present\n",
		len(cfg.VMs), expectedVMs(cfg))
	fmt.Fprintf(w, "  unknown:    %s\n", unknownCIDPolicy(cfg))
	fmt.Fprintf(w, "  outputs:    %s\n", sinkDescription(cfg))
	fmt.Fprintf(w, "  monitor:    %s\n", monitorDescription(cfg))
	fmt.Fprintf(w, "  limits:     max_connections=%d per_cid=%d max_payload=%s dedup_window=%d\n",
		cfg.Limits.MaxConnections, cfg.Limits.MaxConnectionsPerCID,
		cfg.Limits.MaxPayloadSize, cfg.Limits.DedupWindow)
	fmt.Fprintf(w, "  logging:    level=%s format=%s output=%s\n",
		cfg.Logging.Level, cfg.Logging.Format, cfg.Logging.Output)
}

// logStartup records the listener, the size of the CID map and the sinks.
//
// Those three are what an operator needs to tell a collector that is up from
// one that is up and useless: bound to the wrong CID, mapping no VMs, or
// writing to a sink nobody reads. It is a summary and not a dump of the
// configuration, which -check-config prints in full.
func logStartup(log *slog.Logger, cfg config.Host) {
	log.Info("sauronhost starting",
		"version", identity.Version,
		"hypervisor", cfg.Host.Name,
		"listen", listenDescription(cfg),
		"mapped_vms", len(cfg.VMs),
		"expected_vms", expectedVMs(cfg),
		"outputs", sinkDescription(cfg),
		"allow_unknown_cids", cfg.Limits.AllowUnknownCIDs,
		"monitor_enabled", cfg.Monitor.Enabled,
		"max_connections", cfg.Limits.MaxConnections)
}

// listenDescription renders the listening socket, spelling out the wildcard
// CID: "4294967295" means nothing to a reader, and binding a specific CID by
// accident makes the collector deaf to every other guest.
func listenDescription(cfg config.Host) string {
	if cfg.Listen.Kind == config.TransportTCP {
		return "tcp " + cfg.Listen.TCPAddress + " (development transport; a TCP peer is not an authenticated VM)"
	}
	cid := strconv.FormatUint(uint64(cfg.Listen.CID), 10)
	if cfg.Listen.CID == config.VMADDR_CID_ANY {
		cid = "any"
	}
	return fmt.Sprintf("vsock cid %s port %d", cid, cfg.Listen.Port)
}

// expectedVMs counts the VMs whose stream must always be present. They are the
// ones sauron.stream.lost is raised for.
func expectedVMs(cfg config.Host) int {
	n := 0
	for _, vm := range cfg.VMs {
		if vm.Expected {
			n++
		}
	}
	return n
}

// unknownCIDPolicy states what happens to a guest with no entry in vms.
func unknownCIDPolicy(cfg config.Host) string {
	if cfg.Limits.AllowUnknownCIDs {
		return "CIDs not listed in vms are accepted and recorded with a synthetic name"
	}
	return "CIDs not listed in vms are refused (their audit streams are not collected)"
}

// sinkDescription lists the enabled sinks with their destinations.
func sinkDescription(cfg config.Host) string {
	var enabled []string
	if cfg.Output.Stdout.Enabled {
		enabled = append(enabled, "stdout")
	}
	if cfg.Output.File.Enabled {
		enabled = append(enabled, "file "+cfg.Output.File.Path)
	}
	if cfg.Output.Syslog.Enabled {
		enabled = append(enabled, "syslog "+syslogDescription(cfg.Output.Syslog))
	}
	if len(enabled) == 0 {
		// Validation allows this; output.Build refuses it at startup, because
		// a collector with no sink acknowledges every event and discards it.
		return "none -- the collector will refuse to start"
	}
	return strings.Join(enabled, ", ")
}

// syslogDescription renders the syslog destination, local socket included.
func syslogDescription(cfg config.SyslogOutput) string {
	if cfg.Network == "" {
		return "(local socket, tag " + cfg.Tag + ")"
	}
	return fmt.Sprintf("%s %s (tag %s)", cfg.Network, cfg.Address, cfg.Tag)
}

// monitorDescription renders the stream-health watch, which is what turns a VM
// that has gone quiet into an alert.
func monitorDescription(cfg config.Host) string {
	if !cfg.Monitor.Enabled {
		return "disabled -- a VM that stops sending will not be reported"
	}
	return fmt.Sprintf("enabled, timeout %s, checked every %s",
		cfg.Monitor.Timeout, cfg.Monitor.CheckInterval)
}

// startupHint answers the two ways the collector usually fails to start with
// something an operator can act on. Both look like a broken program and are
// neither.
func startupHint(cfg config.Host, err error) string {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "no AF_VSOCK transport"):
		return "the hypervisor needs the vsock module loaded (modprobe vhost_vsock) before the " +
			"collector can bind. If it is loaded, check that RestrictAddressFamilies= in " +
			"/usr/lib/systemd/system/sauronhost.service still lists AF_VSOCK: a unit that does not " +
			"gets EAFNOSUPPORT, which reads exactly like a missing module"
	case strings.Contains(msg, "address already in use"):
		return fmt.Sprintf("another process already holds %s. Only one listener can have the port: "+
			"stop the other collector, or the socat used to test the path by hand",
			listenDescription(cfg))
	}
	return ""
}

// installSignalHandler arranges the two-stage shutdown and returns a context
// that the first signal cancels, plus a function that removes the handler.
func installSignalHandler(ctx context.Context, stderr io.Writer) (context.Context, func()) {
	ctx, cancel := context.WithCancel(ctx)

	// Depth 2: the second signal is the one that has to get through, and the
	// signal package drops a delivery that finds the channel full.
	sigs := make(chan os.Signal, 2)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	done := make(chan struct{})
	go watchSignals(done, sigs, cancel, stderr, os.Exit)

	var once sync.Once
	return ctx, func() {
		once.Do(func() {
			signal.Stop(sigs)
			close(done)
		})
		cancel()
	}
}

// watchSignals implements the shutdown contract: the first SIGINT or SIGTERM
// cancels the root context, which stops accepting new guests, lets the live
// sessions finish what they were writing and closes the sinks. A second signal
// ends the process there and then.
//
// The second stage matters more here than in the agent. An event that was
// received but not yet acknowledged is still held by its guest and will be
// re-sent, but an event already written to a buffered sink and not yet flushed
// exists nowhere else, so the first stage must be allowed to finish whenever
// an operator can wait -- and must be interruptible when they cannot.
//
// Both notices go to stderr rather than through the logger, which may be
// writing to a file on the filesystem that is wedged.
func watchSignals(done <-chan struct{}, sigs <-chan os.Signal, cancel context.CancelFunc, stderr io.Writer, exit func(int)) {
	select {
	case <-done:
		return
	case s := <-sigs:
		fmt.Fprintf(stderr, "%s: signal %q received; draining guest sessions and flushing the outputs "+
			"(signal again to exit immediately)\n", progName, s.String())
		cancel()
	}

	select {
	case <-done:
		return
	case s := <-sigs:
		fmt.Fprintf(stderr, "%s: signal %q received again; exiting now, unflushed events are lost and "+
			"unacknowledged ones will be re-sent by the guests\n", progName, s.String())
		exit(signalExitCode(s))
	}
}

// signalExitCode follows the shell convention of 128+signal, so a supervisor
// can tell a process that was told to stop from one that failed.
func signalExitCode(s os.Signal) int {
	if ss, ok := s.(syscall.Signal); ok {
		return 128 + int(ss)
	}
	return exitFailure
}
