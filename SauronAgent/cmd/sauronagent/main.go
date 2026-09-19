// Command sauronagent is the guest-side agent. It reads the kernel's
// NETLINK_AUDIT stream, correlates and normalizes what it finds and forwards
// the result to the hypervisor's collector over AF_VSOCK.
//
// Usage:
//
//	sauronagent
//	sauronagent -config /etc/sauronagent/sauronagent.yaml
//	sauronagent -check-config [-config file]
//	sauronagent -version
//
// With no -config the agent runs on its built-in defaults, which is how the
// shipped unit starts it. The flag set is deliberately this small. Everything
// that changes what the agent collects, keeps or sends lives in the defaults or
// in the one configuration file, where it is reviewable, version controlled and
// exactly what -check-config validated. A fleet whose agents are each tuned by
// a different ExecStart= line is a fleet whose audit coverage nobody can state.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"syscall"

	"github.com/define42/SauronAgent/internal/agent"
	"github.com/define42/SauronAgent/internal/config"
	"github.com/define42/SauronAgent/internal/identity"
	"github.com/define42/SauronAgent/internal/logging"
	"github.com/define42/SauronAgent/internal/metrics"
)

// progName prefixes everything written to the terminal. The journal already
// tags the unit, but an operator running the binary by hand needs to know
// which of the two programs is complaining.
const progName = "sauronagent"

// Exit statuses.
//
// The shipped unit is Restart=always with the start rate limit disabled, so a
// non-zero status here means "restart me and keep saying so in the journal"
// rather than "give up". That is the right trade for an agent: a guest that
// has stopped being audited must stay noisy.
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
	// An argument the agent does not understand is not ignored. It is far more
	// likely to be a mistyped flag that was meant to change what is collected
	// than something the operator wanted dropped.
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

	// A configuration the agent did not understand is worse than no agent: it
	// looks like collection while some setting the operator wrote is not in
	// force. The loader rejects unknown keys and invalid values, and both are
	// fatal here.
	cfg, err := config.LoadAgent(*configPath)
	if err != nil {
		fmt.Fprintf(stderr, "%s: %v\n", progName, err)
		return exitFailure
	}

	if *checkConfig {
		fmt.Fprintf(stdout, "%s: %s is valid\n", progName, configDescription(*configPath))
		writeSummary(stdout, cfg)
		return exitOK
	}

	logger, closer, err := logging.New(cfg.Logging)
	if err != nil {
		fmt.Fprintf(stderr, "%s: %v\n", progName, err)
		return exitFailure
	}
	if closer != nil {
		defer func() { _ = closer.Close() }()
	}

	id := identity.Gather()
	counters := &metrics.Agent{}

	// Logged before anything is opened, so that a guest whose agent fails to
	// start still says in the journal which guest it is and where it was
	// trying to send.
	logStartup(logger, *configPath, cfg, id)

	// New opens the netlink socket and the spool, so a missing CAP_AUDIT_READ
	// or an unwritable state directory fails here, while an operator is
	// watching, rather than becoming an agent that never delivers an event.
	a, err := agent.New(agent.Options{
		Config:   cfg,
		Identity: id,
		Metrics:  counters,
		Logger:   logger,
	})
	if err != nil {
		logger.Error("agent failed to start", "error", err)
		fmt.Fprintf(stderr, "%s: %v\n", progName, err)
		if hint := startupHint(cfg, err); hint != "" {
			fmt.Fprintf(stderr, "%s: %s\n", progName, hint)
			logger.Error("startup hint", "hint", hint)
		}
		return exitFailure
	}
	defer func() { _ = a.Close() }()

	ctx, stop := installSignalHandler(ctx, stderr)
	defer stop()

	runErr := a.Run(ctx)

	// Close here rather than only in the deferred call, so that the spool's
	// final sync is done before anything reports the agent as stopped. What is
	// in the spool at this point is precisely the evidence a restart has to
	// deliver.
	closeErr := a.Close()

	snap := counters.Snapshot()
	if err := errors.Join(runErr, closeErr); err != nil {
		logger.Error("sauronagent stopped with an error",
			"error", err,
			"events_created", snap.EventsCreated,
			"events_acknowledged", snap.EventsAcknowledged,
			"events_dropped", snap.EventsDropped)
		fmt.Fprintf(stderr, "%s: %v\n", progName, err)
		if hint := startupHint(cfg, err); hint != "" {
			fmt.Fprintf(stderr, "%s: %s\n", progName, hint)
		}
		return exitFailure
	}
	if snap.EventsDropped > 0 {
		// Each drop was already reported to the host as a sauron.* event, but
		// the last line in this guest's journal must not read like a run in
		// which nothing was lost.
		logger.Warn("evidence was lost during this run; the host was told which sequences",
			"events_dropped", snap.EventsDropped,
			"kernel_records_lost", snap.KernelRecordsLost,
			"parse_errors", snap.ParseErrors)
	}
	logger.Info("sauronagent stopped",
		"events_created", snap.EventsCreated,
		"events_sent", snap.EventsSent,
		"events_acknowledged", snap.EventsAcknowledged,
		"events_dropped", snap.EventsDropped,
		"spool_events", snap.SpoolEvents)
	return exitOK
}

// usage prints the command line. It says that the shipped unit passes no
// -config, because an operator looking for the file it reads needs to know
// there is none until they add one.
func usage(w io.Writer, flags *flag.FlagSet) {
	fmt.Fprintf(w, "usage: %s [-config file] [-check-config] [-version]\n", progName)
	fmt.Fprintf(w, "\nSauronAgent forwards the guest's Linux audit stream to the hypervisor's\n")
	fmt.Fprintf(w, "collector over AF_VSOCK. The shipped systemd unit runs it without -config,\n")
	fmt.Fprintf(w, "on the built-in defaults.\n\n")
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

// writeSummary prints the settings that decide what is collected, where it
// goes and what survives a failure. It is what -check-config reports on top of
// "valid": a file that parses can still say something the operator did not
// mean, and these are the values worth reading back.
func writeSummary(w io.Writer, cfg config.Agent) {
	fmt.Fprintf(w, "  collector:  %s\n", targetDescription(cfg))
	fmt.Fprintf(w, "  audit:      enabled=%t preserve_raw=%t correlation_timeout=%s manage_rules=%t\n",
		cfg.Audit.Enabled, cfg.Audit.PreserveRaw, cfg.Audit.CorrelationTimeout, cfg.Audit.ManageRules)
	if len(cfg.Audit.ExcludeTypes) > 0 {
		fmt.Fprintf(w, "  excluded:   %s (never reaches the host)\n", strings.Join(cfg.Audit.ExcludeTypes, ", "))
	}
	fmt.Fprintf(w, "  queue:      %d events\n", cfg.Queue.Capacity)
	fmt.Fprintf(w, "  spool:      %s\n", spoolDescription(cfg))
	fmt.Fprintf(w, "  logging:    level=%s format=%s output=%s\n",
		cfg.Logging.Level, cfg.Logging.Format, cfg.Logging.Output)
}

// targetDescription renders the collector the agent will dial.
func targetDescription(cfg config.Agent) string {
	if cfg.Transport.Kind == config.TransportTCP {
		return "tcp " + cfg.Transport.TCPAddress + " (development transport)"
	}
	return fmt.Sprintf("vsock cid %d port %d", cfg.VSOCK.CID, cfg.VSOCK.Port)
}

// spoolDescription renders the spool, or says plainly what running without one
// costs: with no spool, a host outage is bounded by queue.capacity and
// everything past it is destroyed.
func spoolDescription(cfg config.Agent) string {
	if !cfg.Spool.Enabled {
		return "disabled -- a host outage longer than the queue destroys events"
	}
	return fmt.Sprintf("%s (max %s, segments %s, sync_on_write=%t)",
		cfg.Spool.Path, cfg.Spool.MaxSize, cfg.Spool.SegmentSize, cfg.Spool.SyncOnWrite)
}

// logStartup records the guest's identity and a summary of the configuration,
// including where that configuration came from.
//
// The identity is what ties a journal to a VM, and the boot id is what scopes
// the sequence numbers the collector deduplicates on, so both belong in the
// first line of every run. It is a summary and not a dump: -check-config
// prints the configuration, and an agent that logs all of it at info level
// only teaches operators to skim.
func logStartup(log *slog.Logger, configPath string, cfg config.Agent, id identity.Identity) {
	attrs := []any{
		"version", id.Version,
		"hostname", id.Hostname,
		"boot_id", id.BootID,
		"machine_id", id.MachineID,
		"kernel", id.Kernel,
		"config", configDescription(configPath),
		"transport", string(cfg.Transport.Kind),
	}
	if cfg.Transport.Kind == config.TransportTCP {
		attrs = append(attrs, "target", cfg.Transport.TCPAddress)
	} else {
		attrs = append(attrs, "target_cid", cfg.VSOCK.CID, "target_port", cfg.VSOCK.Port)
	}
	attrs = append(attrs,
		"audit_enabled", cfg.Audit.Enabled,
		"audit_manage_rules", cfg.Audit.ManageRules,
		"preserve_raw", cfg.Audit.PreserveRaw,
		"queue_capacity", cfg.Queue.Capacity,
		"spool", spoolDescription(cfg))
	log.Info("sauronagent starting", attrs...)
}

// startupHint turns the two startup failures an operator actually meets into
// an instruction instead of an errno.
//
// The netlink one is by far the most common: a unit without the ambient
// capability starts, is refused the socket and looks like a broken agent
// rather than a missing grant. The audit package already names the capability
// in its EPERM message, and that is what this keys on, so that an unwritable
// spool directory -- also a permission error -- is not answered with advice
// about a capability that has nothing to do with it.
func startupHint(cfg config.Agent, err error) string {
	if !errors.Is(err, fs.ErrPermission) {
		return ""
	}
	if strings.Contains(err.Error(), "CAP_AUDIT_CONTROL") {
		return "kernel audit rule setup needs CAP_AUDIT_CONTROL. The shipped sauronagent.service " +
			"grants CAP_AUDIT_READ and CAP_AUDIT_CONTROL through AmbientCapabilities and " +
			"CapabilityBoundingSet. For externally managed audit policy, set audit.manage_rules: false"
	}
	if strings.Contains(err.Error(), "CAP_AUDIT_READ") {
		return "the kernel refused the audit socket. Grant CAP_AUDIT_READ: the shipped unit " +
			"/usr/lib/systemd/system/sauronagent.service (packaging/systemd/sauronagent.service in " +
			"the source tree) includes it in both AmbientCapabilities and " +
			"CapabilityBoundingSet, and both are needed, because an ambient " +
			"capability outside the bounding set grants nothing. Do not add PrivateUsers=: inside a " +
			"user namespace CAP_AUDIT_READ does not cover the initial namespace the kernel checks, " +
			"and the agent would start and receive nothing. Running the binary by hand needs root, " +
			"or setcap cap_audit_read,cap_audit_control+ep on it for the default managed policy"
	}
	if cfg.Spool.Enabled {
		return fmt.Sprintf("a path the agent needs was refused. The spool is %s: the shipped unit "+
			"makes it writable with StateDirectory=sauronagent under ProtectSystem=strict, and the "+
			"directory must be owned by the user in User= (systemd-tmpfiles --create creates it as "+
			"sauronagent:sauronagent, mode 0700)", cfg.Spool.Path)
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
// cancels the root context, which stops collection, drains the queue into the
// spool, delivers what it can and ends the session with a SHUTDOWN frame so
// the collector can tell a maintenance window from a VM that went quiet. A
// second signal ends the process there and then.
//
// The second stage exists because an orderly flush can only be as fast as the
// host allows. An operator who has decided not to wait must not have to reach
// for SIGKILL: everything still unacknowledged is already in the spool and
// goes out after the restart, so exiting here costs nothing but the tail of
// this session.
//
// Both notices go to stderr rather than through the logger. logging.output may
// be a file on the filesystem that is wedged, and the operator who pressed
// Ctrl-C is watching a terminal.
func watchSignals(done <-chan struct{}, sigs <-chan os.Signal, cancel context.CancelFunc, stderr io.Writer, exit func(int)) {
	select {
	case <-done:
		return
	case s := <-sigs:
		fmt.Fprintf(stderr, "%s: signal %q received; shutting down (signal again to exit immediately)\n", progName, s.String())
		cancel()
	}

	select {
	case <-done:
		return
	case s := <-sigs:
		fmt.Fprintf(stderr, "%s: signal %q received again; exiting now, undelivered events stay in the spool\n", progName, s.String())
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
