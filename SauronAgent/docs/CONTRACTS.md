# Internal API contracts

This reference summarizes selected package interfaces and the rules their
callers rely on. The source and its Go doc comments are authoritative; these
internal APIs are not a separately versioned public compatibility promise.

SauronAgent shares the root Go module. Paths below are relative to the
`SauronAgent/` directory, and imports start with
`github.com/define42/devbox-gateway/SauronAgent`. Code outside this subtree
embeds the collector through `collector`; it cannot import the subtree's
`internal` packages directly.

From the repository root, inspect the current declarations with:

```sh
go doc ./SauronAgent/collector
go doc ./SauronAgent/internal/agent.Options
go doc ./SauronAgent/internal/host.Options
```

Foundation types:

- `internal/audit/records.go`      — `RecordType`, `RawMessage`, `Record`, `RecordTypeName`
- `internal/audit/records_gen.go`  — generated record type constants
- `internal/audit/group.go`        — `Group`
- `internal/event/event.go`        — `Event`, `SchemaVersion`, `Int`, `AUIDUnset`, `Clone`, `SetField`
- `internal/event/categories.go`   — normalized category constants
- `internal/protocol/frame.go`     — `Magic`, `Version`, `HeaderSize`, `Header`, `Frame`, `MessageType`, `Flags`, `MarshalHeader`, `UnmarshalHeader`, errors
- `internal/protocol/message.go`   — `Hello`, `Ready`, `EventMessage`, `Ack`, `Ping`, `Pong`, `ErrorMessage`, `Shutdown`
- `internal/config/*`              — compiled-in `Agent`, YAML-loaded `Host`, and their sections
- `internal/output/sink.go`        — `Sink`, `Envelope`, `Source`, `Reported`
- `internal/transport/transport.go`— `Dialer`, `Listener`
- `internal/metrics/metrics.go`    — `Agent`, `Host` counters
- `internal/identity/identity.go`  — `Identity`, `Gather`
- `internal/logging/logging.go`    — `New`, `Discard`

## internal/audit

```go
// Parsing
func ParseRecord(msg RawMessage) (*Record, error)
func ParseLine(line string) (*Record, error)   // accepts "type=NAME msg=audit(...): ..."

// Netlink receiver
type NetlinkConn struct{ /* unexported */ }
func Dial(receiveBuffer int) (*NetlinkConn, error)
func (c *NetlinkConn) Receive() ([]RawMessage, error)
func (c *NetlinkConn) Close() error
func (c *NetlinkConn) SetReceiveDeadline(t time.Time) error

// Startup policy: enable auditing and idempotently ensure the managed
// syscall groups and discovered configuration/persistence/SSH path rules.
// Requires CAP_AUDIT_CONTROL and path traversal access; the shipped service
// uses CAP_DAC_READ_SEARCH. Does not register the audit daemon PID.
func EnsureManagedRules(ctx context.Context) error

// Same policy, with path-discovery diagnostics sent to the supplied logger.
func EnsureManagedRulesWithLogger(ctx context.Context, logger *slog.Logger) error

// Compatibility name; ensures the complete managed baseline.
func EnsureExecutionRules(ctx context.Context) error

// Listener: netlink receiver + parser, emitting parsed records on a channel.
type ListenerOptions struct {
    ReceiveBuffer int
    ExcludeTypes  []RecordType
    Metrics       *metrics.Agent
    Logger        *slog.Logger
    OnParseError  func(raw RawMessage, err error)
    OnKernelLoss  func(lost uint64)
}
type Listener struct{ /* unexported */ }
func NewListener(opts ListenerOptions) (*Listener, error)
func (l *Listener) Run(ctx context.Context, out chan<- *Record) error
func (l *Listener) Close() error

// Correlation
type CorrelatorOptions struct {
    Timeout          time.Duration
    MaxPendingEvents int
    Metrics          *metrics.Agent
    Logger           *slog.Logger
    Now              func() time.Time   // nil means time.Now
}
type Correlator struct{ /* unexported */ }
func NewCorrelator(opts CorrelatorOptions) *Correlator
func (c *Correlator) Run(ctx context.Context, in <-chan *Record, out chan<- *Group) error
// Add/Expire exist for tests that drive the correlator without goroutines.
func (c *Correlator) Add(r *Record) []*Group
func (c *Correlator) Expire(now time.Time) []*Group
func (c *Correlator) Flush() []*Group
```

## internal/event (normalization)

```go
type NormalizeOptions struct {
    PreserveRaw bool
    BootID      string
}
func Normalize(g *audit.Group, opts NormalizeOptions) *Event

// Internal agent events. Sequence is assigned on submission, before the queue.
func NewInternal(typ, severity string, fields map[string]any) *Event
func NewQueueOverflow(dropped uint64, firstMissing, lastMissing uint64) *Event
func NewParseFailure(raw string, reason string) *Event
func NewSpoolFull(dropped uint64, firstMissing, lastMissing uint64) *Event
func NewTransportDisconnected(reason string, attempt int) *Event
func NewTransportConnected(peer string, attempt int) *Event
func NewKernelRecordsLost(lost uint64) *Event
```

## internal/protocol (codec)

```go
type Encoder struct{ /* unexported */ }
func NewEncoder(w io.Writer, maxPayload uint32) *Encoder
func (e *Encoder) WriteFrame(t MessageType, seq uint64, payload []byte) error
func (e *Encoder) WriteMessage(t MessageType, seq uint64, v any) error

type Decoder struct{ /* unexported */ }
func NewDecoder(r io.Reader, maxPayload uint32) *Decoder
func (d *Decoder) ReadFrame() (*Frame, error)   // Frame and Payload valid until next call
func (d *Decoder) ReadFrameInto(f *Frame) error

func DecodePayload(f *Frame, v any) error

// Conn couples an encoder and decoder to one net.Conn, with deadlines.
type Conn struct{ /* unexported */ }
func NewConn(c net.Conn, maxPayload uint32) *Conn
func (c *Conn) Send(t MessageType, seq uint64, v any, timeout time.Duration) error
func (c *Conn) Receive(timeout time.Duration) (*Frame, error)
func (c *Conn) NetConn() net.Conn
func (c *Conn) Close() error
```

## internal/transport

```go
func NewVSOCKDialer(cid, port uint32) Dialer
func NewTCPDialer(address string) Dialer
func ListenVSOCK(cid, port uint32) (Listener, error)
func ListenTCP(address string) (Listener, error)
func PeerCID(conn net.Conn) (uint32, bool)

type BackoffOptions struct {
    Initial    time.Duration
    Max        time.Duration
    Multiplier float64
    Jitter     float64
    Rand       func() float64   // nil means a package-internal source
}
type Backoff struct{ /* unexported */ }
func NewBackoff(opts BackoffOptions) *Backoff
func (b *Backoff) Next() time.Duration
func (b *Backoff) Reset()
func (b *Backoff) Attempts() int
// Wait sleeps for the next backoff interval or until ctx is done.
func (b *Backoff) Wait(ctx context.Context) error
```

## internal/queue

```go
type Options struct {
    Capacity int
    Metrics  *metrics.Agent
}
type Queue struct{ /* unexported */ }
func New(opts Options) *Queue
// Put never blocks. When the queue is full it drops the oldest event and
// records the loss so that an overflow event can be generated; it returns
// the number of events dropped by this call.
func (q *Queue) Put(e *event.Event) (dropped int)
func (q *Queue) Get(ctx context.Context) (*event.Event, error)
func (q *Queue) TryGet() (*event.Event, bool)
func (q *Queue) Len() int
func (q *Queue) Cap() int
// DrainOverflow returns and clears the accumulated overflow accounting.
func (q *Queue) DrainOverflow() (dropped uint64, firstMissing, lastMissing uint64, ok bool)
func (q *Queue) Close()
```

## internal/spool

```go
type Options struct {
    Dir          string
    MaxSize      int64
    SegmentSize  int64
    SyncOnWrite  bool
    SyncInterval time.Duration
    Metrics      *metrics.Agent
    Logger       *slog.Logger
}
type Spool struct{ /* unexported */ }
func Open(opts Options) (*Spool, error)

// Append records an event with a sequence; durability follows the sync policy.
func (s *Spool) Append(e *event.Event) error
// Next returns up to max unacknowledged events in sequence order.
func (s *Spool) Next(max int) ([]*event.Event, error)
// NextAfter advances a sender cursor without acknowledging retained events.
func (s *Spool) NextAfter(through uint64, max int) ([]*event.Event, error)
// Ack discards every event up to and including seq.
func (s *Spool) Ack(seq uint64) error
// LastSequence is the highest sequence ever appended, surviving restart.
func (s *Spool) LastSequence() uint64
// FirstUnacked is the lowest sequence still held.
func (s *Spool) FirstUnacked() uint64
func (s *Spool) PendingCount() int
func (s *Spool) Bytes() int64
// DrainDropped reports size-limit loss and detected spool corruption.
func (s *Spool) DrainDropped() (dropped uint64, firstMissing, lastMissing uint64, ok bool)
func (s *Spool) Sync() error
func (s *Spool) Close() error
```

## internal/output

```go
func NewStdout(cfg config.StdoutOutput) (Sink, error)
func NewFile(cfg config.FileOutput) (Sink, error)
func NewSyslog(cfg config.SyslogOutput) (Sink, error)
// Multi fans an envelope out to every sink. A write is successful only when
// every sink accepted it, because the collector acknowledges to the guest on
// the strength of that result.
func NewMulti(sinks ...Sink) Sink
func Build(cfg config.OutputSection) (Sink, error)
```

## internal/agent (guest pipeline)

```go
type Options struct {
    Config   config.Agent
    Identity identity.Identity
    Metrics  *metrics.Agent
    Logger   *slog.Logger
    // Dialer overrides transport construction in tests.
    Dialer transport.Dialer
    // An injected Source skips kernel setup unless ConfigureRules is supplied.
    Source func(ctx context.Context, out chan<- *audit.Record) error
    ConfigureRules func(context.Context) error
}
type Agent struct{ /* unexported */ }
func New(opts Options) (*Agent, error)
func (a *Agent) Run(ctx context.Context) error
func (a *Agent) Close() error
```

The pipeline stages and the order in which a sequence number is assigned:

```text
netlink reader -> correlator -> normalizer -> assign sequence -> queue -> spool -> sender
```

Sequence numbers are assigned immediately after normalization and before the queue, so that
queue and spool overflow accounting can name exactly which sequences were lost. Sequence is
recovered from the spool's LastSequence across agent restarts and, when the
spool persists, across guest reboots. Events retain their original boot ID.
The collector's deduplication key uses the session's HELLO boot ID.

## internal/host (host collector)

```go
type Options struct {
    Config  config.Host
    Sink    output.Sink
    Metrics *metrics.Host
    Logger  *slog.Logger
    // Listener overrides transport construction in tests.
    Listener transport.Listener
    // OnInternalEvent receives host-generated events such as stream loss.
    OnInternalEvent func(*output.Envelope)
    // Resolve checks live hypervisor state once per VSOCK connection, before
    // the static VM map. Resolved VMs do not join the expected-stream monitor.
    Resolve func(cid uint32) (config.VMMapping, bool)
}
type Server struct{ /* unexported */ }
func New(opts Options) (*Server, error)
func (s *Server) Run(ctx context.Context) error
func (s *Server) Close() error
```

## Output acceptance and replay

The collector acknowledges only after the selected sink accepts an event or
its gap report. A successful `Write` controls acknowledgement; the server does
not call `Flush` before each ACK. Sink implementations must make accepted
writes durable themselves if that is the required delivery contract.

`collector.NewFileSink` uses rotation and buffered kernel writes, with syncing
on `Flush` and `Close`. Collector deduplication state is in memory, so
consumers must tolerate duplicates after restarts or state eviction. See the
[protocol reference](protocol.md#44-ack) for cumulative acknowledgement and
gap handling.
