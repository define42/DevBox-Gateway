# SauronAgent guest events

[SauronAgent](https://github.com/define42/DevBox-Gateway/blob/main/SauronAgent/README.md), running inside the VMs, reads the guest
kernel's audit stream (process executions, logins, privilege changes, audit and
firewall configuration changes, …) and streams it to the hypervisor over
virtio-vsock — no guest networking involved. The gateway always runs
SauronAgent's host collector on fixed AF_VSOCK port 9000 and receives those
events itself. No enable switch or port setting is needed. To also forward
guest events to Splunk HEC, configure:

```ini
SAURON_SPLUNK_HEC_ENDPOINT=https://splunk.example.com:8088
SAURON_SPLUNK_HEC_TOKEN=11111111-2222-3333-4444-555555555555
SAURON_SPLUNK_HEC_INDEX=devbox_sauron
# Independent of SPLUNK_HEC_ACK_ENABLED; requires this token's ACK support.
SAURON_SPLUNK_HEC_ACK_ENABLED=false
```

- Every newly created VM gets a virtio-vsock device, for which libvirt picks a
  CID that is unique among the running domains. Existing VMs without a vsock
  device are not automatically migrated; recreate them or add the device
  through libvirt before collecting their events. SauronAgent must also be
  installed and running inside each guest.
- The gateway listens on AF_VSOCK port 9000 and attributes each
  connection to the running VM libvirt assigned its CID to. The CID is set by the
  hypervisor, so a guest cannot pass its events off as another VM's; what the
  guest says about itself (hostname, machine-id, …) is recorded under
  `source.reported` and never used for attribution.
- Each event is written as a collector envelope: the gateway's receive time
  (`received_at`), the trusted `source` (`vm`, `uuid`, `cid`, `host`, and
  `labels.owner` — the gateway user who owns the VM), and the guest's normalized
  `event` unchanged. The collector's own `sauron.*` events (protocol violations,
  sequence gaps, refused connections, output failures) go to the same stream.
  If CID lookup fails, the collector still records the event with
  `source.known=false` and a synthetic `unknown-cid-N` name; VM UUID and owner
  labels are then unavailable.
  Once fresh expected-VM inventory supplies a complete identity, the next valid
  event or heartbeat on that unresolved connection asks the agent to reconnect.
  The collector resolves the new connection's identity, and the agent replays
  unacknowledged records.
  Existing records keep their original attribution; a fully resolved connection
  keeps its pinned identity even if the CID is later reused.
- Events go to `SAURON_EVENT_LOG_FILE` and, when configured, to Splunk HEC, using
  their own endpoint, token, and index so guest telemetry can land in a different
  index than the gateway audit log. In Splunk they arrive with
  `source=sauronagent`, `sourcetype=devbox-gateway:sauron`, the VM name as
  `host`, and the gateway's receive time as `_time` (a guest controls its own
  clock; its timestamp stays in `event.timestamp`).
- Delivery to Splunk is store and forward. The gateway acknowledges an event to
  its guest — which then deletes its own copy — as soon as the event is written
  and fsynced to the gateway's spool (`SAURON_SPOOL_DIR`) and accepted by any
  other configured sink. This guest acknowledgement still means local
  acceptance when `SAURON_SPLUNK_HEC_ACK_ENABLED=true`; already-spooled records
  remain after VM deletion. A background forwarder delivers the spool to Splunk
  in order, in batches, retrying with
  backoff capped at 30s for however long Splunk is unreachable — days if
  need be — and resumes from its checkpoint after a gateway restart. A long
  outage is reported in the process log every 5 minutes with the spool's size.
  If saving an accepted batch's checkpoint fails, the forwarder retries that
  save before reading or sending more events. Recovery does not require a new
  append, even when the spool is full. A restart before the checkpoint is saved
  can replay the batch.
- The gateway spool is bounded by `SAURON_SPOOL_MAX_MIB` (10 GiB by default).
  When it fills, the gateway preserves pending records and stops acknowledging
  new events. Guests then retain events in their own spools (1 GiB by default).
  A full guest spool evicts its oldest unsent segments and reports the lost
  sequence range, so a sufficiently long outage can lose guest events. Guest
  spool writes also use periodic fsync by default; a power loss can lose recent
  unsynced writes.
- The embedded file sink fsyncs each event and file creation/rotation metadata
  before the guest ACK, including file-only collection. Acknowledged file
  records follow the filesystem's fsync durability guarantees; size-based
  rotation still limits retention. Per-event fsync adds storage latency and
  limits throughput. With HEC enabled, its gateway spool is also fsynced before
  acceptance.
- Retries can produce duplicate deliveries. After a crash or restart, events that were
  delivered just before it can reach Splunk twice. An event Splunk rejects as
  invalid on its own (HEC codes 6, 12, 13, 15, or too large) is dropped with a
  log line, so it cannot block the backlog; every other refusal — an index the
  token may not write to, an unhealthy or unreachable Splunk — keeps the events
  spooled. Redirects and unconfirmed `2xx` replies keep the checkpoint unchanged;
  successful delivery requires HEC JSON with `code: 0` by default. Set
  `SAURON_SPLUNK_HEC_ACK_ENABLED=true` to additionally require an explicit
  `true` ACK for the submitted batch's exact `ackId`, with the token, channel,
  endpoint affinity and five-minute polling limit described in
  [Forwarding to Splunk HEC](audit-logs.md#forwarding-to-splunk-hec). ACK errors
  and unconfirmed ACKs always retain the batch, including malformed ACK
  replies and shutdown; the permanent-event rejection policy only applies to
  the event submission. This switch is independent of `SPLUNK_HEC_ACK_ENABLED`.
  If both streams share an ACK-enabled token, enable both gateway switches;
  use separate tokens to configure different ACK modes.
  Concurrent sessions sharing a peer or trusted VM UUID serialize event
  acceptance through deduplication, output and commit. This prevents simultaneous
  copies on the same event stream from racing each other.
- The gateway refuses to start when the guest-event HEC endpoint lacks a token
  (or a token, index or enabled ACK setting lacks an endpoint), or when neither
  the file nor HEC is configured. It also refuses to start when it cannot open
  the vsock listener: the host needs the `vhost_vsock` kernel module, and must
  not run `sauronhost` on the same port.
  The shipped systemd unit allows the `AF_VSOCK` socket family; in Docker, see
  the seccomp note under [Quick start](../installation/docker-compose.md#quick-start-docker-compose).
- Every 15 seconds the collector refreshes its expected agents from running,
  persistent VMs with gateway ownership metadata. A new VM gets
  `SAURON_AGENT_STARTUP_GRACE` to connect; after first contact,
  `SAURON_AGENT_TIMEOUT` bounds silence. Overdue agents emit
  `sauron.stream.lost` and make `/api/ready` return `503`; matching traffic emits
  `sauron.stream.resumed`. Only the current trusted CID, VM name and UUID can
  refresh that VM's deadline. Stopped or removed VMs leave the expected set on
  the next successful inventory refresh.
- Inventory errors retain the previous expectations and fail readiness. An
  inventory query that does not complete leaves readiness unhealthy once the
  snapshot is older than 45 seconds. Running managed VMs without an assigned
  vsock CID also fail the inventory check. Missing agents and inventory errors
  recover automatically after valid traffic or inventory returns; neither
  condition restarts the gateway. An unexpected collector exit terminates the
  gateway with exit status 1 so its service manager can restart it.
- Stream alerts wait for successful output acceptance and are retried after
  storage recovery. The in-memory alert queue holds at most 4096 entries;
  overflow logs an error and keeps readiness unhealthy until operator recovery
  and restart. Partial acceptance by multiple outputs can produce duplicate
  alerts. See [monitoring and recovery](https://github.com/define42/DevBox-Gateway/blob/main/SauronAgent/docs/deployment.md#6-what-to-monitor).
- Unreported sequence gaps also fail readiness, including while their output
  write is in progress. A separate worker retries pending gap reports every
  second, independently of guest traffic and inventory queries. A gap clears
  when its loss report is accepted or the missing events arrive. Accepted loss
  evidence does not prove those original events were delivered or clear a
  rejected guest record's health tracking. When loss accounting is full, a
  report waits for capacity before another output attempt; other streams can
  continue. Received originals are protected before waiting for output, so a
  concurrent loss report cannot acknowledge an original still awaiting storage.

For example, `index=devbox_sauron sourcetype="devbox-gateway:sauron"
event.type=process.exec source.labels.owner=alice` lists every program alice's
VMs ran.
