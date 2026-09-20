package gateway

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mdlayher/vsock"

	"github.com/define42/devbox-gateway/internal/config"
	"github.com/define42/devbox-gateway/internal/splunkhec"
)

func TestSauronOptionsMapsSettings(t *testing.T) {
	// Leftover deployment variables must neither disable collection nor
	// redirect the listener away from the agent's compiled-in port.
	t.Setenv("SAURON_ENABLE", "false")
	t.Setenv("SAURON_VSOCK_PORT", "9100")
	t.Setenv(config.SAURON_EVENT_LOG_FILE, "/srv/sauron/events.jsonl")
	t.Setenv(config.SAURON_SPLUNK_HEC_ENDPOINT, "https://splunk.example.test:8088")
	t.Setenv(config.SAURON_SPLUNK_HEC_TOKEN, "sauron-token")
	t.Setenv(config.SAURON_SPLUNK_HEC_INDEX, "sauron")
	t.Setenv(config.SAURON_SPLUNK_HEC_SKIP_TLS_VERIFY, "true")
	t.Setenv(config.SAURON_SPOOL_DIR, "/srv/sauron/spool")
	t.Setenv(config.SAURON_SPOOL_MAX_MIB, "2048")

	got := sauronOptions(config.NewSettings(false))
	if got.Port != 9000 || got.EventLogFile != "/srv/sauron/events.jsonl" {
		t.Errorf("sauronOptions() port %d, event log %q; want 9000 and /srv/sauron/events.jsonl", got.Port, got.EventLogFile)
	}
	wantHEC := splunkhec.Config{
		Endpoint:           "https://splunk.example.test:8088",
		Token:              "sauron-token",
		Index:              "sauron",
		InsecureSkipVerify: true,
	}
	if got.HEC != wantHEC {
		t.Errorf("sauronOptions().HEC = %+v, want %+v", got.HEC, wantHEC)
	}
	if got.SpoolDir != "/srv/sauron/spool" || got.SpoolMaxBytes != 2048<<20 {
		t.Errorf("sauronOptions() spool %q, %d bytes; want /srv/sauron/spool and 2 GiB", got.SpoolDir, got.SpoolMaxBytes)
	}
	if got.Resolve == nil {
		t.Error("sauronOptions().Resolve is nil; guests would never be attributed to their VMs")
	}
}

func TestStartSauronCollectorIsMandatory(t *testing.T) {
	for _, tc := range []struct{ name, legacyEnabled string }{
		{name: "default"},
		{name: "legacy disabled", legacyEnabled: "false"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("SAURON_ENABLE", tc.legacyEnabled)
			// A directory cannot be opened as the event file. Reaching this
			// failure proves setup is attempted without needing AF_VSOCK.
			t.Setenv(config.SAURON_EVENT_LOG_FILE, t.TempDir())
			collector, err := startSauronCollector(config.NewSettings(false))
			if collector != nil {
				_ = collector.Close()
				t.Fatal("collector started with an unusable output")
			}
			if err == nil || !strings.Contains(err.Error(), "start sauron collector: open sauron event log") {
				t.Fatalf("collector startup error = %v, want the mandatory output failure", err)
			}
		})
	}
}

func TestMcovBootGatewayRequiresSauronOutput(t *testing.T) {
	t.Setenv(config.ConfigFileEnv, filepath.Join(t.TempDir(), "missing.conf"))
	t.Setenv("SAURON_ENABLE", "false")
	t.Setenv(config.SAURON_EVENT_LOG_FILE, "")
	t.Setenv(config.SAURON_SPLUNK_HEC_ENDPOINT, "")
	t.Setenv(config.SAURON_SPLUNK_HEC_TOKEN, "")
	t.Setenv(config.SAURON_SPLUNK_HEC_INDEX, "")

	_, err := bootGateway()
	if err == nil || !strings.Contains(err.Error(), config.SAURON_EVENT_LOG_FILE) {
		t.Fatalf("expected a mandatory collector output validation error, got %v", err)
	}
}

// TestMcovBootGatewayForwardsSauronEventsToSplunkHEC boots the gateway with the
// mandatory SauronAgent collector and plays a guest over AF_VSOCK loopback. The
// loopback CID (1) belongs to no libvirt domain, so the live libvirt resolver
// records the guest as unknown -- which also proves it is consulted.
func TestMcovBootGatewayForwardsSauronEventsToSplunkHEC(t *testing.T) {
	requireSauronVSock(t)
	mcovBootEnv(t)
	collector := newMcovHECCollector(t)
	eventLog := filepath.Join(t.TempDir(), "sauron.jsonl")
	t.Setenv(config.SAURON_EVENT_LOG_FILE, eventLog)
	t.Setenv(config.SAURON_SPLUNK_HEC_ENDPOINT, collector.server.URL)
	t.Setenv(config.SAURON_SPLUNK_HEC_TOKEN, "mcov-sauron-token")
	t.Setenv(config.SAURON_SPLUNK_HEC_INDEX, "mcov_sauron")
	t.Setenv(config.SAURON_SPLUNK_HEC_SKIP_TLS_VERIFY, "true")

	gateway, err := bootGateway()
	if err != nil {
		t.Fatalf("bootGateway: %v", err)
	}
	defer func() { _ = gateway.Close() }()
	if gateway.sauron == nil {
		t.Fatal("gateway booted without its mandatory collector")
	}

	conn, err := vsock.Dial(1, config.SauronVSockPort, nil)
	if err != nil {
		t.Fatalf("dial the collector over vsock loopback: %v", err)
	}
	defer func() { _ = conn.Close() }()
	if acked := sauronPlayGuest(t, conn); acked != 1 {
		t.Fatalf("collector acknowledged through %d, want 1", acked)
	}
	// Delivery from the spool is asynchronous.
	bodies, auths := waitForHECBody(t, collector, `"sourcetype":"devbox-gateway:sauron"`)
	if err := gateway.Close(); err != nil {
		t.Fatalf("close gateway runtime: %v", err)
	}

	for _, want := range []string{`"host":"unknown-cid-1"`, `"index":"mcov_sauron"`, `"sourcetype":"devbox-gateway:sauron"`, `"command":"id"`} {
		if !strings.Contains(bodies, want) {
			t.Errorf("collector bodies missing %s: %s", want, bodies)
		}
	}
	for _, auth := range auths {
		if auth != "Splunk mcov-sauron-token" {
			t.Errorf("Authorization = %q, want the SauronAgent HEC token", auth)
		}
	}
	if strings.Contains(bodies, `"sourcetype":"devbox-gateway:audit"`) {
		t.Error("audit events reached the SauronAgent HEC; the two streams must stay separate")
	}
}

// waitForHECBody waits until a request body the fake collector received
// contains want.
func waitForHECBody(t *testing.T, collector *mcovHECCollector, want string) (string, []string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		bodies, auths := collector.snapshot()
		if strings.Contains(bodies, want) {
			return bodies, auths
		}
		if time.Now().After(deadline) {
			t.Fatalf("collector never received %s; bodies: %s", want, bodies)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// requireSauronVSock checks the fixed production port before a live boot test.
// No collector-disable or port override is introduced for test environments.
func requireSauronVSock(t *testing.T) {
	t.Helper()
	listener, err := vsock.ListenContextID(0xFFFFFFFF, config.SauronVSockPort, nil)
	if err != nil {
		t.Skipf("AF_VSOCK port 9000 is unavailable for a live gateway boot: %v", err)
	}
	probe, err := vsock.Dial(1, config.SauronVSockPort, nil)
	if err != nil {
		_ = listener.Close()
		t.Skipf("no AF_VSOCK loopback transport on this host: %v", err)
	}
	_ = probe.Close()
	_ = listener.Close()
}

// sauronGuest speaks the guest side of the SAUR wire protocol (SauronAgent
// docs/protocol.md), written out by hand.
type sauronGuest struct {
	t    *testing.T
	conn net.Conn
}

func (g sauronGuest) send(messageType byte, sequence uint64, payload any) {
	g.t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		g.t.Fatalf("encode payload: %v", err)
	}
	frame := make([]byte, 20, 20+len(body))
	copy(frame, "SAUR")
	frame[4], frame[5] = 1, messageType
	binary.BigEndian.PutUint64(frame[8:16], sequence)
	binary.BigEndian.PutUint32(frame[16:20], uint32(len(body)))
	if _, err := g.conn.Write(append(frame, body...)); err != nil {
		g.t.Fatalf("send frame type %d: %v", messageType, err)
	}
}

func (g sauronGuest) receive() (byte, []byte, error) {
	header := make([]byte, 20)
	if _, err := io.ReadFull(g.conn, header); err != nil {
		return 0, nil, err
	}
	if !bytes.Equal(header[:4], []byte("SAUR")) {
		g.t.Fatalf("collector sent a malformed header %x", header)
	}
	payload := make([]byte, binary.BigEndian.Uint32(header[16:20]))
	_, err := io.ReadFull(g.conn, payload)
	return header[5], payload, err
}

// sauronPlayGuest runs one session -- HELLO, one EVENT, SHUTDOWN -- and returns
// the highest sequence acknowledged before the collector closed it.
func sauronPlayGuest(t *testing.T, conn net.Conn) uint64 {
	t.Helper()
	guest := sauronGuest{t: t, conn: conn}
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))

	guest.send(1, 0, map[string]any{"protocol_version": 1, "agent_version": "test", "boot_id": "boot-1"})
	if messageType, payload, err := guest.receive(); err != nil || messageType != 2 {
		t.Fatalf("after HELLO got type %d %s, %v; want READY", messageType, payload, err)
	}
	guest.send(3, 1, map[string]any{"event": map[string]any{
		"version": 1, "sequence": 1, "timestamp": time.Now().UTC().Format(time.RFC3339Nano),
		"type": "process.exec", "boot_id": "boot-1", "command": "id",
	}})
	guest.send(8, 0, map[string]any{"reason": "test"})

	var acked uint64
	for {
		messageType, payload, err := guest.receive()
		if err != nil {
			return acked
		}
		if messageType != 4 {
			continue
		}
		var ack struct {
			Sequence uint64 `json:"sequence"`
		}
		if err := json.Unmarshal(payload, &ack); err != nil {
			t.Fatalf("decode ACK %s: %v", payload, err)
		}
		acked = max(acked, ack.Sequence)
	}
}
