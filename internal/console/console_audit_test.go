package console

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/define42/devbox-gateway/internal/audit"
	"github.com/define42/devbox-gateway/internal/identity"
	"github.com/define42/devbox-gateway/internal/session"
)

type synchronizedAuditBuffer struct {
	mu     sync.Mutex
	buffer bytes.Buffer
}

func (b *synchronizedAuditBuffer) Write(payload []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffer.Write(payload)
}

func (b *synchronizedAuditBuffer) snapshot() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	return bytes.Clone(b.buffer.Bytes())
}

func captureConsoleAuditRecords(t *testing.T) *synchronizedAuditBuffer {
	t.Helper()

	var output synchronizedAuditBuffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&output, nil)))
	t.Cleanup(func() {
		slog.SetDefault(previous)
	})
	return &output
}

func awaitConsoleAuditRecords(t *testing.T, output *synchronizedAuditBuffer, want int) []map[string]any {
	t.Helper()

	deadline := time.Now().Add(websocketTestTimeout)
	for {
		records := consoleAuditRecords(t, output)
		if len(records) >= want {
			return records
		}
		if time.Now().After(deadline) {
			t.Fatalf("got %d console audit records, want at least %d: %#v", len(records), want, records)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func consoleAuditRecords(t *testing.T, output *synchronizedAuditBuffer) []map[string]any {
	t.Helper()

	var records []map[string]any
	decoder := json.NewDecoder(bytes.NewReader(output.snapshot()))
	for {
		var record map[string]any
		err := decoder.Decode(&record)
		if err == io.EOF {
			return records
		}
		if err != nil {
			t.Fatalf("decode console audit record: %v", err)
		}
		if record["msg"] == "audit" {
			records = append(records, record)
		}
	}
}

func assertConsoleAuditRecord(
	t *testing.T,
	record map[string]any,
	action string,
	vmName string,
	protocol string,
) {
	t.Helper()

	want := map[string]any{
		"action":        action,
		"user":          "covx-audit-admin",
		"result":        "success",
		"source_ip":     "127.0.0.1",
		"vm":            vmName,
		"protocol":      protocol,
		"administrator": true,
	}
	for key, wantValue := range want {
		if got := record[key]; got != wantValue {
			t.Errorf("console audit attribute %q = %#v, want %#v", key, got, wantValue)
		}
	}
}

type consoleAuditCase struct {
	name     string
	suffix   string
	route    string
	protocol string
	start    func(*covxDomain)
}

func TestConsoleConnectionAuditLifecycle(t *testing.T) {
	tests := []consoleAuditCase{
		{
			name:     "serial",
			suffix:   "audit-serial",
			route:    "/api/dashboard/console/",
			protocol: audit.ProtocolSerial,
			start:    (*covxDomain).startPaused,
		},
		{
			name:     "noVNC",
			suffix:   "audit-vnc",
			route:    "/api/dashboard/vnc/",
			protocol: audit.ProtocolNoVNC,
			start:    (*covxDomain).start,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			testConsoleConnectionAuditLifecycle(t, test)
		})
	}
}

func testConsoleConnectionAuditLifecycle(t *testing.T, test consoleAuditCase) {
	t.Helper()

	const username = "covx-audit-admin"

	dom := covxDefineDomain(t, test.suffix)
	dom.setOwnerMetadata("<owner>" + username + "</owner>")
	test.start(dom)

	manager := session.New()
	server := covxDashboardServer(t, manager)
	cookie := covxSessionCookieForUser(
		t,
		manager,
		&identity.User{Name: username, IsAdmin: true},
		time.Time{},
	)
	output := captureConsoleAuditRecords(t)

	conn := covxDialWebsocket(t, server, test.route+dom.name+"/ws", cookie)
	records := awaitConsoleAuditRecords(t, output, 1)
	if len(records) != 1 {
		t.Fatalf("got %d audit records after connect, want 1: %#v", len(records), records)
	}
	assertConsoleAuditRecord(t, records[0], audit.ActionConnectionConnect, dom.name, test.protocol)
	if _, ok := records[0]["duration_ms"]; ok {
		t.Error("connect audit record unexpectedly includes duration_ms")
	}

	covxRevokeUserConnections(t, manager, username, conn)
	covxAwaitWebsocketClosed(t, conn)
	records = awaitConsoleAuditRecords(t, output, 2)
	if len(records) != 2 {
		t.Fatalf("got %d audit records after disconnect, want 2: %#v", len(records), records)
	}
	assertConsoleAuditRecord(t, records[1], audit.ActionConnectionDisconnect, dom.name, test.protocol)
	if _, ok := records[1]["duration_ms"]; !ok {
		t.Error("disconnect audit record is missing duration_ms")
	}
}
