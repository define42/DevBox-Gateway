package audit

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestActionAndProtocolConstants(t *testing.T) {
	tests := []struct {
		name string
		got  string
		want string
	}{
		{name: "user login", got: ActionUserLogin, want: "user.login"},
		{name: "user logout", got: ActionUserLogout, want: "user.logout"},
		{name: "vm create", got: ActionVMCreate, want: "vm.create"},
		{name: "vm start", got: ActionVMStart, want: "vm.start"},
		{name: "vm stop", got: ActionVMStop, want: "vm.stop"},
		{name: "vm reboot", got: ActionVMReboot, want: "vm.reboot"},
		{name: "vm remove", got: ActionVMRemove, want: "vm.remove"},
		{name: "connection connect", got: ActionConnectionConnect, want: "connection.connect"},
		{name: "connection disconnect", got: ActionConnectionDisconnect, want: "connection.disconnect"},
		{name: "admin base image upload", got: ActionAdminBaseImageUpload, want: "admin.base_image.upload"},
		{name: "admin base image delete", got: ActionAdminBaseImageDelete, want: "admin.base_image.delete"},
		{name: "noVNC protocol", got: ProtocolNoVNC, want: "novnc"},
		{name: "serial protocol", got: ProtocolSerial, want: "serial"},
		{name: "RDP protocol", got: ProtocolRDP, want: "rdp"},
		{name: "success result", got: ResultSuccess, want: "success"},
		{name: "failure result", got: ResultFailure, want: "failure"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.got != test.want {
				t.Fatalf("constant = %q, want %q", test.got, test.want)
			}
		})
	}
}

func TestLogEmitsCompleteSchema(t *testing.T) {
	record, _ := captureRecord(context.Background(), t, Event{
		Action:        ActionConnectionDisconnect,
		User:          "alice",
		Result:        ResultFailure,
		SourceIP:      "192.0.2.10",
		VM:            "alice.desktop",
		ResourceType:  "base_image",
		Resource:      "ubuntu-24.04",
		Protocol:      ProtocolRDP,
		Operation:     "proxy",
		Administrator: true,
		Duration:      1500 * time.Millisecond,
	})

	want := map[string]any{
		"level":         "INFO",
		"msg":           "audit",
		"action":        ActionConnectionDisconnect,
		"user":          "alice",
		"result":        ResultFailure,
		"source_ip":     "192.0.2.10",
		"vm":            "alice.desktop",
		"resource_type": "base_image",
		"resource":      "ubuntu-24.04",
		"protocol":      ProtocolRDP,
		"operation":     "proxy",
		"administrator": true,
		"duration_ms":   float64(1500),
	}
	for key, wantValue := range want {
		if got := record[key]; got != wantValue {
			t.Errorf("attribute %q = %#v, want %#v", key, got, wantValue)
		}
	}

	if got, wantCount := len(record), len(want)+1; got != wantCount {
		t.Errorf("record has %d fields, want %d: %#v", got, wantCount, record)
	}
	if _, ok := record["time"]; !ok {
		t.Error("record is missing slog time field")
	}
}

func TestLogOmitsEmptyOptionalFields(t *testing.T) {
	record, _ := captureRecord(context.Background(), t, Event{
		Action: ActionUserLogin,
		User:   "bob",
	})

	want := map[string]any{
		"level":  "INFO",
		"msg":    "audit",
		"action": ActionUserLogin,
		"user":   "bob",
		"result": "success",
	}
	for key, wantValue := range want {
		if got := record[key]; got != wantValue {
			t.Errorf("attribute %q = %#v, want %#v", key, got, wantValue)
		}
	}

	if got, wantCount := len(record), len(want)+1; got != wantCount {
		t.Errorf("record has %d fields, want %d: %#v", got, wantCount, record)
	}
}

func TestLogDoesNotReadSensitiveContextValues(t *testing.T) {
	type contextKey string
	const secret = "correct-horse-battery-staple"
	ctx := context.WithValue(context.Background(), contextKey("password"), secret)

	record, raw := captureRecord(ctx, t, Event{
		Action: ActionUserLogout,
		User:   "carol",
	})

	for _, key := range []string{"password", "password_hash", "credential", "token"} {
		if _, ok := record[key]; ok {
			t.Errorf("sensitive attribute %q was emitted", key)
		}
	}
	if strings.Contains(raw, secret) {
		t.Error("sensitive context value was emitted")
	}
}

func TestConfigureJSONFileAppendsOneJSONRecordPerLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private", "audit.jsonl")
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatalf("create test audit directory: %v", err)
	}
	if err := os.WriteFile(path, []byte("{\"existing\":true}\n"), 0o640); err != nil {
		t.Fatalf("seed audit file: %v", err)
	}

	closer, err := ConfigureJSONFile(path)
	if err != nil {
		t.Fatalf("configure audit file: %v", err)
	}
	t.Cleanup(func() {
		if closeErr := closer.Close(); closeErr != nil {
			t.Errorf("close audit file: %v", closeErr)
		}
	})

	const eventCount = 32
	var writers sync.WaitGroup
	writers.Add(eventCount)
	for index := range eventCount {
		go func() {
			defer writers.Done()
			Log(context.Background(), Event{
				Action: ActionUserLogin,
				User:   fmt.Sprintf("user-%d\nwith-newline", index),
			})
		}()
	}
	writers.Wait()
	if err := closer.Close(); err != nil {
		t.Fatalf("close audit file: %v", err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read audit file: %v", err)
	}
	if !bytes.HasSuffix(raw, []byte("\n")) {
		t.Fatal("audit file does not end with a newline")
	}

	scanner := bufio.NewScanner(bytes.NewReader(raw))
	recordCount := 0
	for scanner.Scan() {
		var record map[string]any
		if err := json.Unmarshal(scanner.Bytes(), &record); err != nil {
			t.Fatalf("line %d is not one JSON object: %q: %v", recordCount+1, scanner.Text(), err)
		}
		recordCount++
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan audit file: %v", err)
	}
	if want := eventCount + 1; recordCount != want {
		t.Fatalf("audit file contains %d lines, want %d", recordCount, want)
	}
}

func TestConfigureJSONFilePreservesOperationalLogAndRestoresLogging(t *testing.T) {
	previousLogger := slog.Default()
	previousLogWriter := log.Writer()
	t.Cleanup(func() {
		slog.SetDefault(previousLogger)
		log.SetOutput(previousLogWriter)
	})

	var restoredSlog bytes.Buffer
	slog.SetDefault(slog.New(slog.NewJSONHandler(&restoredSlog, nil)))
	var operationalLog bytes.Buffer
	log.SetOutput(&operationalLog)

	path := filepath.Join(t.TempDir(), "audit", "events.jsonl")
	closer, err := ConfigureJSONFile(path)
	if err != nil {
		t.Fatalf("configure audit file: %v", err)
	}

	log.Print("ordinary service event")
	Log(context.Background(), Event{Action: ActionUserLogout, User: "alice"})
	if err := closer.Close(); err != nil {
		t.Fatalf("close audit file: %v", err)
	}
	if err := closer.Close(); err != nil {
		t.Fatalf("close audit file again: %v", err)
	}
	Log(context.Background(), Event{Action: ActionUserLogout, User: "after-close"})
	log.Print("ordinary event after close")

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read audit file: %v", err)
	}
	if strings.Contains(string(raw), "ordinary service event") {
		t.Error("standard log output was written to the audit file")
	}
	if !strings.Contains(string(raw), `"user":"alice"`) {
		t.Errorf("audit file does not contain configured audit record: %s", raw)
	}
	if strings.Contains(string(raw), "after-close") {
		t.Error("audit record emitted after close was written to the closed audit file")
	}
	if !strings.Contains(operationalLog.String(), "ordinary service event") ||
		!strings.Contains(operationalLog.String(), "ordinary event after close") {
		t.Errorf("standard log destination was not preserved and restored: %q", operationalLog.String())
	}
	if !strings.Contains(restoredSlog.String(), `"user":"after-close"`) {
		t.Errorf("previous slog logger was not restored: %q", restoredSlog.String())
	}

	assertPathMode(t, filepath.Dir(path), 0o750)
	assertPathMode(t, path, 0o640)
}

func TestConfigureJSONFileRejectsEmptyPath(t *testing.T) {
	closer, err := ConfigureJSONFile(" \t ")
	if err == nil {
		if closer != nil {
			_ = closer.Close()
		}
		t.Fatal("ConfigureJSONFile() error = nil, want non-nil")
	}
}

func assertPathMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %q: %v", path, err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Errorf("%q mode = %04o, want %04o", path, got, want)
	}
}

func captureRecord(ctx context.Context, t *testing.T, event Event) (map[string]any, string) {
	t.Helper()

	var output bytes.Buffer
	previous := slog.Default()
	previousLogWriter := log.Writer()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&output, nil)))
	log.SetOutput(previousLogWriter)
	t.Cleanup(func() {
		slog.SetDefault(previous)
		log.SetOutput(previousLogWriter)
	})

	Log(ctx, event)
	raw := output.String()
	var record map[string]any
	if err := json.Unmarshal(output.Bytes(), &record); err != nil {
		t.Fatalf("decode audit record %q: %v", raw, err)
	}
	return record, raw
}
