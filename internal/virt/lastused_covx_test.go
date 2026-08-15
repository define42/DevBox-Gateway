package virt

import (
	"strings"
	"testing"
	"time"
)

func TestViocovMarkVMLastUsed(t *testing.T) {
	if err := MarkVMLastUsed("   "); err == nil {
		t.Fatal("expected blank VM name to be rejected")
	}

	missingName := viocovUniqueName("lastused-missing")
	if err := MarkVMLastUsed(missingName); err == nil || !strings.Contains(err.Error(), "lookup domain") {
		t.Fatalf("expected missing domain lookup error, got %v", err)
	}

	conn := newTestLibvirtConn(t)
	name := viocovUniqueName("lastused")
	dom := viocovDefineDomain(t, conn, name, "")

	const oldTimestamp = "2000-01-02T03:04:05Z"
	if err := setDomainLastUsedMetadata(dom, oldTimestamp); err != nil {
		t.Fatalf("set initial last-used metadata: %v", err)
	}

	before := time.Now().UTC().Add(-time.Second)
	if err := MarkVMLastUsed(name); err != nil {
		t.Fatalf("MarkVMLastUsed: %v", err)
	}
	after := time.Now().UTC().Add(time.Second)

	got, has, err := domainLastUsed(dom)
	if err != nil {
		t.Fatalf("read last-used metadata: %v", err)
	}
	if !has {
		t.Fatal("expected last-used metadata")
	}
	if got == oldTimestamp {
		t.Fatal("expected MarkVMLastUsed to replace existing metadata")
	}

	markedAt, err := time.Parse(time.RFC3339, got)
	if err != nil {
		t.Fatalf("last-used timestamp %q is not RFC3339: %v", got, err)
	}
	if markedAt.Location() != time.UTC {
		t.Fatalf("expected UTC last-used timestamp, got %q", got)
	}
	if markedAt.Before(before) || markedAt.After(after) {
		t.Fatalf("last-used timestamp %q is outside expected range %s to %s", got, before, after)
	}
}

func TestViocovNowLastUsedTimestamp(t *testing.T) {
	got := nowLastUsedTimestamp()
	parsed, err := time.Parse(time.RFC3339, got)
	if err != nil {
		t.Fatalf("timestamp %q is not RFC3339: %v", got, err)
	}
	if parsed.Location() != time.UTC {
		t.Fatalf("expected UTC timestamp, got %q", got)
	}
}
