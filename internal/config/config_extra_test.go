package config

import (
	"strings"
	"testing"
)

func TestGetStringFormatsAllKinds(t *testing.T) {
	s := &SettingsType{m: map[string]*Setting{}}
	s.SetString("S", "string", "hello")
	s.SetInt("I", "int", 7)
	s.SetBool("B", "bool", true)
	s.SetDuration("D", "duration", 0)

	tests := map[string]string{
		"S": "hello",
		"I": "7",
		"B": "true",
		"D": "0s",
	}
	for id, want := range tests {
		if got := s.GetString(id); got != want {
			t.Fatalf("GetString(%s)=%q, want %q", id, got, want)
		}
	}

	// Unknown kind falls back to Raw.
	s.m["X"] = &Setting{Kind: Kind(99), Raw: "raw"}
	if got := s.GetString("X"); got != "raw" {
		t.Fatalf("GetString(X)=%q, want raw", got)
	}
}

func TestOverwriteForTestStringMismatch(t *testing.T) {
	s := &SettingsType{m: map[string]*Setting{}}
	s.SetInt("I", "int", 7)
	err := s.OverwriteForTestString("I", "hello")
	if err == nil {
		t.Fatal("expected mismatch error when overriding int as string")
	}
	var mismatch *SettingTypeMismatchError
	if !asTypeMismatch(err, &mismatch) {
		t.Fatalf("expected SettingTypeMismatchError, got %T", err)
	}
	if mismatch.Expected != KindString || mismatch.Actual != KindInt {
		t.Fatalf("unexpected kinds in error: %+v", mismatch)
	}
	if !strings.Contains(mismatch.Error(), "string") || !strings.Contains(mismatch.Error(), "int") {
		t.Fatalf("expected error to mention kinds, got %q", mismatch.Error())
	}
}

func TestKindToStringUnknown(t *testing.T) {
	if got := kindToString(Kind(99)); got != "unknown" {
		t.Fatalf("expected unknown for invalid kind, got %q", got)
	}
}

// asTypeMismatch is a small helper to avoid importing errors here just for one call.
func asTypeMismatch(err error, target **SettingTypeMismatchError) bool {
	if err == nil {
		return false
	}
	if e, ok := err.(*SettingTypeMismatchError); ok {
		*target = e
		return true
	}
	return false
}
