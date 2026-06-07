package virt

import "testing"

func TestCheckLibvirtVersion(t *testing.T) {
	tests := []struct {
		name    string
		version uint32
		wantErr bool
	}{
		{name: "exact minimum 6.2.0", version: 6*1_000_000 + 2*1_000, wantErr: false},
		{name: "newer minor 6.3.0", version: 6*1_000_000 + 3*1_000, wantErr: false},
		{name: "newer major 7.0.0", version: 7 * 1_000_000, wantErr: false},
		{name: "patch above minimum 6.2.1", version: 6*1_000_000 + 2*1_000 + 1, wantErr: false},
		{name: "too old 6.1.0", version: 6*1_000_000 + 1*1_000, wantErr: true},
		{name: "too old 6.0.0", version: 6 * 1_000_000, wantErr: true},
		{name: "too old 5.10.0", version: 5*1_000_000 + 10*1_000, wantErr: true},
		{name: "zero", version: 0, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkLibvirtVersion(tt.version)
			if tt.wantErr && err == nil {
				t.Fatalf("checkLibvirtVersion(%d) = nil, want error", tt.version)
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("checkLibvirtVersion(%d) = %v, want nil", tt.version, err)
			}
		})
	}
}

func TestFormatLibvirtVersion(t *testing.T) {
	tests := []struct {
		version uint32
		want    string
	}{
		{version: 6*1_000_000 + 2*1_000, want: "6.2.0"},
		{version: 6*1_000_000 + 2*1_000 + 1, want: "6.2.1"},
		{version: 7 * 1_000_000, want: "7.0.0"},
		{version: 5*1_000_000 + 10*1_000 + 3, want: "5.10.3"},
		{version: 0, want: "0.0.0"},
	}

	for _, tt := range tests {
		if got := formatLibvirtVersion(tt.version); got != tt.want {
			t.Errorf("formatLibvirtVersion(%d) = %q, want %q", tt.version, got, tt.want)
		}
	}
}
