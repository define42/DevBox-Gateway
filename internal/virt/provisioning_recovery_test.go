package virt

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestProvisioningRecoveryCrashPoints(t *testing.T) {
	tests := []struct {
		name     string
		state    string
		active   bool
		rollback bool
		failAt   string
		want     []string
	}{
		{"intent before allocation", provisioningPending, false, false, "", []string{"validate", "intent", "volumes", "network", "undefine"}},
		{"partial disk upload", provisioningPending, false, false, "", []string{"validate", "intent", "volumes", "network", "undefine"}},
		{"ready before first start", provisioningReady, false, false, "", nil},
		{"started then guest shut off", provisioningReady, false, false, "", nil},
		{"started VM", provisioningReady, true, false, "", nil},
		{"unexpected active incomplete VM", provisioningPending, true, false, "active", nil},
		{"failed request after start", provisioningReady, true, true, "", []string{"validate", "intent", "stop", "volumes", "network", "undefine"}},
		{"crash during running rollback", provisioningRollback, true, false, "", []string{"validate", "intent", "stop", "volumes", "network", "undefine"}},
		{"in use or replaced storage", provisioningPending, false, false, "validate", []string{"validate"}},
		{"failed rollback marker", provisioningReady, true, true, "intent", []string{"validate", "intent"}},
		{"failed stop", provisioningReady, true, true, "stop", []string{"validate", "intent", "stop"}},
		{"failed disk cleanup", provisioningPending, false, false, "volumes", []string{"validate", "intent", "volumes"}},
		{"failed network cleanup", provisioningPending, false, false, "network", []string{"validate", "intent", "volumes", "network"}},
		{"failed intent removal", provisioningPending, false, false, "undefine", []string{"validate", "intent", "volumes", "network", "undefine"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			intent := testProvisioningIntent()
			intent.State = test.state
			var calls []string
			action := func(name string) func() error {
				return func() error {
					calls = append(calls, name)
					if name == test.failAt {
						return errors.New("injected failure")
					}
					return nil
				}
			}
			err := runProvisioningRecovery(intent, test.active, test.rollback, provisioningRecoveryActions{
				validateStorage: action("validate"), beginRollback: action("intent"), stop: action("stop"),
				removeVolumes: action("volumes"), releaseNetwork: action("network"), undefine: action("undefine"),
			})
			if (err != nil) != (test.failAt != "") {
				t.Fatalf("recovery error = %v, failAt = %q", err, test.failAt)
			}
			if !reflect.DeepEqual(calls, test.want) {
				t.Fatalf("recovery actions = %v, want %v", calls, test.want)
			}
		})
	}
}

func TestProvisioningRecoveryResumesAfterPartialCleanup(t *testing.T) {
	intent := testProvisioningIntent()
	intent.State = provisioningReady
	disk, network, domain := true, true, true
	failNetwork := true
	actions := provisioningRecoveryActions{
		validateStorage: func() error { return nil },
		beginRollback:   func() error { intent.State = provisioningRollback; return nil },
		stop:            func() error { return nil },
		removeVolumes:   func() error { disk = false; return nil },
		releaseNetwork: func() error {
			if failNetwork {
				return errors.New("interrupted after disk removal")
			}
			network = false
			return nil
		},
		undefine: func() error { domain = false; return nil },
	}
	if err := runProvisioningRecovery(intent, false, true, actions); err == nil {
		t.Fatal("expected interrupted rollback")
	}
	if disk || !network || !domain || intent.State != provisioningRollback {
		t.Fatal("partial cleanup did not retain durable rollback ownership")
	}
	// Simulate a fresh process: it has only the persisted state, no knowledge
	// that the original request asked to roll back a previously ready VM.
	failNetwork = false
	if err := runProvisioningRecovery(intent, false, false, actions); err != nil {
		t.Fatalf("resume rollback: %v", err)
	}
	if disk || network || domain {
		t.Fatal("resumed cleanup left owned resources")
	}
}

func TestProvisioningRecoveryRejectsForeignIdentity(t *testing.T) {
	intent := testProvisioningIntent()
	doc, err := pendingProvisioningXML(intent)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		doc  string
	}{
		{"different UUID", strings.Replace(doc, "<uuid>"+intent.UUID, "<uuid>dd127f9c-2a5f-477e-aa6d-452de7b10f20", 1)},
		{"different name", strings.Replace(doc, "<name>"+intent.Name, "<name>bob.desktop", 1)},
		{"different owner", strings.Replace(doc, "'>alice</owner>", "'>bob</owner>", 1)},
		{"unrelated attached disk", strings.Replace(doc, "</domain>", "<devices><disk><source pool='desktop' volume='bob.desktop'/></disk></devices></domain>", 1)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := validateProvisioningDomainXML(test.doc, intent); err == nil {
				t.Fatal("recovery accepted a foreign identity or disk")
			}
		})
	}
}

func TestProvisioningRecoveryFindsOtherDiskUsers(t *testing.T) {
	intent := testProvisioningIntent()
	tests := []struct {
		name string
		doc  string
		used bool
	}{
		{"pool volume", "<domain><devices><disk><source pool='desktop' volume='alice.desktop'/></disk></devices></domain>", true},
		{"file disk", "<domain><devices><disk><source file='/var/lib/devbox/images/alice.desktop'/></disk></devices></domain>", true},
		{"backing file", "<domain><devices><disk><source file='/another.qcow2'/><backingStore><source file='/var/lib/devbox/images/alice.desktop'/></backingStore></disk></devices></domain>", true},
		{"seed disk", "<domain><devices><disk><source file='/var/lib/devbox/images/alice.desktop_seed.iso'/></disk></devices></domain>", true},
		{"unrelated disk", "<domain><devices><disk><source pool='desktop' volume='bob.desktop'/></disk></devices></domain>", false},
		{"unrelated domain", "<domain><name>bob.desktop</name></domain>", false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := referencesProvisioningVolume(test.doc, intent)
			if err != nil || got != test.used {
				t.Fatalf("disk reference = %v, %v; want %v", got, err, test.used)
			}
		})
	}
}
