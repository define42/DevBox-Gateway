package virt

import (
	"encoding/xml"
	"testing"
)

func testProvisioningIntent() provisioningIntent {
	return provisioningIntent{
		Version: 1, State: provisioningPending,
		UUID: "3254d935-75f7-4f39-a95d-48a876e9a4ec", Name: "alice.desktop", Owner: "alice",
		Pool: "desktop", PoolUUID: "cdbcc3f0-cc72-42e0-adcb-e47c976607a1", PoolPath: "/var/lib/devbox/images",
		Disk: "alice.desktop", Seed: "alice.desktop_seed.iso",
	}
}

func TestProvisioningIntentValidation(t *testing.T) {
	tests := []struct {
		name   string
		change func(*provisioningIntent)
	}{
		{"unknown version", func(i *provisioningIntent) { i.Version++ }},
		{"unknown state", func(i *provisioningIntent) { i.State = "unknown" }},
		{"missing UUID", func(i *provisioningIntent) { i.UUID = "" }},
		{"missing pool UUID", func(i *provisioningIntent) { i.PoolUUID = "" }},
		{"foreign owner", func(i *provisioningIntent) { i.Owner = "bob" }},
		{"foreign disk", func(i *provisioningIntent) { i.Disk = "bob.desktop" }},
		{"foreign seed", func(i *provisioningIntent) { i.Seed = "bob.desktop_seed.iso" }},
		{"relative pool", func(i *provisioningIntent) { i.PoolPath = "../images" }},
		{"unclean pool", func(i *provisioningIntent) { i.PoolPath += "/../images" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			intent := testProvisioningIntent()
			test.change(&intent)
			if err := intent.validate(); err == nil {
				t.Fatal("accepted an unsafe provisioning intent")
			}
		})
	}
	for _, state := range []string{provisioningPending, provisioningReady, provisioningRollback} {
		intent := testProvisioningIntent()
		intent.State = state
		if err := intent.validate(); err != nil {
			t.Fatalf("valid state %s: %v", state, err)
		}
	}
}

func TestPendingProvisioningXMLPersistsOwnershipAtomically(t *testing.T) {
	intent := testProvisioningIntent()
	doc, err := pendingProvisioningXML(intent)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateProvisioningDomainXML(doc, intent); err != nil {
		t.Fatalf("initial definition lacks durable domain ownership: %v", err)
	}
	var parsed struct {
		Metadata struct {
			Intent provisioningIntent `xml:"urn:devboxgateway:domain:provisioning provisioning"`
		} `xml:"metadata"`
		Devices struct {
			Disks      []struct{} `xml:"disk"`
			Interfaces []struct{} `xml:"interface"`
		} `xml:"devices"`
	}
	if err := xml.Unmarshal([]byte(doc), &parsed); err != nil {
		t.Fatal(err)
	}
	if !sameProvisioningOperation(parsed.Metadata.Intent, intent) || parsed.Metadata.Intent.State != provisioningPending {
		t.Fatalf("initial definition lost its recovery record: %+v", parsed.Metadata.Intent)
	}
	if len(parsed.Devices.Disks) != 0 || len(parsed.Devices.Interfaces) != 0 {
		t.Fatal("intent definition attached resources before they were provisioned")
	}
}

func TestProvisioningStartXMLRetainsIntentAndUUID(t *testing.T) {
	intent := testProvisioningIntent()
	cfg := VMStartConfig{
		Name: intent.Name, SeedISO: intent.Seed, StoragePoolName: intent.Pool,
		VCPU: 1, MemoryMiB: 128, Network: identityForAddress(2), provisioning: &intent,
	}
	doc, err := provisioningStartXML(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateProvisioningDomainXML(doc, intent); err != nil {
		t.Fatalf("full definition changed operation identity: %v", err)
	}
	var parsed struct {
		Metadata struct {
			Intent provisioningIntent `xml:"urn:devboxgateway:domain:provisioning provisioning"`
		} `xml:"metadata"`
	}
	if err := xml.Unmarshal([]byte(doc), &parsed); err != nil {
		t.Fatal(err)
	}
	if !sameProvisioningOperation(parsed.Metadata.Intent, intent) || parsed.Metadata.Intent.State != provisioningPending {
		t.Fatalf("full definition lost its pending record: %+v", parsed.Metadata.Intent)
	}
}

func TestProvisioningPoolIdentityRejectsReplacement(t *testing.T) {
	intent := testProvisioningIntent()
	tests := []struct {
		name string
		id   string
		path string
	}{
		{"replacement pool", "2c8a7502-1b6f-419e-bc47-56b75c496cde", intent.PoolPath},
		{"relocated pool", intent.PoolUUID, "/elsewhere"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := verifyProvisioningPoolIdentity(test.id, test.path, intent); err == nil {
				t.Fatal("recovery accepted different storage identity")
			}
		})
	}
}
