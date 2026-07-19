package dashboard

import (
	"devboxgateway/internal/config"
	"devboxgateway/internal/hash"
	"devboxgateway/internal/virt"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"libvirt.org/go/libvirt"
)

const (
	covxOwnerMetadataNamespace = "urn:devboxgateway:domain:owner"
	covxOwnerMetadataPrefix    = "devboxgateway"
	covxFrontDomain            = "covx.example.test"
	covxSNISecret              = "covx-secret"
)

type covxOwnerMetadata struct {
	XMLName xml.Name `xml:"owner"`
	Value   string   `xml:",chardata"`
}

// covxFailingWriter records headers/status but fails every body write, so the
// write-error logging branches can be exercised.
type covxFailingWriter struct {
	header http.Header
	status int
}

func (w *covxFailingWriter) Header() http.Header {
	if w.header == nil {
		w.header = make(http.Header)
	}
	return w.header
}

func (w *covxFailingWriter) WriteHeader(status int) { w.status = status }

func (w *covxFailingWriter) Write([]byte) (int, error) {
	return 0, errors.New("covx write failed")
}

func covxDomainXML(name string) string {
	return fmt.Sprintf(`<domain type='qemu'>
  <name>%s</name>
  <memory unit='MiB'>64</memory>
  <currentMemory unit='MiB'>64</currentMemory>
  <vcpu placement='static'>1</vcpu>
  <os>
    <type arch='x86_64' machine='q35'>hvm</type>
  </os>
</domain>`, name)
}

func covxDefineOwnedDomain(t *testing.T, name, owner string) {
	t.Helper()

	conn, err := libvirt.NewConnect(virt.LibvirtURI())
	if err != nil {
		t.Fatalf("connect libvirt: %v", err)
	}
	defer func() { _, _ = conn.Close() }()

	dom, err := conn.DomainDefineXML(covxDomainXML(name))
	if err != nil {
		t.Fatalf("define test domain %q: %v", name, err)
	}
	t.Cleanup(func() { covxUndefineDomain(name) })
	defer func() { _ = dom.Free() }()

	payload, err := xml.Marshal(covxOwnerMetadata{Value: owner})
	if err != nil {
		t.Fatalf("marshal owner metadata for %q: %v", name, err)
	}
	if err := dom.SetMetadata(
		libvirt.DOMAIN_METADATA_ELEMENT,
		string(payload),
		covxOwnerMetadataPrefix,
		covxOwnerMetadataNamespace,
		libvirt.DOMAIN_AFFECT_CONFIG,
	); err != nil {
		t.Fatalf("set owner metadata for %q: %v", name, err)
	}
}

func covxUndefineDomain(name string) {
	conn, err := libvirt.NewConnect(virt.LibvirtURI())
	if err != nil {
		return
	}
	defer func() { _, _ = conn.Close() }()

	dom, err := conn.LookupDomainByName(name)
	if err != nil {
		return
	}
	defer func() { _ = dom.Free() }()

	if active, activeErr := dom.IsActive(); activeErr == nil && active {
		_ = dom.Destroy()
	}
	_ = dom.Undefine()
}

// covxWaitForVM polls the VM cache until the owner's VM shows up; the
// background worker refreshes from libvirt every couple of seconds.
func covxWaitForVM(t *testing.T, owner string) {
	t.Helper()

	deadline := time.Now().Add(20 * time.Second)
	for len(virt.GetInstance().GetVMs(owner)) == 0 {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for a VM owned by %q in the cache", owner)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func TestWriteRDPFileNotFound(t *testing.T) {
	settings := config.NewSettingType(false)

	rec := httptest.NewRecorder()
	WriteRDPFile(rec, settings, fmt.Sprintf("covx-nobody-%d", time.Now().UnixNano()), "covx-missing-vm")

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected %d, got %d", http.StatusNotFound, rec.Code)
	}
	var payload ActionResponse
	if err := json.NewDecoder(rec.Body).Decode(&payload); err != nil {
		t.Fatalf("decode JSON response: %v", err)
	}
	if payload.OK || payload.Error != "VM not found." {
		t.Fatalf("unexpected payload: %+v", payload)
	}
}

func TestWriteRDPFileWithLibvirtVM(t *testing.T) {
	suffix := time.Now().UnixNano()
	owner := fmt.Sprintf("covxowner%d", suffix)
	vmName := fmt.Sprintf("covxdash%d", suffix)
	covxDefineOwnedDomain(t, vmName, owner)
	covxWaitForVM(t, owner)

	t.Setenv(config.FRONT_DOMAIN, covxFrontDomain)
	t.Setenv(config.SNI_HASH_SECRET, covxSNISecret)
	settings := config.NewSettingType(false)

	t.Run("download", func(t *testing.T) {
		rec := httptest.NewRecorder()
		WriteRDPFile(rec, settings, owner, vmName)
		assertRDPDownload(t, rec, owner, vmName)
	})

	t.Run("other VM name not found", func(t *testing.T) {
		if _, _, ok := RDPFileForUser(settings, owner, vmName+"-other"); ok {
			t.Fatal("expected no .rdp file for a VM name the user does not own")
		}
	})

	t.Run("write error is tolerated", func(t *testing.T) {
		writer := &covxFailingWriter{}
		WriteRDPFile(writer, settings, owner, vmName)
		if writer.status != http.StatusOK {
			t.Fatalf("expected status %d despite write failure, got %d", http.StatusOK, writer.status)
		}
	})
}

func assertRDPDownload(t *testing.T, rec *httptest.ResponseRecorder, owner, vmName string) {
	t.Helper()

	if rec.Code != http.StatusOK {
		t.Fatalf("expected %d, got %d", http.StatusOK, rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/x-rdp" {
		t.Fatalf("expected application/x-rdp content type, got %q", ct)
	}
	wantDisposition := fmt.Sprintf("attachment; filename=%q", vmName+".rdp")
	if got := rec.Header().Get("Content-Disposition"); got != wantDisposition {
		t.Fatalf("expected Content-Disposition %q, got %q", wantDisposition, got)
	}

	body := rec.Body.String()
	wantHost := hash.RoutingLabel([]byte(covxSNISecret), vmName) + "." + covxFrontDomain
	if !strings.Contains(body, "full address:s:"+wantHost+":443") {
		t.Fatalf("expected connect host %q in body %q", wantHost, body)
	}
	// The test domain carries no guest-user metadata, so the RDP login falls
	// back to the requesting user.
	if !strings.Contains(body, "username:s:"+owner) {
		t.Fatalf("expected fallback RDP username %q in body %q", owner, body)
	}
}

func TestRDPConnectHostWithoutFrontDomain(t *testing.T) {
	t.Setenv(config.FRONT_DOMAIN, "")
	settings := config.NewSettingType(false)

	if got := rdpConnectHost(settings, "covx-vm"); got != "covx-vm" {
		t.Fatalf("expected bare VM name without a front domain, got %q", got)
	}
}

func TestWriteJSONEncodeError(t *testing.T) {
	writer := &covxFailingWriter{}
	WriteJSON(writer, http.StatusOK, ActionResponse{OK: true})

	if writer.status != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, writer.status)
	}
	if ct := writer.Header().Get("Content-Type"); ct != "application/json; charset=utf-8" {
		t.Fatalf("expected JSON content type, got %q", ct)
	}
}
