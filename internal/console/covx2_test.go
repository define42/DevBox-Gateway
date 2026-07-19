package console

import (
	"devboxgateway/internal/session"
	"devboxgateway/internal/virt"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"libvirt.org/go/libvirt"
)

// covxDomainXML is a minimal diskless TCG domain whose BIOS mirrors its boot
// messages to the serial console (bios useserial -> machine graphics=off), so
// the serial bridge sees real console output without booting an OS. The VNC
// socket is libvirt-managed like the production template.
const covxDomainXML = `<domain type='qemu'>
  <name>%s</name>
  <memory unit='MiB'>64</memory>
  <vcpu>1</vcpu>
  <os>
    <type arch='x86_64'>hvm</type>
    <bios useserial='yes'/>
  </os>
  <devices>
    <emulator>/usr/bin/qemu-system-x86_64</emulator>
    <serial type='pty'>
      <target port='0'/>
    </serial>
    <graphics type='vnc' autoport='no'>
      <listen type='socket'/>
    </graphics>
  </devices>
</domain>`

const (
	// covxOwnerMetadata mirrors the payload the virt package stores under its
	// owner metadata namespace for VMs owned by covxTestUsername.
	covxOwnerMetadata       = "<owner>" + covxTestUsername + "</owner>"
	covxOtherOwnerMetadata  = "<owner>covx-other-user</owner>"
	covxBrokenOwnerMetadata = "<notowner>covx</notowner>"

	covxOwnerMetadataPrefix = "devboxgateway"
	covxOwnerMetadataNS     = "urn:devboxgateway:domain:owner"

	// covxSerialDataTimeout bounds how long tests wait for the BIOS to produce
	// serial output after resuming a domain (typically well under two seconds).
	covxSerialDataTimeout = 15 * time.Second
)

type covxDomain struct {
	t    *testing.T
	dom  *libvirt.Domain
	name string
}

func covxDefineDomain(t *testing.T, suffix string) *covxDomain {
	t.Helper()

	name := fmt.Sprintf("covx-%s-%d", suffix, time.Now().UnixNano())
	conn, err := libvirt.NewConnect(virt.LibvirtURI())
	if err != nil {
		t.Fatalf("connect libvirt: %v", err)
	}

	dom, err := conn.DomainDefineXML(fmt.Sprintf(covxDomainXML, name))
	if err != nil {
		_, _ = conn.Close()
		t.Fatalf("define test domain %s: %v", name, err)
	}
	t.Cleanup(func() {
		_ = dom.Destroy()
		_ = dom.Undefine()
		_ = dom.Free()
		_, _ = conn.Close()
	})
	return &covxDomain{t: t, dom: dom, name: name}
}

func (d *covxDomain) setOwnerMetadata(payload string) {
	d.t.Helper()

	err := d.dom.SetMetadata(
		libvirt.DOMAIN_METADATA_ELEMENT,
		payload,
		covxOwnerMetadataPrefix,
		covxOwnerMetadataNS,
		libvirt.DOMAIN_AFFECT_CONFIG,
	)
	if err != nil {
		d.t.Fatalf("set owner metadata on %s: %v", d.name, err)
	}
}

func (d *covxDomain) start() {
	d.t.Helper()
	if err := d.dom.Create(); err != nil {
		d.t.Fatalf("start test domain %s: %v", d.name, err)
	}
}

func (d *covxDomain) startPaused() {
	d.t.Helper()
	if err := d.dom.CreateWithFlags(libvirt.DOMAIN_START_PAUSED); err != nil {
		d.t.Fatalf("start test domain %s paused: %v", d.name, err)
	}
}

func (d *covxDomain) resume() {
	d.t.Helper()
	if err := d.dom.Resume(); err != nil {
		d.t.Fatalf("resume test domain %s: %v", d.name, err)
	}
}

func covxOpenConsole(t *testing.T, name string) *virt.SerialConsole {
	t.Helper()

	console, err := virt.OpenSerialConsole(name)
	if err != nil {
		t.Fatalf("open serial console for %s: %v", name, err)
	}
	return console
}

func TestCovxConsoleAndVNCOwnershipAndStoppedBranches(t *testing.T) {
	dom := covxDefineDomain(t, "own")
	manager := session.NewManager()
	server := covxDashboardServer(t, manager)
	cookie := covxSessionCookie(t, manager, covxTestUsername)

	tests := []struct {
		name       string
		metadata   string
		wantStatus int
		wantBody   string
	}{
		{name: "not owned", metadata: covxOtherOwnerMetadata, wantStatus: http.StatusForbidden, wantBody: "You do not have permission"},
		{name: "ownership lookup error", metadata: covxBrokenOwnerMetadata, wantStatus: http.StatusInternalServerError, wantBody: "Unable to verify VM ownership."},
		{name: "stopped vm", metadata: covxOwnerMetadata, wantStatus: http.StatusConflict, wantBody: "must be running for"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dom.setOwnerMetadata(tc.metadata)
			for _, channel := range []string{"console", "vnc"} {
				status, body := covxGetStatus(t, server, "/api/dashboard/"+channel+"/"+dom.name+"/ws", cookie)
				if status != tc.wantStatus {
					t.Fatalf("%s: expected %d, got %d with body %s", channel, tc.wantStatus, status, body)
				}
				if !strings.Contains(body, tc.wantBody) {
					t.Fatalf("%s: expected body to contain %q, got %q", channel, tc.wantBody, body)
				}
			}
		})
	}
}

func TestCovxConsoleAndVNCOnRunningVM(t *testing.T) {
	dom := covxDefineDomain(t, "run")
	dom.setOwnerMetadata(covxOwnerMetadata)
	dom.start()

	manager := session.NewManager()
	server := covxDashboardServer(t, manager)
	cookie := covxSessionCookie(t, manager, covxTestUsername)

	t.Run("plain request fails websocket upgrade", func(t *testing.T) {
		// The backend (serial console / VNC socket) opens successfully, then the
		// upgrade of a non-websocket request fails and the backend is closed.
		for _, channel := range []string{"console", "vnc"} {
			status, body := covxGetStatus(t, server, "/api/dashboard/"+channel+"/"+dom.name+"/ws", cookie)
			if status != http.StatusBadRequest {
				t.Fatalf("%s: expected %d, got %d with body %s", channel, http.StatusBadRequest, status, body)
			}
		}
	})

	t.Run("vnc websocket establishes and closes on revocation", func(t *testing.T) {
		conn := covxDialWebsocket(t, server, "/api/dashboard/vnc/"+dom.name+"/ws", cookie)
		// Revoking the user's connections runs the handler's registered close
		// callback, which tears the bridge down server-side.
		covxRevokeUserConnections(t, manager, covxTestUsername)
		covxAwaitWebsocketClosed(t, conn)
	})
}

func TestCovxDashboardConsoleWSEndToEnd(t *testing.T) {
	dom := covxDefineDomain(t, "serial")
	dom.setOwnerMetadata(covxOwnerMetadata)
	// Start paused so the console websocket is attached before the BIOS runs;
	// resuming afterwards makes its serial output arrive on the open bridge.
	dom.startPaused()

	manager := session.NewManager()
	server := covxDashboardServer(t, manager)
	cookie := covxSessionCookie(t, manager, covxTestUsername)

	conn := covxDialWebsocket(t, server, "/api/dashboard/console/"+dom.name+"/ws", cookie)
	dom.resume()

	if err := conn.SetReadDeadline(time.Now().Add(covxSerialDataTimeout)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	messageType, payload, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("read console output: %v", err)
	}
	if messageType != websocket.BinaryMessage {
		t.Fatalf("expected binary console output, got message type %d", messageType)
	}
	if len(payload) == 0 {
		t.Fatal("expected non-empty console output")
	}

	if err := conn.WriteMessage(websocket.BinaryMessage, []byte("\r")); err != nil {
		t.Fatalf("write console input: %v", err)
	}

	// Revoking the user's connections runs the handler's registered close
	// callback (websocket close + console interrupt), ending the bridge.
	covxRevokeUserConnections(t, manager, covxTestUsername)
	covxAwaitWebsocketClosed(t, conn)
}

func TestCovxPumpConsoleToWebsocketRecvError(t *testing.T) {
	dom := covxDefineDomain(t, "pumprecv")
	dom.startPaused()

	_, serverWS, cleanup := newWebsocketPair(t)
	defer cleanup()

	console := covxOpenConsole(t, dom.name)
	done := make(chan struct{})
	go func() {
		pumpConsoleToWebsocket(dom.name, serverWS, console)
		close(done)
	}()

	// Interrupt aborts the console stream, so Recv fails with a non-EOF error.
	if err := console.Interrupt(); err != nil {
		t.Fatalf("interrupt console: %v", err)
	}

	select {
	case <-done:
	case <-time.After(websocketTestTimeout):
		t.Fatal("pumpConsoleToWebsocket did not return after interrupt")
	}
	_ = console.Close()
}

func TestCovxPumpConsoleToWebsocketWriteFailure(t *testing.T) {
	dom := covxDefineDomain(t, "pumpwrite")
	dom.startPaused()

	_, serverWS, cleanup := newWebsocketPair(t)
	defer cleanup()

	console := covxOpenConsole(t, dom.name)
	// Closing the server websocket makes the write of the first received console
	// bytes fail deterministically — the pump now sets a fresh write deadline
	// before each write, so an expired deadline would be overwritten.
	if err := serverWS.Close(); err != nil {
		t.Fatalf("close server websocket: %v", err)
	}

	done := make(chan struct{})
	go func() {
		pumpConsoleToWebsocket(dom.name, serverWS, console)
		close(done)
	}()

	dom.resume()

	select {
	case <-done:
	case <-time.After(covxSerialDataTimeout):
		t.Fatal("pumpConsoleToWebsocket did not return after websocket write failure")
	}
	_ = console.Interrupt()
	_ = console.Close()
}

func TestCovxSendAllToConsole(t *testing.T) {
	dom := covxDefineDomain(t, "send")
	dom.startPaused()

	console := covxOpenConsole(t, dom.name)
	if err := sendAllToConsole(console, []byte("\r")); err != nil {
		t.Fatalf("send to live console: %v", err)
	}

	if err := console.Interrupt(); err != nil {
		t.Fatalf("interrupt console: %v", err)
	}
	if err := sendAllToConsole(console, []byte("x")); err == nil {
		t.Fatal("expected error sending to an interrupted console")
	}
	_ = console.Close()
}

func TestCovxPumpWebsocketToConsoleSendError(t *testing.T) {
	dom := covxDefineDomain(t, "wssend")
	dom.startPaused()

	console := covxOpenConsole(t, dom.name)
	if err := console.Interrupt(); err != nil {
		t.Fatalf("interrupt console: %v", err)
	}

	clientWS, serverWS, cleanup := newWebsocketPair(t)
	defer cleanup()

	done := make(chan struct{})
	go func() {
		pumpWebsocketToConsole(dom.name, serverWS, console)
		close(done)
	}()

	if err := clientWS.WriteMessage(websocket.BinaryMessage, []byte("input")); err != nil {
		t.Fatalf("write websocket payload: %v", err)
	}

	select {
	case <-done:
	case <-time.After(websocketTestTimeout):
		t.Fatal("pumpWebsocketToConsole did not return after console send failure")
	}
	_ = console.Close()
}
