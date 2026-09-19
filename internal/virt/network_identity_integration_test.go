package virt

import (
	"fmt"
	"testing"
	"time"

	"libvirt.org/go/libvirt"
)

func TestConcurrentNetworkReservations(t *testing.T) {
	conn := newTestLibvirtConn(t)
	if err := ensureDefaultNetwork(conn); err != nil {
		t.Fatal(err)
	}
	const count = 8
	prefix := fmt.Sprintf("network-allocation-%d", time.Now().UnixNano())
	names := make([]string, count)
	for i := range names {
		names[i] = fmt.Sprintf("%s-%d", prefix, i)
	}
	t.Cleanup(func() {
		for _, name := range names {
			if err := releaseNetworkIdentity(conn, name); err != nil {
				t.Errorf("release %s: %v", name, err)
			}
		}
	})
	identities := concurrentlyReserveIdentities(t, names)
	for i, identity := range identities {
		reopened, err := reserveNetworkIdentity(conn, names[i])
		if err != nil || reopened != identity {
			t.Fatalf("reservation did not persist: got %+v, %v; want %+v", reopened, err, identity)
		}
	}
	verifyReservedIdentities(t, conn, names, identities)
}

func concurrentlyReserveIdentities(t *testing.T, names []string) []NetworkIdentity {
	t.Helper()
	type result struct {
		index    int
		identity NetworkIdentity
		err      error
	}
	ready := make(chan struct{})
	results := make(chan result, len(names))
	for i, name := range names {
		go func() {
			<-ready
			identity, err := reserveFromIndependentConnection(name)
			results <- result{i, identity, err}
		}()
	}
	close(ready)
	identities := make([]NetworkIdentity, len(names))
	for range names {
		got := <-results
		if got.err != nil {
			t.Errorf("concurrent reservation %s: %v", names[got.index], got.err)
		}
		identities[got.index] = got.identity
	}
	if t.Failed() {
		t.FailNow()
	}
	return identities
}

// Independent connections deliberately bypass the process mutex, modeling two
// gateway processes that read the same free address before either updates it.
func reserveFromIndependentConnection(name string) (NetworkIdentity, error) {
	conn, err := libvirt.NewConnect(LibvirtURI())
	if err != nil {
		return NetworkIdentity{}, err
	}
	defer func() { _, _ = conn.Close() }()
	network, err := conn.LookupNetworkByName(defaultNetworkName)
	if err != nil {
		return NetworkIdentity{}, err
	}
	defer func() { _ = network.Free() }()
	return reserveAvailableNetworkIdentity(network, name)
}

func verifyReservedIdentities(t *testing.T, conn *libvirt.Connect, names []string, identities []NetworkIdentity) {
	t.Helper()
	network, err := conn.LookupNetworkByName(defaultNetworkName)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = network.Free() }()
	hosts, err := readNetworkReservations(network)
	if err != nil {
		t.Fatalf("persistent and live reservations must agree: %v", err)
	}
	seen := make(map[NetworkIdentity]bool, len(identities))
	for i, identity := range identities {
		if seen[identity] {
			t.Fatalf("two VMs share network identity %+v", identity)
		}
		seen[identity] = true
		if err := validateIdentityReservation(hosts, names[i], identity); err != nil {
			t.Fatal(err)
		}
	}
}
