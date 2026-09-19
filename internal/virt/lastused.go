package virt

import (
	"encoding/xml"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"libvirt.org/go/libvirt"
)

const (
	domainLastUsedMetadataNamespace = "urn:devboxgateway:domain:lastused"
	domainLastUsedMetadataPrefix    = "devboxgatewaylastused"
)

type domainLastUsedMetadata struct {
	XMLName xml.Name `xml:"lastused"`
	Value   string   `xml:",chardata"`
}

func domainLastUsedMetadataXML(lastUsed string) (string, error) {
	lastUsed = strings.TrimSpace(lastUsed)
	if lastUsed == "" {
		return "", fmt.Errorf("domain last-used metadata requires a non-empty timestamp")
	}

	payload, err := xml.Marshal(domainLastUsedMetadata{Value: lastUsed})
	if err != nil {
		return "", fmt.Errorf("marshal domain last-used metadata: %w", err)
	}
	return string(payload), nil
}

func setDomainLastUsedMetadata(dom *libvirt.Domain, lastUsed string) error {
	payload, err := domainLastUsedMetadataXML(lastUsed)
	if err != nil {
		return err
	}

	return dom.SetMetadata(
		libvirt.DOMAIN_METADATA_ELEMENT,
		payload,
		domainLastUsedMetadataPrefix,
		domainLastUsedMetadataNamespace,
		libvirt.DOMAIN_AFFECT_CONFIG,
	)
}

func domainLastUsed(dom *libvirt.Domain) (string, bool, error) {
	payload, err := dom.GetMetadata(
		libvirt.DOMAIN_METADATA_ELEMENT,
		domainLastUsedMetadataNamespace,
		libvirt.DOMAIN_AFFECT_CONFIG,
	)
	if err != nil {
		if errors.Is(err, libvirt.ERR_NO_DOMAIN_METADATA) {
			return "", false, nil
		}
		return "", false, fmt.Errorf("get domain last-used metadata: %w", err)
	}

	var metadata domainLastUsedMetadata
	if err := xml.Unmarshal([]byte(payload), &metadata); err != nil {
		return "", false, fmt.Errorf("parse domain last-used metadata: %w", err)
	}

	lastUsed := strings.TrimSpace(metadata.Value)
	if lastUsed == "" {
		return "", false, nil
	}
	return lastUsed, true, nil
}

// formatLastUsedTimestamp renders a last-used time as the RFC3339 UTC string
// stored in domain last-used metadata.
func formatLastUsedTimestamp(t time.Time) string {
	return t.UTC().Format(time.RFC3339)
}

func parseLastUsedTimestamp(value string) (time.Time, error) {
	return time.Parse(time.RFC3339, strings.TrimSpace(value))
}

// vmLastUsedRegistry is the in-memory record of when each VDI was last used,
// keyed by VM name. It is the fast path the auto-shutdown sweeper reads on
// every pass; the durable copy lives in per-domain last-used metadata so the
// timestamps survive gateway restarts.
type vmLastUsedRegistry struct {
	mu     sync.Mutex
	times  map[string]time.Time
	uses   map[string]map[*vmUse]struct{}
	guards *keyedMutex
}

func newVMLastUsedRegistry() *vmLastUsedRegistry {
	return &vmLastUsedRegistry{
		times:  make(map[string]time.Time),
		uses:   make(map[string]map[*vmUse]struct{}),
		guards: newKeyedMutex(),
	}
}

// vmUse has a distinct identity for each connection, including connections to
// a VM recreated under the same name. A nonzero-sized token keeps pointers unique.
type vmUse struct{ _ byte }

func (r *vmLastUsedRegistry) beginUse(name string, now time.Time) *vmUse {
	r.mu.Lock()
	defer r.mu.Unlock()
	use := &vmUse{}
	if r.uses[name] == nil {
		r.uses[name] = make(map[*vmUse]struct{})
	}
	r.uses[name][use] = struct{}{}
	r.times[name] = now
	return use
}

func (r *vmLastUsedRegistry) endUse(name string, use *vmUse, now time.Time) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.uses[name][use]; !ok {
		return false
	}
	delete(r.uses[name], use)
	if len(r.uses[name]) == 0 {
		delete(r.uses, name)
	}
	r.times[name] = now
	return true
}

func (r *vmLastUsedRegistry) inUse(name string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.uses[name]) > 0
}

func (r *vmLastUsedRegistry) set(name string, t time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.times[name] = t
}

func (r *vmLastUsedRegistry) get(name string) (time.Time, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	t, ok := r.times[name]
	return t, ok
}

func (r *vmLastUsedRegistry) remove(name string) {
	unlock := r.guards.Lock(name)
	defer unlock()
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.times, name)
	delete(r.uses, name)
}

// retainNames drops inactive entries whose VM name is not in names. Live
// connections must remain protected even when a cached listing omits their VM.
func (r *vmLastUsedRegistry) retainNames(names map[string]struct{}) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for name := range r.times {
		if _, ok := names[name]; !ok && len(r.uses[name]) == 0 {
			delete(r.times, name)
		}
	}
}

// vmLastUsed records when each VDI was last used (created, started, or opened
// via RDP, serial, or noVNC). Process-wide because the touch points (dashboard
// handlers, VM start paths) and the auto-shutdown sweeper must observe one
// shared record.
var vmLastUsed = newVMLastUsedRegistry() //nolint:gochecknoglobals // process-wide last-used state shared by touch points and the auto-shutdown sweeper

// TrackVMUse protects a VM from auto-shutdown while an authorized RDP, serial,
// or VNC connection is opening or connected. Call the returned function when
// setup fails or the connection ends; it is safe to call more than once. The
// last disconnect starts a full idle window, including after a clean restart.
func TrackVMUse(name string) func() {
	name = strings.TrimSpace(name)
	if name == "" {
		return func() {}
	}
	unlock := vmLastUsed.guards.Lock(name)
	defer unlock()
	now := time.Now()
	use := vmLastUsed.beginUse(name, now)
	persistVMUse(name, now)
	notifyVMLastUsedChanged()

	return func() {
		unlock := vmLastUsed.guards.Lock(name)
		defer unlock()
		now := time.Now()
		if vmLastUsed.endUse(name, use, now) {
			persistVMUse(name, now)
			notifyVMLastUsedChanged()
		}
	}
}

func persistVMUse(name string, now time.Time) {
	if err := persistVMLastUsed(name, now); err != nil {
		log.Printf("persist last-used metadata for %s: %v", name, err)
	}
}

// MarkVMUsed records now as the named VM's last-used time, in memory and in
// the domain's persistent metadata. It is best-effort by design: the in-memory
// record always succeeds and governs auto-shutdown for this process lifetime,
// while a failed metadata write (libvirt hiccup) only costs durability across
// a gateway restart, so it is logged rather than surfaced to the caller —
// a user's RDP/serial/noVNC action must not fail because of it.
func MarkVMUsed(name string) {
	name = strings.TrimSpace(name)
	if name == "" {
		return
	}
	unlock := vmLastUsed.guards.Lock(name)
	defer unlock()

	now := time.Now()
	vmLastUsed.set(name, now)
	notifyVMLastUsedChanged()

	persistVMUse(name, now)
}

// notifyVMLastUsedChanged nudges open dashboards to re-pull VM data so a
// just-recorded touch (and its recomputed auto-shutdown countdown) is visible
// immediately. peekInventory keeps this from starting the background worker as
// a side effect; when the worker is not running there is nobody to notify.
func notifyVMLastUsedChanged() {
	if worker := peekInventory(); worker != nil {
		worker.NotifyVMDataChanged()
	}
}

func persistVMLastUsed(name string, t time.Time) error {
	conn, err := connectLibvirt()
	if err != nil {
		return fmt.Errorf("connect libvirt: %w", err)
	}
	defer func() {
		_, _ = conn.Close()
	}()

	dom, err := conn.LookupDomainByName(name)
	if err != nil {
		return fmt.Errorf("lookup domain %s: %w", name, err)
	}
	defer func() {
		_ = dom.Free()
	}()

	return setDomainLastUsedMetadata(dom, formatLastUsedTimestamp(t))
}

// markDomainUsed is MarkVMUsed for callers that already hold the domain handle
// (the VM start paths), saving the extra connection. Same best-effort
// semantics: the started VM must not be reported as failed over a metadata
// stamp, so persistence errors are only logged.
func markDomainUsed(dom *libvirt.Domain, name string) {
	unlock := vmLastUsed.guards.Lock(name)
	defer unlock()
	now := time.Now()
	vmLastUsed.set(name, now)
	notifyVMLastUsedChanged()
	if err := setDomainLastUsedMetadata(dom, formatLastUsedTimestamp(now)); err != nil {
		log.Printf("persist last-used metadata for %s: %v", name, err)
	}
}

// loadVMLastUsedFromMetadata recovers the persisted last-used timestamp for
// the named VM, used to warm the in-memory registry after a gateway restart.
// Absent or unreadable metadata reports false so the caller can grant a fresh
// idle window instead of acting on unknown history.
func loadVMLastUsedFromMetadata(name string) (time.Time, bool) {
	conn, err := connectLibvirt()
	if err != nil {
		log.Printf("load last-used metadata for %s: connect libvirt: %v", name, err)
		return time.Time{}, false
	}
	defer func() {
		_, _ = conn.Close()
	}()

	dom, err := conn.LookupDomainByName(name)
	if err != nil {
		log.Printf("load last-used metadata for %s: lookup domain: %v", name, err)
		return time.Time{}, false
	}
	defer func() {
		_ = dom.Free()
	}()

	value, has, err := domainLastUsed(dom)
	if err != nil {
		log.Printf("load last-used metadata for %s: %v", name, err)
		return time.Time{}, false
	}
	if !has {
		return time.Time{}, false
	}

	t, err := parseLastUsedTimestamp(value)
	if err != nil {
		log.Printf("load last-used metadata for %s: parse %q: %v", name, value, err)
		return time.Time{}, false
	}
	return t, true
}
