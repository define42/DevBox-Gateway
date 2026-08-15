package virt

import (
	"fmt"
	"log"
	"strings"
	"time"

	"libvirt.org/go/libvirt"
)

// enforceIdleAutoShutdown force-stops active gateway-managed domains whose
// last-used timestamp has reached the configured deadline. Domains without
// owner metadata are not managed by this gateway and must never be affected.
func enforceIdleAutoShutdown(conn *libvirt.Connect, after time.Duration, now time.Time) error {
	if after <= 0 {
		return nil
	}

	domains, err := conn.ListAllDomains(libvirt.CONNECT_LIST_DOMAINS_ACTIVE)
	if err != nil {
		return fmt.Errorf("list active domains for idle auto-shutdown: %w", err)
	}
	defer freeDomains(domains)

	for i := range domains {
		autoShutdownDomainIfIdle(&domains[i], after, now)
	}
	return nil
}

func autoShutdownDomainIfIdle(dom *libvirt.Domain, after time.Duration, now time.Time) {
	name, err := dom.GetName()
	if err != nil {
		log.Printf("idle auto-shutdown domain name: %v", err)
		return
	}
	unlockName := vmNameLocks.Lock(name)
	defer unlockName()

	_, hasOwner, err := domainOwner(dom)
	if err != nil {
		log.Printf("idle auto-shutdown read owner for vm %q: %v", name, err)
		return
	}
	if !hasOwner {
		return
	}

	state, _, err := dom.GetState()
	if err != nil {
		log.Printf("idle auto-shutdown read state for vm %q: %v", name, err)
		return
	}
	if !domainStateEligibleForIdleAutoShutdown(state) {
		return
	}

	lastUsed, hasLastUsed, err := domainLastUsed(dom)
	if err != nil {
		log.Printf("idle auto-shutdown read last-used for vm %q: %v", name, err)
		return
	}
	due, err := idleAutoShutdownDue(lastUsed, hasLastUsed, after, now)
	if err != nil {
		log.Printf("idle auto-shutdown parse last-used for vm %q: %v", name, err)
		return
	}
	if !due {
		return
	}

	if err := dom.Destroy(); err != nil {
		log.Printf("idle auto-shutdown vm %q: %v", name, err)
		return
	}
	if hasLastUsed {
		log.Printf("auto-shutdown vm %q after %s without RDP use", name, after)
		return
	}
	log.Printf("auto-shutdown vm %q because last-used metadata is missing", name)
}

func domainStateEligibleForIdleAutoShutdown(state libvirt.DomainState) bool {
	switch state {
	case libvirt.DOMAIN_RUNNING, libvirt.DOMAIN_BLOCKED, libvirt.DOMAIN_PAUSED, libvirt.DOMAIN_PMSUSPENDED:
		return true
	case libvirt.DOMAIN_NOSTATE, libvirt.DOMAIN_SHUTDOWN, libvirt.DOMAIN_SHUTOFF, libvirt.DOMAIN_CRASHED:
		return false
	default:
		return false
	}
}

func idleAutoShutdownDue(lastUsed string, hasLastUsed bool, after time.Duration, now time.Time) (bool, error) {
	if after <= 0 {
		return false, nil
	}
	lastUsed = strings.TrimSpace(lastUsed)
	if !hasLastUsed || lastUsed == "" {
		return true, nil
	}

	usedAt, err := time.Parse(time.RFC3339, lastUsed)
	if err != nil {
		return false, fmt.Errorf("invalid RFC3339 timestamp %q: %w", lastUsed, err)
	}
	return !now.Before(usedAt.Add(after)), nil
}
