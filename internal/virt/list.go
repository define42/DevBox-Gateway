package virt

import (
	"context"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"libvirt.org/go/libvirt"
)

type vmInfo struct {
	Name      string
	Owner     string
	State     string
	MemoryMiB int
	VCPU      int
	VolumeGB  int
	IP        string
	PrimaryIP string
	TTYReady  bool
	VNCReady  bool
}

func ListVMs(user string, conn *libvirt.Connect) ([]vmInfo, error) {

	doms, err := conn.ListAllDomains(0)
	if err != nil {
		log.Printf("list domains: %v", err)
		return nil, err
	}
	defer func() {
		for _, d := range doms {
			_ = d.Free()
		}
	}()

	var result []vmInfo
	for _, d := range doms {
		name, err := d.GetName()
		if err != nil {
			log.Printf("domain name: %v", err)
			continue
		}

		owner := ""
		if metadataOwner, hasOwner, err := domainOwner(&d); err != nil {
			log.Printf("domain owner %s: %v", name, err)
		} else if hasOwner {
			owner = metadataOwner
		}
		if user != "" && owner != user {
			continue
		}

		state, _, err := d.GetState()
		if err != nil {
			log.Printf("domain state %s: %v", name, err)
			continue
		}
		mem, vcpu := domainResources(d)
		volGB := domainDiskGB(d)
		ttyReady := domainTTYReady(&d)
		vncReady := domainVNCReady(&d)
		ip := ""
		primaryIP := ""
		if state == libvirt.DOMAIN_RUNNING || state == libvirt.DOMAIN_PAUSED || state == libvirt.DOMAIN_PMSUSPENDED {
			ips := domainIPs(d, name)
			if len(ips) > 0 {
				primaryIP = ips[0]
				ip = strings.Join(ips, ", ")
			}
		}
		result = append(result, vmInfo{
			Name:      name,
			Owner:     owner,
			State:     formatState(state),
			MemoryMiB: mem,
			VCPU:      vcpu,
			VolumeGB:  volGB,
			IP:        ip,
			PrimaryIP: primaryIP,
			TTYReady:  ttyReady,
			VNCReady:  vncReady,
		})
	}
	return result, nil
}

func domainTTYReady(d *libvirt.Domain) bool {
	_, ok, err := domainSerialSocketPath(d)
	if err != nil {
		log.Printf("domain tty readiness: %v", err)
		return false
	}
	return ok
}

func domainVNCReady(d *libvirt.Domain) bool {
	_, ok, err := domainVNCSocketPath(d)
	if err != nil {
		log.Printf("domain vnc readiness: %v", err)
		return false
	}
	return ok
}

func domainResources(d libvirt.Domain) (int, int) {
	info, err := d.GetInfo()
	if err != nil {
		log.Printf("domain info: %v", err)
		return 0, 0
	}
	memMiB := int(info.Memory / 1024)
	return memMiB, int(info.NrVirtCpu)
}

func domainDiskGB(d libvirt.Domain) int {
	info, err := d.GetBlockInfo("vda", 0)
	if err != nil {
		//log.Printf("block info: %v", err)
		return 0
	}
	size := info.Capacity
	if size == 0 {
		size = info.Physical
	}
	if size == 0 {
		size = info.Allocation
	}
	if size == 0 {
		return 0
	}
	return int((size + (1 << 30) - 1) >> 30)
}

func domainIPs(d libvirt.Domain, name string) []string {
	sources := []libvirt.DomainInterfaceAddressesSource{
		libvirt.DOMAIN_INTERFACE_ADDRESSES_SRC_AGENT,
		libvirt.DOMAIN_INTERFACE_ADDRESSES_SRC_LEASE,
		libvirt.DOMAIN_INTERFACE_ADDRESSES_SRC_ARP,
	}
	var ipv4 []string
	seen := make(map[string]struct{})
	var firstErr error

	for _, src := range sources {
		ifaces, err := d.ListAllInterfaceAddresses(src)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		for _, iface := range ifaces {
			for _, addr := range iface.Addrs {
				if addr.Addr == "" {
					continue
				}
				if _, ok := seen[addr.Addr]; ok {
					continue
				}
				seen[addr.Addr] = struct{}{}
				switch addr.Type {
				case libvirt.IP_ADDR_TYPE_IPV4:
					ipv4 = append(ipv4, addr.Addr)
				default:
					ipv4 = append(ipv4, addr.Addr)
				}
			}
		}
	}
	return ipv4
}

func formatState(state libvirt.DomainState) string {
	switch state {
	case libvirt.DOMAIN_RUNNING:
		return "running"
	case libvirt.DOMAIN_PAUSED:
		return "paused"
	case libvirt.DOMAIN_SHUTDOWN, libvirt.DOMAIN_SHUTOFF:
		return "shut off"
	case libvirt.DOMAIN_CRASHED:
		return "crashed"
	case libvirt.DOMAIN_PMSUSPENDED:
		return "suspended"
	default:
		return fmt.Sprintf("unknown (%d)", state)
	}
}

type SingletonWorker struct {
	ticker *time.Ticker
	ctx    context.Context
	cancel context.CancelFunc
	mu     sync.RWMutex
	vms    []vmInfo
}

func (s *SingletonWorker) GetVMs(user string) []vmInfo {
	snapshot := s.snapshotVMs()

	var filteredVMs []vmInfo
	for _, vm := range snapshot {
		if user == "" || vm.Owner == user {
			filteredVMs = append(filteredVMs, vm)
		}
	}
	return filteredVMs
}
func (s *SingletonWorker) GetVMnames() []string {
	snapshot := s.snapshotVMs()

	var names []string
	for _, vm := range snapshot {
		names = append(names, vm.Name)
	}
	return names
}

func (s *SingletonWorker) GetIpOfVm(vmName string) (string, error) {
	for _, vm := range s.snapshotVMs() {
		if vm.Name == vmName {
			return vm.PrimaryIP, nil
		}
	}
	return "", fmt.Errorf("VM %s not found", vmName)
}

func (s *SingletonWorker) snapshotVMs() []vmInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if len(s.vms) == 0 {
		return nil
	}

	snapshot := make([]vmInfo, len(s.vms))
	copy(snapshot, s.vms)
	return snapshot
}

func (s *SingletonWorker) setVMs(vms []vmInfo) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(vms) == 0 {
		s.vms = nil
		return
	}

	next := make([]vmInfo, len(vms))
	copy(next, vms)
	s.vms = next
}

var (
	instance *SingletonWorker
	once     sync.Once
)

func GetInstance() *SingletonWorker {
	once.Do(func() {
		ctx, cancel := context.WithCancel(context.Background())

		instance = &SingletonWorker{
			ticker: time.NewTicker(2 * time.Second),
			ctx:    ctx,
			cancel: cancel,
		}

		go instance.run()
	})

	return instance
}

func (s *SingletonWorker) run() {
	log.Println("singleton worker started")

	var conn *libvirt.Connect
	defer func() {
		if conn != nil {
			_, _ = conn.Close()
		}
	}()

	for {
		select {
		case <-s.ticker.C:
			if conn == nil {
				var err error
				conn, err = libvirt.NewConnect(LibvirtURI())
				if err != nil {
					log.Printf("list vms connect: %v", err)
					continue
				}
			}

			if err := s.doWork(conn); err != nil {
				log.Printf("singleton worker list vms: %v", err)
				_, _ = conn.Close()
				conn = nil
			}
		case <-s.ctx.Done():
			log.Println("singleton worker stopped")
			return
		}
	}
}

func (s *SingletonWorker) doWork(conn *libvirt.Connect) error {
	log.Println("doing work every 2 seconds")
	if conn == nil {
		return fmt.Errorf("libvirt connection is nil")
	}

	vms, err := ListVMs("", conn)
	if err != nil {
		return err
	}
	s.setVMs(vms)
	return nil
}

func (s *SingletonWorker) Stop() {
	s.cancel()
	s.ticker.Stop()
}
