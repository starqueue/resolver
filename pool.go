package resolver

import (
	"github.com/miekg/dns"
	"slices"
	"sync"
	"sync/atomic"
	"time"
)

type NameserverPoolStatus uint8

const (
	PoolEmpty NameserverPoolStatus = iota
	PoolExpired
	PoolHasHostnamesButNoIpAddresses
	PrimedButNeedsEnhancing
	PoolPrimed
)

type nameserverPool struct {
	hostsWithoutAddresses []string

	// ipv4Servers and ipv6Servers store []exchanger atomically.
	// Readers load the slice without locking. Writers (enrich) replace
	// the entire slice under the updating mutex.
	ipv4Servers atomic.Value // stores []exchanger
	ipv4Next    atomic.Uint32
	ipv4Count   atomic.Uint32

	ipv6Servers atomic.Value // stores []exchanger
	ipv6Next    atomic.Uint32
	ipv6Count   atomic.Uint32

	updating sync.Mutex // protects enrich writes only

	expires atomic.Int64
}

func (pool *nameserverPool) hasIPv4() bool {
	return pool.countIPv4() > 0
}

func (pool *nameserverPool) hasIPv6() bool {
	return pool.countIPv6() > 0
}

func (pool *nameserverPool) countIPv4() uint32 {
	return pool.ipv4Count.Load()
}

func (pool *nameserverPool) countIPv6() uint32 {
	return pool.ipv6Count.Load()
}

func (pool *nameserverPool) getIPv4() exchanger {
	servers, _ := pool.ipv4Servers.Load().([]exchanger)
	count := uint32(len(servers))
	if count == 0 {
		return nil
	}
	idx := (pool.ipv4Next.Add(1) - 1) % count
	return servers[idx]
}

func (pool *nameserverPool) getIPv6() exchanger {
	servers, _ := pool.ipv6Servers.Load().([]exchanger)
	count := uint32(len(servers))
	if count == 0 {
		return nil
	}
	idx := (pool.ipv6Next.Add(1) - 1) % count
	return servers[idx]
}

//---

func (pool *nameserverPool) expired() bool {
	expires := pool.expires.Load()
	return expires > 0 && expires < time.Now().Unix()
}

func (pool *nameserverPool) status() NameserverPoolStatus {
	if pool.expired() {
		return PoolExpired
	}

	ipv4Count := int(pool.ipv4Count.Load())
	ipv6Count := int(pool.ipv6Count.Load())

	if ipv4Count == 0 && ipv6Count == 0 && len(pool.hostsWithoutAddresses) == 0 {
		return PoolEmpty
	}

	total := ipv4Count
	if IPv6Available() {
		total = total + ipv6Count
	}

	if total == 0 {
		return PoolHasHostnamesButNoIpAddresses
	}

	// If there are unknown addresses, and we have less than x IPs, then we want to enrich.
	pool.updating.Lock()
	hasUnresolved := len(pool.hostsWithoutAddresses) > 0
	pool.updating.Unlock()
	if total < DesireNumberOfNameserversPerZone && hasUnresolved {
		return PrimedButNeedsEnhancing
	}

	return PoolPrimed
}

func newNameserverPool(nameservers []*dns.NS, extra []dns.RR) *nameserverPool {
	pool := &nameserverPool{}

	var ttl = MaxAllowedTTL
	pool.hostsWithoutAddresses = make([]string, 0, len(nameservers))

	// Build a set of valid NS hostnames to validate glue records against.
	// Only glue records matching declared NS hostnames are trusted.
	validHostnames := make(map[string]bool, len(nameservers))
	for _, rr := range nameservers {
		validHostnames[canonicalName(rr.Ns)] = true
	}

	// Filter extra records to only include those matching NS hostnames.
	validExtra := make([]dns.RR, 0, len(extra))
	for _, rr := range extra {
		if validHostnames[canonicalName(rr.Header().Name)] {
			validExtra = append(validExtra, rr)
		}
	}

	var ipv4 []exchanger
	var ipv6 []exchanger

	for _, rr := range nameservers {
		hostname := canonicalName(rr.Ns)

		ttl = min(rr.Header().Ttl, ttl)

		//---

		a, aaaa, minTtlSeen := findAddressesForHostname(hostname, validExtra)

		if len(a) == 0 && len(aaaa) == 0 {
			pool.hostsWithoutAddresses = append(pool.hostsWithoutAddresses, hostname)
			continue
		}

		//---

		ttl = min(minTtlSeen, ttl)

		for _, addr := range a {
			ipv4 = append(ipv4, &nameserver{
				hostname: addr.Header().Name,
				addr:     addr.A.String(),
			})
		}

		for _, addr := range aaaa {
			ipv6 = append(ipv6, &nameserver{
				hostname: addr.Header().Name,
				addr:     addr.AAAA.String(),
			})
		}

	}

	pool.hostsWithoutAddresses = slices.Clip(pool.hostsWithoutAddresses)
	pool.ipv4Servers.Store(ipv4)
	pool.ipv6Servers.Store(ipv6)

	// Enforce minimum zone TTL so hot zones stay cached longer.
	if ttl < MinZoneTTL {
		ttl = MinZoneTTL
	}
	expires := time.Now().Add(time.Duration(ttl) * time.Second)
	pool.expires.Store(expires.Unix())

	pool.updateIPCount()

	return pool
}

func (pool *nameserverPool) enrich(records []dns.RR) {
	if len(records) == 0 {
		return
	}

	pool.updating.Lock()
	defer pool.updating.Unlock()

	// Load current slices to append to.
	ipv4, _ := pool.ipv4Servers.Load().([]exchanger)
	ipv6, _ := pool.ipv6Servers.Load().([]exchanger)
	// Copy so we don't mutate the slice readers may hold.
	newIPv4 := make([]exchanger, len(ipv4))
	copy(newIPv4, ipv4)
	newIPv6 := make([]exchanger, len(ipv6))
	copy(newIPv6, ipv6)

	var ttl = MaxAllowedTTL
	hostnamesStillWithoutAddresses := make([]string, 0, len(pool.hostsWithoutAddresses))

	for _, hostname := range pool.hostsWithoutAddresses {

		a, aaaa, minTtlSeen := findAddressesForHostname(hostname, records)

		if len(a) == 0 && len(aaaa) == 0 {
			hostnamesStillWithoutAddresses = append(hostnamesStillWithoutAddresses, hostname)
			continue
		}

		//---

		ttl = min(minTtlSeen, ttl)

		for _, addr := range a {
			newIPv4 = append(newIPv4, &nameserver{
				hostname: addr.Header().Name,
				addr:     addr.A.String(),
			})
		}

		for _, addr := range aaaa {
			newIPv6 = append(newIPv6, &nameserver{
				hostname: addr.Header().Name,
				addr:     addr.AAAA.String(),
			})
		}
	}

	// Atomically replace slices so readers never see partial updates.
	pool.ipv4Servers.Store(newIPv4)
	pool.ipv6Servers.Store(newIPv6)

	// Only shorten the expiry time, never extend it beyond the original NS TTL.
	if pool.expires.Load() > 0 {
		newExpiry := time.Now().Add(time.Duration(ttl) * time.Second).Unix()
		if currentExpiry := pool.expires.Load(); newExpiry < currentExpiry {
			pool.expires.Store(newExpiry)
		}
	}

	pool.hostsWithoutAddresses = slices.Clip(hostnamesStillWithoutAddresses)

	pool.updateIPCount()
}

func (pool *nameserverPool) updateIPCount() {
	ipv4, _ := pool.ipv4Servers.Load().([]exchanger)
	ipv6, _ := pool.ipv6Servers.Load().([]exchanger)
	pool.ipv4Count.Store(uint32(len(ipv4)))
	pool.ipv6Count.Store(uint32(len(ipv6)))
}

func findAddressesForHostname(hostname string, records []dns.RR) ([]*dns.A, []*dns.AAAA, uint32) {
	a := make([]*dns.A, 0, len(records))
	aaaa := make([]*dns.AAAA, 0, len(records))

	var ttl = MaxAllowedTTL

	for _, rr := range records {
		if canonicalName(rr.Header().Name) != hostname {
			continue
		}
		switch addr := rr.(type) {
		case *dns.A:
			a = append(a, addr)
			ttl = min(rr.Header().Ttl, ttl)
		case *dns.AAAA:
			aaaa = append(aaaa, addr)
			ttl = min(rr.Header().Ttl, ttl)
		}
	}

	return a, aaaa, ttl
}
