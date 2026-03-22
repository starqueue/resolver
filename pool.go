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

	ipv4      []exchanger
	ipv4Next  atomic.Uint32 // Round-robin counter; wraps at MaxUint32, handled by modulo operation.
	ipv4Count atomic.Uint32

	ipv6      []exchanger
	ipv6Next  atomic.Uint32 // Round-robin counter; wraps at MaxUint32, handled by modulo operation.
	ipv6Count atomic.Uint32

	updating sync.RWMutex
	enriched sync.Once

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
	pool.updating.RLock()
	defer pool.updating.RUnlock()

	count := uint32(len(pool.ipv4))
	if count == 0 {
		return nil
	}
	ipv4Next := (pool.ipv4Next.Add(1) - 1) % count
	return pool.ipv4[ipv4Next]
}

func (pool *nameserverPool) getIPv6() exchanger {
	pool.updating.RLock()
	defer pool.updating.RUnlock()

	count := uint32(len(pool.ipv6))
	if count == 0 {
		return nil
	}
	ipv6Next := (pool.ipv6Next.Add(1) - 1) % count
	return pool.ipv6[ipv6Next]
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

	pool.updating.RLock()
	defer pool.updating.RUnlock()

	ipv4Count := len(pool.ipv4)
	ipv6Count := len(pool.ipv6)

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
	if total < DesireNumberOfNameserversPerZone && len(pool.hostsWithoutAddresses) > 0 {
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
			pool.ipv4 = append(pool.ipv4, &nameserver{
				hostname: addr.Header().Name,
				addr:     addr.A.String(),
			})
		}

		for _, addr := range aaaa {
			pool.ipv6 = append(pool.ipv6, &nameserver{
				hostname: addr.Header().Name,
				addr:     addr.AAAA.String(),
			})
		}

	}

	pool.hostsWithoutAddresses = slices.Clip(pool.hostsWithoutAddresses)

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
			pool.ipv4 = append(pool.ipv4, &nameserver{
				hostname: addr.Header().Name,
				addr:     addr.A.String(),
			})
		}

		for _, addr := range aaaa {
			pool.ipv6 = append(pool.ipv6, &nameserver{
				hostname: addr.Header().Name,
				addr:     addr.AAAA.String(),
			})
		}
	}

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
	pool.ipv4Count.Store(uint32(len(pool.ipv4)))
	pool.ipv6Count.Store(uint32(len(pool.ipv6)))
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
