package resolver

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// enrichSem limits concurrent pool enrichment goroutines to prevent
// unbounded goroutine/socket creation when many zones need NS resolution.
var enrichSem = make(chan struct{}, 20)

func createZone(ctx context.Context, name, parent string, nameservers []*dns.NS, extra []dns.RR, exchanger exchanger) (zone, error) {
	name = dns.CanonicalName(name)
	parent = dns.CanonicalName(parent)

	if name == parent || !dns.IsSubDomain(parent, name) {
		return nil, fmt.Errorf("%w: the new zone name [%s] must be a subdomain of the parent [%s]", ErrFailedCreatingZoneAndPool, name, parent)
	}

	pool := newNameserverPool(nameservers, extra)

	switch pool.status() {
	case PrimedButNeedsEnhancing:
		if !LazyEnrichment {
			go func() {
				select {
				case enrichSem <- struct{}{}:
					defer func() { <-enrichSem }()
					_ = enrichPool(ctx, name, pool, exchanger) // background lazy enrichment: error surfaces on next status() check
				default:
					// Too many concurrent enrichments — skip.
				}
			}()
		}
	case PoolPrimed:
		// Ready to use.
	case PoolHasHostnamesButNoIpAddresses:
		// Block until enrichment succeeds. The query waits here but gets
		// a working zone. The parallel enrichPool resolves hostnames
		// concurrently so this is typically ~200ms instead of 1.2s.
		err := enrichPool(ctx, name, pool, exchanger)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("%w for [%s]: the nameserver pool is empty and we have no hostnames to enrich", ErrFailedCreatingZoneAndPool, name)
	}

	z := &zoneImpl{
		zoneName:   name,
		parentName: parent,
		pool:       pool,
	}

	Debug(fmt.Sprintf("new zone created [%s]", name))

	return z, nil
}

// enrichPool resolves NS hostnames to IP addresses to populate the
// nameserver pool. All hostname/type combinations are queried in
// parallel for maximum speed.
func enrichPool(ctx context.Context, zoneName string, pool *nameserverPool, exchanger exchanger) error {
	if len(pool.hostsWithoutAddresses) == 0 {
		return fmt.Errorf("%w [%s]: the nameserver pool is empty so we have no hostnames to enrich", ErrFailedEnrichingPool, zoneName)
	}

	hosts := pool.hostsWithoutAddresses
	if len(hosts) > DesireNumberOfNameserversPerZone {
		hosts = hosts[:DesireNumberOfNameserversPerZone]
	}

	types := []uint16{dns.TypeA}
	if IPv6Available() {
		types = append(types, dns.TypeAAAA)
	}

	enrichCtx, enrichCancel := context.WithTimeout(ctx, 3*time.Second)
	defer enrichCancel()

	// Fire all hostname × type queries in parallel.
	// Previously these were sequential — 3 hosts × 2 types = 6 queries
	// at ~200ms each = 1.2s. In parallel: ~200ms total.
	done := make(chan bool, 1)
	var wg sync.WaitGroup

	for _, t := range types {
		for _, domain := range hosts {
			t, domain := t, domain
			wg.Add(1)
			go func() {
				defer wg.Done()
				if enrichCtx.Err() != nil {
					return
				}

				qmsg := new(dns.Msg)
				qmsg.SetQuestion(dns.Fqdn(domain), t)

				response := exchanger.exchange(enrichCtx, qmsg)
				if !response.HasError() && !response.IsEmpty() && len(response.Msg.Answer) > 0 {
					pool.enrich(response.Msg.Answer)
					select {
					case done <- true:
					default:
					}
				}
			}()
		}
	}

	// Wait for first success or all to complete.
	select {
	case <-done:
		// At least one enrichment succeeded. Let remaining finish in background.
		go func() { wg.Wait() }()
	case <-enrichCtx.Done():
		return fmt.Errorf("%w [%s]: enrichment timeout", ErrFailedEnrichingPool, zoneName)
	}

	switch pool.status() {
	case PoolPrimed, PrimedButNeedsEnhancing:
		Debug(fmt.Sprintf("zone pool enriched for [%s]", zoneName))
		return nil
	default:
		return fmt.Errorf("%w [%s]: the nameserver pool still not primed after enrichment", ErrFailedEnrichingPool, zoneName)
	}
}
