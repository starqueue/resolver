package resolver

import (
	"context"
	"fmt"
	"github.com/miekg/dns"
	"strings"
)

type Resolver struct {
	zones zoneStore
	funcs resolverFunctions
}

// The core, top level, resolving functions. They're defined as variables to aid overriding them for testing.
type resolverFunctions struct {
	resolveLabel         func(ctx context.Context, d *domain, z zone, qmsg *dns.Msg, auth *authenticator) (zone, *Response)
	checkForMissingZones func(ctx context.Context, d *domain, z zone, rmsg *dns.Msg, auth *authenticator) zone
	createZone           func(ctx context.Context, name, parent string, nameservers []*dns.NS, extra []dns.RR, exchanger exchanger) (zone, error)
	finaliseResponse     func(ctx context.Context, auth *authenticator, qmsg *dns.Msg, response *Response) *Response
	processDelegation    func(ctx context.Context, z zone, rmsg *dns.Msg) (zone, *Response)
	cname                func(ctx context.Context, qmsg *dns.Msg, r *Response, exchanger exchanger) error
	getExchanger         func() exchanger
}

// NewResolver creates a new Resolver with the root zone pre-configured.
// It panics if the embedded root zone data cannot be parsed, which should never happen
// in production since the data is statically embedded. If you need error handling during
// initialization, use NewResolverWithError() instead.
func NewResolver() *Resolver {
	r, err := NewResolverWithError()
	if err != nil {
		panic(err)
	}
	return r
}

// NewResolverWithError creates a new Resolver, returning an error instead of panicking
// if initialization fails. This is preferred in contexts where graceful error handling
// is needed.
func NewResolverWithError() (*Resolver, error) {
	pool, err := buildRootServerPool()
	if err != nil {
		return nil, fmt.Errorf("failed to build root server pool: %w", err)
	}

	z := new(zones)
	z.add(&zoneImpl{
		zoneName: ".",
		pool:     pool,
	})

	resolver := &Resolver{
		zones: z,
	}

	// When not testing, we point to the concrete instances of the functions.
	resolver.funcs = resolverFunctions{
		resolveLabel:         resolver.resolveLabel,
		checkForMissingZones: resolver.checkForMissingZones,
		createZone:           createZone,
		finaliseResponse:     resolver.finaliseResponse,
		processDelegation:    resolver.processDelegation,
		cname:                cname,
		getExchanger:         resolver.getExchanger,
	}

	return resolver, nil
}

func (resolver *Resolver) getExchanger() exchanger {
	return resolver
}

// Close is a no-op placeholder for future graceful shutdown support.
// Currently, goroutines spawned for DNSKEY pre-fetching and enrichment are not
// tracked at the resolver level. Callers should use context cancellation to
// signal in-flight queries to stop. A future implementation could add lifecycle
// management for background goroutines.
func (resolver *Resolver) Close() {
	// No-op: placeholder for future shutdown logic.
}

// CountZones metrics gathering.
func (resolver *Resolver) CountZones() int {
	return resolver.zones.count()
}

//-----------------------------------------------------------------------------

func buildRootServerPool() (*nameserverPool, error) {
	zp := dns.NewZoneParser(strings.NewReader(rootZone), ".", "local")

	pool := &nameserverPool{hostsWithoutAddresses: make([]string, 0)}

	var ipv4 []exchanger
	var ipv6 []exchanger

	for rr, ok := zp.Next(); ok; rr, ok = zp.Next() {
		switch rr := rr.(type) {
		case *dns.A:
			ipv4 = append(ipv4, &nameserver{
				hostname: canonicalName(rr.Header().Name),
				addr:     rr.A.String(),
			})
		case *dns.AAAA:
			ipv6 = append(ipv6, &nameserver{
				hostname: canonicalName(rr.Header().Name),
				addr:     rr.AAAA.String(),
			})
		default:
			// Continue
		}
	}

	if err := zp.Err(); err != nil {
		return nil, err
	}

	pool.ipv4Servers.Store(ipv4)
	pool.ipv6Servers.Store(ipv6)
	pool.updateIPCount()

	return pool, nil
}
