package resolver

import (
	"github.com/nsmithuk/resolver/dnssec"
	"sync"
	"time"
)

const (
	DefaultMaxAllowedTTL = uint32(60 * 60 * 48) // 48 Hours

	DefaultMaxQueriesPerRequest = uint32(100)

	DefaultDesireNumberOfNameserversPerZone = 3

	DefaultLazyEnrichment = false

	DefaultSuppressBogusResponseSections = true

	DefaultRemoveAuthoritySectionForPositiveAnswers  = true
	DefaultRemoveAdditionalSectionForPositiveAnswers = true

	DefaultTimeoutUDP = 500 * time.Millisecond
	DefaultTimeoutTCP = 2000 * time.Millisecond
)

// ConfigMu protects all package-level configuration variables from concurrent access.
// Callers modifying configuration while queries are in flight must hold ConfigMu.Lock().
// Reading configuration from query paths uses ConfigMu.RLock() internally.
// For best results, set all configuration before creating any Resolver instances.
var ConfigMu sync.RWMutex

var (
	// MaxAllowedTTL define the maximum TTL that we'll cache any record for. This overrides any TTLs set by records
	// we receive. Shorter TTLs on received records will still be respected.
	MaxAllowedTTL = DefaultMaxAllowedTTL

	// MaxQueriesPerRequest gives the maximum number of DNS lookups that can occur from a single request to resolver.Exchange().
	// This will include all requests from the root to the leaf, plus any enrichment needed.
	// Its main task is to prevent infinite loops.
	// Note: DNSKEY and DS lookups performed by the DNSSEC authenticator use separate zone exchanges
	// that go through the pool directly, not through resolver.exchange(), so they do not increment
	// this counter.
	MaxQueriesPerRequest = DefaultMaxQueriesPerRequest

	// DesireNumberOfNameserversPerZone The number of nameservers, with IP addresses, that we ideally know for a zone.
	// If we know less than this, and LazyEnrichment is _not_ enabled, then we'll set-out to gather more addresses.
	DesireNumberOfNameserversPerZone = DefaultDesireNumberOfNameserversPerZone

	// LazyEnrichment - if true, we put less effort into gathering the IP address details of a zone's nameservers.
	// We will still always gather the minimum to complete the query, but no more.
	// Enabling LazyEnrichment can reduce reliability over multiple queries.
	LazyEnrichment = DefaultLazyEnrichment

	// SuppressBogusResponseSections indicates if a response Answer, Authority and Extra sections should
	// be suppressed if a response is Bogus. The default and recommended value is true which
	// aligns the resolver with https://datatracker.ietf.org/doc/html/rfc4035#section-5.5
	SuppressBogusResponseSections = DefaultSuppressBogusResponseSections

	// RemoveAuthoritySectionForPositiveAnswers indicates if the Authority section should be removed when it's deemed
	// that its records have no material impact on the result, e.g. it only contains nameserver records.
	// Note: RFC 2181 Section 6.1 specifies that authority section NS records provide useful delegation
	// information for downstream caching resolvers. Setting this to false may improve interoperability
	// with downstream caching resolvers at the cost of larger response sizes.
	RemoveAuthoritySectionForPositiveAnswers  = DefaultRemoveAuthoritySectionForPositiveAnswers
	RemoveAdditionalSectionForPositiveAnswers = DefaultRemoveAdditionalSectionForPositiveAnswers
)

//---

// Cache Default (disabled) cache function.
var Cache CacheInterface = nil

//---

type Logger func(string)

// Default logging functions just black-hole the input.

var Query Logger = func(s string) {}
var Debug Logger = func(s string) {}
var Info Logger = func(s string) {}
var Warn Logger = func(s string) {}

//---

func init() {
	go IPv6Available()
	dnssec.Info = func(s string) {
		Info(s)
	}
	dnssec.Warn = func(s string) {
		Warn(s)
	}
	dnssec.Debug = func(s string) {
		Debug(s)
	}
}
