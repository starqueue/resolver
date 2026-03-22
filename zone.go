package resolver

import (
	"context"
	"fmt"
	"github.com/miekg/dns"
	"sync"
	"sync/atomic"
	"time"
)

//---------------------------------------------------------------------------------

type zone interface {
	exchanger
	name() string
	parent() string
	expired() bool
	clone(name, parent string) zone
	soa(ctx context.Context, name string) (*dns.SOA, error)
	dnskeys(ctx context.Context) ([]dns.RR, error)
}

type zoneImpl struct {
	zoneName   string
	parentName string

	pool  expiringExchanger
	calls atomic.Uint64

	dnskeyRecords atomic.Value // stores []dns.RR
	dnskeyExpiry  atomic.Int64 // unix timestamp
	dnskeyLock    sync.Mutex   // only held during fetch, not reads
}

func (z *zoneImpl) name() string {
	return z.zoneName
}

func (z *zoneImpl) parent() string {
	return z.parentName
}

func (z *zoneImpl) expired() bool {
	return z.pool.expired()
}

func (z *zoneImpl) clone(name, parent string) zone {
	if canonicalName(name) == canonicalName(parent) || !dns.IsSubDomain(parent, name) {
		Debug(fmt.Sprintf("child %s is not actually a child of parent: %s", name, parent))
		// Return nil instead of panicking, since this can be triggered by adversarial DNS data.
		// Callers should check for nil return.
		return nil
	}
	return &zoneImpl{
		zoneName:   canonicalName(name),
		parentName: canonicalName(parent),
		pool:       z.pool,
	}
}

func (z *zoneImpl) exchange(ctx context.Context, m *dns.Msg) *Response {

	z.calls.Add(1)

	if Cache != nil {
		if msg, err := Cache.Get(z.zoneName, m.Question[0]); err != nil {
			Warn(fmt.Errorf("error trying to perform a cache lookup for zone [%s]: %w", z.zoneName, err).Error())
		} else if msg != nil {
			trace, _ := ctx.Value(CtxTrace).(*Trace)
			shortId := "unknown"
			iteration := uint32(0)
			if trace != nil {
				shortId = trace.ShortID()
				iteration = trace.Iteration()
			}
			Query(fmt.Sprintf(
				"%s-%d: response for [%s] %s in zone [%s] found in cache",
				shortId,
				iteration,
				m.Question[0].Name,
				TypeToString(m.Question[0].Qtype),
				z.zoneName,
			))
			return &Response{Msg: msg.Copy()}
		}
	}

	//---

	if z.pool == nil {
		return newResponseError(fmt.Errorf("%w [%s]", ErrNoPoolConfiguredForZone, z.zoneName))
	}

	ctx = context.WithValue(ctx, ctxZoneName, z.zoneName)
	response := z.pool.exchange(ctx, m)

	//---

	if Cache != nil && !response.IsEmpty() && !response.HasError() {
		// Inline cache update instead of spawning a goroutine per exchange.
		// Under high concurrency, unbounded goroutine creation (30-100K/sec)
		// overwhelms the scheduler.
		msgCopy := response.Msg.Copy()
		msgCopy.Extra = removeRecordsOfType(msgCopy.Extra, dns.TypeOPT)
		if err := Cache.Update(z.zoneName, m.Question[0], msgCopy); err != nil {
			Warn(fmt.Errorf("error trying to perform a cache update for zone [%s]: %w", z.zoneName, err).Error())
		}
	}

	//---

	return response
}

func (z *zoneImpl) soa(ctx context.Context, name string) (*dns.SOA, error) {
	soaMsg := new(dns.Msg)
	soaMsg.SetQuestion(dns.Fqdn(name), dns.TypeSOA)
	soaMsg.RecursionDesired = false
	response := z.exchange(ctx, soaMsg)

	if response.IsEmpty() {
		return nil, ErrEmptyResponse
	}
	if response.HasError() {
		return nil, response.Err
	}
	if !recordsOfTypeExist(response.Msg.Answer, dns.TypeSOA) {
		return nil, nil
	}

	soas := extractRecords[*dns.SOA](response.Msg.Answer)
	if len(soas) != 1 {
		return nil, fmt.Errorf("we expect only a single SOA for a given name / zone. we got %d", len(soas))
	}

	return soas[0], nil
}

func (z *zoneImpl) dnskeys(ctx context.Context) ([]dns.RR, error) {
	// Fast path: check expiry atomically without locking.
	if exp := z.dnskeyExpiry.Load(); exp > 0 && exp > time.Now().Unix() {
		if records, ok := z.dnskeyRecords.Load().([]dns.RR); ok {
			return records, nil
		}
	}

	// Slow path: fetch under lock, but only one goroutine fetches at a time.
	z.dnskeyLock.Lock()
	defer z.dnskeyLock.Unlock()

	// Re-check after acquiring lock — another goroutine may have fetched while we waited.
	if exp := z.dnskeyExpiry.Load(); exp > 0 && exp > time.Now().Unix() {
		if records, ok := z.dnskeyRecords.Load().([]dns.RR); ok {
			return records, nil
		}
	}

	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(z.zoneName), dns.TypeDNSKEY)
	msg.SetEdns0(4096, true)
	msg.RecursionDesired = false
	response := z.exchange(ctx, msg)
	if response.HasError() {
		return nil, fmt.Errorf("%w for %s: %w", ErrFailedToGetDNSKEYs, z.zoneName, response.Err)
	}
	if response.IsEmpty() {
		return nil, fmt.Errorf("%w for %s: response is empty", ErrFailedToGetDNSKEYs, z.zoneName)
	}

	if len(response.Msg.Answer) == 0 {
		// If we got no answer, we'll put a short cache on that, rather than the MaxAllowedTTL.
		z.dnskeyRecords.Store([]dns.RR(nil))
		z.dnskeyExpiry.Store(time.Now().Add(time.Second * 60).Unix())
		return nil, nil
	}

	records := make([]dns.RR, len(response.Msg.Answer))
	copy(records, response.Msg.Answer)

	var ttl = MaxAllowedTTL
	for _, rr := range records {
		ttl = min(ttl, rr.Header().Ttl)
	}

	// Store records first, then expiry — readers check expiry first,
	// so they'll always see valid records when expiry is set.
	z.dnskeyRecords.Store(records)
	z.dnskeyExpiry.Store(time.Now().Add(time.Duration(ttl) * time.Second).Unix())

	return records, nil
}
