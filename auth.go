package resolver

import (
	"context"
	"errors"
	"fmt"
	"github.com/miekg/dns"
	"github.com/nsmithuk/resolver/dnssec"
	"sync"
	"sync/atomic"
)

type authenticator struct {
	ctx  context.Context
	auth *dnssec.Authenticator

	errors []error

	closeOnce  sync.Once
	queue      chan authenticatorInput
	finished   atomic.Bool
	processing *sync.WaitGroup
}

type authenticatorInput struct {
	z   zone
	msg *dns.Msg
}

func newAuthenticator(ctx context.Context, question dns.Question) *authenticator {
	a := dnssec.NewAuth(ctx, question)
	// Buffer size based on expected zone depth. Each zone may produce a DS
	// lookup response + a DNSKEY prefetch + the main exchange response, so
	// size at 3× label count to prevent sender blocking under DNSSEC load.
	bufSize := dns.CountLabel(question.Name) * 3
	if bufSize < 16 {
		bufSize = 16
	}
	auth := &authenticator{
		ctx:        ctx,
		auth:       a,
		errors:     make([]error, 0),
		queue:      make(chan authenticatorInput, bufSize),
		processing: &sync.WaitGroup{},
	}
	go auth.start()
	return auth
}

func (a *authenticator) close() {
	a.closeOnce.Do(func() {
		a.finished.Store(true)
		a.processing.Wait()
		close(a.queue)
	})
}

func (a *authenticator) addDelegationSignerLink(z zone, qname string) {
	a.processing.Add(1)
	if a.finished.Load() {
		a.processing.Done()
		return
	}
	go func() {
		defer a.processing.Done()

		// Use cached DS lookup to avoid redundant network round-trips.
		// The zone caches DS responses so concurrent queries for the
		// same zone chain don't each make separate DS queries.
		zi, ok := z.(*zoneImpl)
		var dsMsg *dns.Msg
		var dsErr error
		if ok {
			dsMsg, dsErr = zi.cachedDSLookup(a.ctx, qname)
		} else {
			// Fallback for non-zoneImpl (e.g. mocks in tests).
			msg := new(dns.Msg)
			msg.SetQuestion(dns.Fqdn(qname), dns.TypeDS)
			msg.SetEdns0(4096, true)
			msg.RecursionDesired = false
			response := z.exchange(a.ctx, msg)
			if !response.IsEmpty() && !response.HasError() {
				dsMsg = response.Msg
			}
		}

		if dsErr != nil || dsMsg == nil {
			return
		}

		// Check if DS records are present. If absent, this delegation
		// is Insecure — no need to fetch DNSKEY or validate signatures
		// for this zone or its children.
		hasDS := false
		for _, rr := range dsMsg.Answer {
			if rr.Header().Rrtype == dns.TypeDS {
				hasDS = true
				break
			}
		}

		if hasDS {
			// DS records exist — pre-fetch DNSKEY for signature verification.
			a.processing.Add(1)
			go func() {
				defer a.processing.Done()
				_, _ = z.dnskeys(a.ctx) // prefetch: error surfaces when the authenticator later requires the keys
			}()
		}
		// If no DS records, skip DNSKEY fetch — the zone is Insecure
		// and no cryptographic verification is needed.

		a.processing.Add(1)
		a.queue <- authenticatorInput{z, dsMsg}
	}()
}

func (a *authenticator) addResponse(z zone, msg *dns.Msg) error {
	a.processing.Add(1)
	if a.finished.Load() {
		a.processing.Done()
		return nil
	}
	a.queue <- authenticatorInput{z, msg}
	return nil
}

func (a *authenticator) start() {
	for in := range a.queue {
		err := a.auth.AddResponse(&authZoneWrapper{ctx: a.ctx, zone: in.z}, in.msg)
		if err != nil {
			// `Errors` is only accessible from this thread when processing is !Done().
			a.errors = append(a.errors, err)
		}
		a.processing.Done()
	}
}

func (a *authenticator) result() (dnssec.AuthenticationResult, dnssec.DenialOfExistenceState, error) {
	// close() handles setting finished=true, waiting for processing, and closing the channel.
	a.close()

	// `Errors` is only accessible from this thread once we've finished Wait().
	if len(a.errors) > 0 {
		if len(a.errors) == 1 {
			return 0, 0, a.errors[0]
		}
		err := errors.New("multiple errors found: ")
		for _, e := range a.errors {
			err = fmt.Errorf("%w: %w", err, e)
		}
		return 0, 0, err
	}

	return a.auth.Result()
}

func (a *authenticator) resultTTLAnswer(rtype uint16) (uint32, bool) {
	return a.auth.ResultTTLAnswer(rtype)
}

func (a *authenticator) resultTTLAuthority(rtype uint16) (uint32, bool) {
	return a.auth.ResultTTLAuthority(rtype)
}

// authZoneWrapper wraps our zone such that is supports the dnssec.Zone interface.
// Note that the dnssec package only needs querying support against this zone's nameservers.
// i.e. We do not need to try these queries recursively. If the nameservers for this zone do not return
// an authoritative answer themselves, we can assume that's an error.
type authZoneWrapper struct {
	ctx  context.Context
	zone zone
}

// Name returns the zone's apex domain name.
func (wrapper *authZoneWrapper) Name() string {
	return wrapper.zone.name()
}

// GetDNSKEYRecords Looks up the DNSKEY records for the given QName, in the zone.
func (wrapper *authZoneWrapper) GetDNSKEYRecords() ([]dns.RR, error) {
	return wrapper.zone.dnskeys(wrapper.ctx)
}
