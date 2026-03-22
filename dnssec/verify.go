package dnssec

import (
	"context"
	"github.com/miekg/dns"
)

func (v verifier) verify(ctx context.Context, zone Zone, msg *dns.Msg, dsRecordsFromParent []*dns.DS) (AuthenticationResult, *result, error) {
	r := &result{
		name: zone.Name(),
		zone: zone,
		msg:  msg,
	}

	if len(dsRecordsFromParent) == 0 {
		// When no DS records are provided from the parent zone, the child zone is treated as Insecure.
		// This is the expected behavior for unsigned delegations where the parent zone has no DS records
		// for this child. Protection against DS-stripping downgrade attacks relies on the parent zone's
		// DNSSEC validation proving the absence of DS records via NSEC/NSEC3 denial-of-existence proofs.
		// The authenticator's result chain validation (in result.go) checks that transitions from Secure
		// to Insecure are backed by proper denial-of-existence records, preventing silent downgrades.
		return Insecure, r, nil
	}

	// Verify DNSKEYS
	// Verify all other RRSETs
	// Delegating Answer check
	// Positive Answer check
	// Negative Answer check

	var status AuthenticationResult

	keys, err := zone.GetDNSKEYRecords()
	if err != nil {
		return Bogus, r, err
	}

	status, err = v.verifyDNSKEYs(ctx, r, keys, dsRecordsFromParent)
	if status != Unknown || err != nil {
		return status, r, err
	}

	status, err = v.verifyRRSETs(ctx, r, extractRecords[*dns.DNSKEY](keys))
	if status != Unknown || err != nil {
		return status, r, err
	}

	// We ignore the message header when determining the type of response, as the header is not signed.

	soaFoundInAuthority := recordsOfTypeExist(r.msg.Ns, dns.TypeSOA)

	// A Delegating Response has no Answers, no SOA, and at least one NS record in the Authority section.
	if !soaFoundInAuthority && len(r.msg.Answer) == 0 && recordsOfTypeExist(r.msg.Ns, dns.TypeNS) {
		status, err = v.validateDelegatingResponse(ctx, r)
		return status, r, err
	}

	// A positive response has at least one answer, and SOA in the Authority section.
	if !soaFoundInAuthority && len(r.msg.Answer) > 0 {
		status, err = v.validatePositiveResponse(ctx, r)
		return status, r, err
	}

	// A negative response has a SOA in the Authority section.
	if soaFoundInAuthority {
		status, err = v.validateNegativeResponse(ctx, r)
		return status, r, err
	}

	// We should never get here. If we do, the response was likely malformed. We'll fail-safe to Bogus.
	return Bogus, r, ErrFailsafeResponse
}
