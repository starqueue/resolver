package dnssec

import (
	"context"
	"github.com/nsmithuk/resolver/dnssec/doe"
)

func validatePositiveResponse(ctx context.Context, r *result) (status AuthenticationResult, err error) {

	// We extract any delegation DS records in the answer.
	// Previously we only looked in the authority for DS records.
	r.dsRecords = r.answer.extractDSRecords()

	//---

	nsec := doe.NewDenialOfExistenceNSEC(ctx, r.zone.Name(), r.authority.extractNSECRecords())
	nsec3 := doe.NewDenialOfExistenceNSEC3(ctx, r.zone.Name(), r.authority.extractNSEC3Records())

	wildcardSignaturesSeen := false
	wildcardSignaturesVerified := false
	for _, sig := range r.answer {
		if sig.wildcard {
			// If here, it implies that the specific QNAME didn't exist, so we expect a NSEC(3) record proving that.
			// https://datatracker.ietf.org/doc/html/rfc5155#section-8.8

			// Multiple wildcard-expanded RRsets are valid per RFC 4035 - for example,
			// both A and AAAA records could be synthesized from the same wildcard.

			wildcardSignaturesSeen = true

			nsecVerified := false
			nsec3Verified := false

			if !nsec.Empty() {
				nsecVerified = nsec.PerformExpandedWildcardProof(r.msg.Question[0].Name)
				if nsecVerified {
					r.denialOfExistence = NsecWildcard
				}
			}

			if !nsec3.Empty() {
				nsec3Verified = nsec3.PerformExpandedWildcardProof(sig.name, sig.rrsig.Labels)
				if nsec3Verified {
					r.denialOfExistence = Nsec3Wildcard
				}
			}

			if nsecVerified || nsec3Verified {
				wildcardSignaturesVerified = true
			}

		}
	}

	if !wildcardSignaturesSeen || wildcardSignaturesVerified {
		return Secure, nil
	}

	return Bogus, ErrBogusWildcardDoeNotFound
}
