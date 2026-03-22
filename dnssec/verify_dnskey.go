package dnssec

import (
	"context"
	"fmt"
	"github.com/miekg/dns"
	"strings"
)

// acceptableAlgorithms lists DNSSEC algorithms considered secure.
// Deprecated or weak algorithms (RSAMD5=1, DSA=3, DSA-NSEC3-SHA1=6) are excluded.
var acceptableAlgorithms = map[uint8]bool{
	dns.RSASHA1:          true,
	dns.RSASHA1NSEC3SHA1: true,
	dns.RSASHA256:        true,
	dns.RSASHA512:        true,
	dns.ECDSAP256SHA256:  true,
	dns.ECDSAP384SHA384:  true,
	dns.ED25519:          true,
	dns.ED448:            true,
}

func verifyDNSKEYs(ctx context.Context, r *result, keys []dns.RR, dsRecordsFromParent []*dns.DS) (AuthenticationResult, error) {

	zoneKeys := extractRecords[*dns.DNSKEY](keys)
	if len(zoneKeys) == 0 {
		return Insecure, ErrKeysNotFound
	}

	//---

	// keySigningKeys are the zone's keys have a matching DS record from the parent zone.
	// These are the keys that are allowed to sign the DNSKEY rrset.
	keySigningKeys := make([]*dns.DNSKEY, 0, len(dsRecordsFromParent))
	for _, d := range dsRecordsFromParent {
		// Skip DS records using deprecated or weak algorithms.
		if !acceptableAlgorithms[d.Algorithm] {
			continue
		}
		for _, k := range zoneKeys {
			if d.Algorithm == k.Algorithm && d.KeyTag == k.KeyTag() && strings.EqualFold(d.Digest, k.ToDS(d.DigestType).Digest) {
				keySigningKeys = append(keySigningKeys, k)
				break
			}
		}
	}

	if len(keySigningKeys) == 0 {
		return Insecure, ErrKeysNotFound
	}

	//---

	keySignatures, err := authenticate(r.zone.Name(), keys, keySigningKeys, answerSection)

	if err != nil {
		return Bogus, fmt.Errorf("%w: %w", ErrBogusResultFound, err)
	}

	r.keys = keySignatures

	if err = keySignatures.Verify(); err != nil {
		return Bogus, fmt.Errorf("%w: %w", ErrBogusResultFound, err)
	}

	return Unknown, nil
}
