package resolver

import (
	"context"
	"fmt"
	"github.com/miekg/dns"
	"strings"
)

// MaxCNAMEChainLength limits the depth of CNAME chains to prevent amplification attacks.
const MaxCNAMEChainLength = 10

func cname(ctx context.Context, qmsg *dns.Msg, r *Response, exchanger exchanger) error {
	cnames := extractRecords[*dns.CNAME](r.Msg.Answer)

	if len(cnames) > MaxCNAMEChainLength {
		return fmt.Errorf("CNAME chain length %d exceeds maximum allowed %d", len(cnames), MaxCNAMEChainLength)
	}

	targets := make([]string, len(cnames))
	for i, c := range cnames {
		targets[i] = c.Target
	}

	Debug(fmt.Sprintf("resolved [%s]  to cnames: [%s]",
		qmsg.Question[0].Name,
		strings.Join(targets, ", ")),
	)

	for _, c := range cnames {
		target := dns.CanonicalName(c.Target)

		if recordsOfNameAndTypeExist(r.Msg.Answer, target, qmsg.Question[0].Qtype) || recordsOfNameAndTypeExist(r.Msg.Answer, target, dns.TypeCNAME) {
			// Skip over if the answer already contains a record for the target.
			continue
		}

		cnameQMsg := new(dns.Msg)
		cnameQMsg.SetQuestion(target, qmsg.Question[0].Qtype)

		if isSetDO(qmsg) {
			cnameQMsg.SetEdns0(4096, true)
		}

		cnameRMsg := exchanger.exchange(ctx, cnameQMsg)

		if cnameRMsg.HasError() {
			return cnameRMsg.Err
		}
		if cnameRMsg.IsEmpty() {
			return fmt.Errorf("unable to follow cname [%s]", c.Target)
		}

		// Only append Answer records from the CNAME target resolution.
		// Authority (Ns) and Extra sections from different zones may have different
		// trust levels, so we don't mix them into the original response.
		// The finaliseResponse function will deduplicate the answer records.
		r.Msg.Answer = append(r.Msg.Answer, cnameRMsg.Msg.Answer...)

		// Ensure we handle differing DNSSEC results correctly.
		r.Auth = r.Auth.Combine(cnameRMsg.Auth)

		// The overall message is only authoritative if all answers are.
		r.Msg.Authoritative = r.Msg.Authoritative && cnameRMsg.Msg.Authoritative

		// Combine Rcodes with severity awareness: ServFail (2) is more severe than NXDomain (3).
		r.Msg.Rcode = combineRcodes(r.Msg.Rcode, cnameRMsg.Msg.Rcode)
	}

	return nil
}

// combineRcodes returns the more severe of two DNS Rcodes.
// ServFail (2) is treated as more severe than NXDomain (3) despite having a lower numeric value.
func combineRcodes(a, b int) int {
	if a == b {
		return a
	}
	if a == dns.RcodeSuccess {
		return b
	}
	if b == dns.RcodeSuccess {
		return a
	}
	// ServFail takes priority over other error codes.
	if a == dns.RcodeServerFailure || b == dns.RcodeServerFailure {
		return dns.RcodeServerFailure
	}
	// For other codes, use max as a reasonable default.
	return max(a, b)
}
