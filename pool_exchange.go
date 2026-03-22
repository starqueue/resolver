package resolver

import (
	"context"
	"fmt"
	"github.com/miekg/dns"
)

func (pool *nameserverPool) exchange(ctx context.Context, m *dns.Msg) *Response {
	hasIPv4 := pool.hasIPv4()
	hasIPv6 := pool.hasIPv6()

	if !hasIPv4 && !hasIPv6 {
		if z, ok := ctx.Value(ctxZoneName).(string); ok {
			return newResponseError(fmt.Errorf("%w [%s]", ErrNoPoolConfiguredForZone, z))
		}
		return newResponseError(ErrNoPoolConfiguredForZone)
	}

	//---

	var response *Response

	if hasIPv6 && IPv6Available() {
		if server := pool.getIPv6(); server != nil {
			response = server.exchange(ctx, m)
		}
	} else {
		if server := pool.getIPv4(); server != nil {
			response = server.exchange(ctx, m)
		}
	}

	if response.IsEmpty() || response.HasError() || response.truncated() {
		// If there was an issue, we give it one more try.
		// If we have more than one nameserver, this will try a different one.
		// Prefer the opposite protocol from what was initially tried for diversity.
		if hasIPv6 && IPv6Available() {
			// If we initially tried IPv6, retry with IPv4; otherwise retry with IPv6.
			if hasIPv4 {
				if server := pool.getIPv4(); server != nil {
					response = server.exchange(ctx, m)
				}
			} else {
				if server := pool.getIPv6(); server != nil {
					response = server.exchange(ctx, m)
				}
			}
		} else {
			// Initial attempt was IPv4. Try a different IPv4 server if available,
			// or fall back to IPv6.
			if hasIPv6 {
				if server := pool.getIPv6(); server != nil {
					response = server.exchange(ctx, m)
				}
			} else if hasIPv4 {
				// Only retry same protocol if we have more than one server.
				if pool.countIPv4() > 1 {
					if server := pool.getIPv4(); server != nil {
						response = server.exchange(ctx, m)
					}
				}
			}
		}
	}

	if response.IsEmpty() || response.HasError() {
		errMsg := fmt.Sprintf("all nameservers tried returned an unsucessful response for qname [%s]", m.Question[0].Name)
		if z, ok := ctx.Value(ctxZoneName).(string); ok {
			errMsg = errMsg + fmt.Sprintf(" in zone [%s]", z)
		}

		err := fmt.Errorf("%w: %s", ErrUnableToResolveAnswer, errMsg)

		if response.HasError() {
			// If we already had an error, we'll wrap it with this one.
			response.Err = fmt.Errorf("%w: %w", response.Err, err)
		} else {
			response.Err = err
		}
	}

	return response
}
