package resolver

import (
	"fmt"
	"github.com/miekg/dns"
	"sync"
	"sync/atomic"
	"time"
)

var ipv6Check sync.Once

var ipv6Answered atomic.Bool
var ipv6Available atomic.Bool

// IPv6Available return true if IPv6 Internet connectivity is found.
// On first call, triggers the check asynchronously and returns false.
// Subsequent calls return the cached result once the check completes.
// Note: the first few queries after startup may not use IPv6 even if available.
func IPv6Available() bool {
	if ipv6Answered.Load() {
		return ipv6Available.Load()
	}
	// Trigger the check if it hasn't started yet, but don't block.
	go ipv6Check.Do(UpdateIPv6Availability)
	// Return current best-known value (may be false if check is still running).
	return ipv6Available.Load()
}

// UpdateIPv6Availability sense checks if we can get a DNS response from an IPv6 address.
func UpdateIPv6Availability() {
	defer ipv6Answered.Store(true)

	msg := new(dns.Msg)
	msg.SetQuestion(".", dns.TypeNS)

	client := &dns.Client{
		Timeout: 500 * time.Millisecond,
	}

	// Tries:
	// 	k.root-servers.net
	// 	e.root-servers.net.
	// 	a.root-servers.net.
	for _, address := range []string{"2001:7fd::1", "2001:500:a8::e", "2001:503:ba3e::2:30"} {
		ipv6Address := fmt.Sprintf("[%s]:53", address)

		_, _, err := client.Exchange(msg, ipv6Address)
		ipv6Available.Store(err == nil)
		if err == nil {
			return
		}
	}
}
