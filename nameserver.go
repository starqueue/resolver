package resolver

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

// dnsClientFactory defines a factory function for creating a DNS client.
type dnsClientFactory func(string) dnsClient

type dnsClient interface {
	ExchangeContext(context.Context, *dns.Msg, string) (*dns.Msg, time.Duration, error)
}

type nameserver struct {
	hostname string
	addr     string

	dnsClientFactory dnsClientFactory

	clientOnce sync.Once
	udpClient  dnsClient
	tcpClient  dnsClient

	numberOfRequests    atomic.Uint32
	totalResponseTimeNs atomic.Int64
	numberOfTcpRequests atomic.Uint32
}

func (*nameserver) defaultDnsClientFactory(protocol string) dnsClient {
	if protocol == "tcp" {
		return &dns.Client{Net: "tcp", Timeout: DefaultTimeoutTCP}
	}
	// Use pooled UDP connections to avoid creating a new socket per query.
	return newPooledUDPClient(DefaultTimeoutUDP)
}

func (nameserver *nameserver) initClients() {
	factory := nameserver.defaultDnsClientFactory
	if nameserver.dnsClientFactory != nil {
		factory = nameserver.dnsClientFactory
	}
	nameserver.udpClient = factory("udp")
	nameserver.tcpClient = factory("tcp")
}

func (nameserver *nameserver) getClient(protocol string) dnsClient {
	nameserver.clientOnce.Do(nameserver.initClients)
	if protocol == "udp" {
		return nameserver.udpClient
	}
	return nameserver.tcpClient
}

func (nameserver *nameserver) exchange(ctx context.Context, m *dns.Msg) *Response {
	zoneName := "unknown"
	if z, ok := ctx.Value(ctxZoneName).(string); ok {
		zoneName = z
	}

	if m == nil {
		return newResponseError(fmt.Errorf("%w in zone [%s]", ErrNilMessageSentToExchange, zoneName))
	}

	// Formats correctly for both ipv4 and ipv6.
	addr := net.JoinHostPort(nameserver.addr, "53")

	r := Response{}
	for _, protocol := range []string{"udp", "tcp"} {
		client := nameserver.getClient(protocol)

		r.Msg, r.Duration, r.Err = client.ExchangeContext(ctx, m, addr)

		//---

		shortId := "unknown"
		iteration := uint32(0)
		if trace, _ := ctx.Value(CtxTrace).(*Trace); trace != nil {
			shortId = trace.ShortID()
			iteration = trace.Iteration()
		}
		Query(fmt.Sprintf(
			"%s-%d: %s taken querying [%s] %s in zone [%s] on %s://%s (%s)",
			shortId,
			iteration,
			r.Duration,
			m.Question[0].Name,
			TypeToString(m.Question[0].Qtype),
			zoneName,
			protocol,
			nameserver.hostname,
			addr,
		))

		nameserver.updateMetrics(protocol, r.Duration)

		// If we got an error back, we'll continue to maybe try again.
		if r.HasError() {
			continue
		}

		// Then we can return straight away.
		if !r.Msg.Truncated {
			return &r
		}
	}

	// r here may have an error. It might be truncated. But it's the best we've got.
	return &r
}

func (nameserver *nameserver) updateMetrics(protocol string, duration time.Duration) {
	nameserver.numberOfRequests.Add(1)
	nameserver.totalResponseTimeNs.Add(duration.Nanoseconds())
	if protocol == "tcp" {
		nameserver.numberOfTcpRequests.Add(1)
	}
}
