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

	// TCP: persistent pipelined connection pool (preferred).
	tcpPool     *tcpPool
	tcpPoolOnce sync.Once

	// UDP: fallback client for when TCP fails.
	udpOnce   sync.Once
	udpClient dnsClient

	numberOfRequests    atomic.Uint32
	totalResponseTimeNs atomic.Int64
	numberOfTcpRequests atomic.Uint32
	numberOfUdpFallback atomic.Uint32
}

func (ns *nameserver) initTCPPool() {
	addr := net.JoinHostPort(ns.addr, "53")
	ns.tcpPool = getTCPPool(addr)
	ns.tcpPool.preDial()
}

func (ns *nameserver) initUDPClient() {
	factory := ns.defaultDnsClientFactory
	if ns.dnsClientFactory != nil {
		factory = ns.dnsClientFactory
	}
	ns.udpClient = factory("udp")
}

func (*nameserver) defaultDnsClientFactory(protocol string) dnsClient {
	if protocol == "tcp" {
		return &dns.Client{Net: "tcp", Timeout: DefaultTimeoutTCP}
	}
	return newPooledUDPClient(DefaultTimeoutUDP)
}

// exchange queries the nameserver, preferring TCP with UDP fallback.
//
// TCP is preferred because persistent pipelined connections give:
//   - Flow control (authoritative server regulates query rate via TCP window)
//   - Connection reuse (no per-query handshake after first query)
//   - Pipelining (multiple concurrent queries per connection)
//   - Instant failure detection (TCP RST vs 500ms UDP timeout)
//
// UDP fallback handles the rare case where TCP is blocked or refused.
func (ns *nameserver) exchange(ctx context.Context, m *dns.Msg) *Response {
	zoneName := "unknown"
	if z, ok := ctx.Value(ctxZoneName).(string); ok {
		zoneName = z
	}

	if m == nil {
		return newResponseError(fmt.Errorf("%w in zone [%s]", ErrNilMessageSentToExchange, zoneName))
	}

	addr := net.JoinHostPort(ns.addr, "53")

	// Try TCP first (persistent pipelined connection).
	ns.tcpPoolOnce.Do(ns.initTCPPool)

	r := Response{}
	r.Msg, r.Duration, r.Err = ns.tcpPool.Exchange(ctx, m)

	logExchange(ctx, r, m, zoneName, "tcp", ns.hostname, addr)
	ns.updateMetrics("tcp", r.Duration)

	if !r.HasError() && !r.Msg.Truncated {
		ns.numberOfTcpRequests.Add(1)
		return &r
	}

	// TCP failed or truncated — fall back to UDP.
	ns.udpOnce.Do(ns.initUDPClient)
	r.Msg, r.Duration, r.Err = ns.udpClient.ExchangeContext(ctx, m, addr)

	logExchange(ctx, r, m, zoneName, "udp", ns.hostname, addr)
	ns.updateMetrics("udp", r.Duration)
	ns.numberOfUdpFallback.Add(1)

	if !r.HasError() && !r.Msg.Truncated {
		return &r
	}

	return &r
}

func logExchange(ctx context.Context, r Response, m *dns.Msg, zoneName, protocol, hostname, addr string) {
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
		hostname,
		addr,
	))
}

func (ns *nameserver) updateMetrics(protocol string, duration time.Duration) {
	ns.numberOfRequests.Add(1)
	ns.totalResponseTimeNs.Add(duration.Nanoseconds())
}
