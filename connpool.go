package resolver

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// connPoolSize is the number of persistent UDP connections per nameserver.
// Each connection binds a unique ephemeral port and can handle one
// in-flight query at a time. The pool eliminates per-query socket
// creation overhead and bounds ephemeral port usage.
const connPoolSize = 16

// pooledUDPClient implements dnsClient using a pool of persistent UDP
// connections. Instead of creating a new socket per Exchange call (which
// exhausts ephemeral ports under high concurrency), it reuses a fixed
// set of connections round-robin.
type pooledUDPClient struct {
	timeout time.Duration
	conns   []*pooledConn
	next    uint32
	mu      sync.Mutex
}

type pooledConn struct {
	mu   sync.Mutex
	conn *dns.Conn
	addr string
}

func newPooledUDPClient(timeout time.Duration) *pooledUDPClient {
	return &pooledUDPClient{
		timeout: timeout,
		conns:   make([]*pooledConn, connPoolSize),
	}
}

func (p *pooledUDPClient) ExchangeContext(ctx context.Context, m *dns.Msg, addr string) (*dns.Msg, time.Duration, error) {
	// Round-robin across pool slots.
	p.mu.Lock()
	idx := p.next % uint32(len(p.conns))
	p.next++
	pc := p.conns[idx]
	if pc == nil {
		pc = &pooledConn{addr: addr}
		p.conns[idx] = pc
	}
	p.mu.Unlock()

	pc.mu.Lock()
	defer pc.mu.Unlock()

	// Ensure we have a live connection to this address.
	if pc.conn == nil || pc.addr != addr {
		if pc.conn != nil {
			_ = pc.conn.Close() // discarding stale connection: close error is irrelevant
		}
		conn, err := dialUDP(addr, p.timeout)
		if err != nil {
			return nil, 0, err
		}
		pc.conn = conn
		pc.addr = addr
	}

	// Set deadline from context or timeout.
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(p.timeout)
	}
	_ = pc.conn.SetDeadline(deadline) // network setup: error surfaces on the subsequent Write/Read

	start := time.Now()
	err := pc.conn.WriteMsg(m)
	if err != nil {
		// Connection may be stale — close and retry once.
		_ = pc.conn.Close() // discarding stale connection: close error is irrelevant
		conn, dialErr := dialUDP(addr, p.timeout)
		if dialErr != nil {
			pc.conn = nil
			return nil, time.Since(start), err
		}
		pc.conn = conn
		_ = pc.conn.SetDeadline(deadline) // network setup: error surfaces on the subsequent Write/Read
		if err = pc.conn.WriteMsg(m); err != nil {
			_ = pc.conn.Close() // discarding broken connection: close error is irrelevant
			pc.conn = nil
			return nil, time.Since(start), err
		}
	}

	resp, err := pc.conn.ReadMsg()
	duration := time.Since(start)
	if err != nil {
		// Close broken connection so next call creates a fresh one.
		_ = pc.conn.Close() // discarding broken connection: close error is irrelevant
		pc.conn = nil
		return nil, duration, err
	}

	return resp, duration, nil
}

func dialUDP(addr string, timeout time.Duration) (*dns.Conn, error) {
	d := net.Dialer{Timeout: timeout}
	conn, err := d.Dial("udp", addr)
	if err != nil {
		return nil, err
	}
	return &dns.Conn{Conn: conn}, nil
}
