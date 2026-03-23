package resolver

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

// tcpPoolConns is the number of persistent TCP connections per nameserver.
// Each connection supports pipelining — multiple queries in-flight
// simultaneously, dispatched by DNS transaction ID. With 2000 workers
// and 13 TLD nameservers, each connection sees ~2000/(13*8) ≈ 19
// concurrent queries — well within TCP pipelining capacity.
const tcpPoolConns = 8

// maxPendingPerConn limits concurrent in-flight queries per connection.
// This prevents overloading authoritative servers and ensures queries
// get timely responses. Excess queries wait briefly for a slot.
const maxPendingPerConn = 100

// tcpIdleTimeout is how long an idle TCP connection is kept open.
const tcpIdleTimeout = 60 * time.Second

// tcpDialTimeout is the timeout for establishing a new TCP connection.
const tcpDialTimeout = 2 * time.Second

// tcpPool maintains persistent pipelined TCP connections to a single
// DNS nameserver. Multiple goroutines can issue queries concurrently
// on the same connection — the write mutex is held only for the
// duration of the write (~microseconds), and responses are dispatched
// asynchronously by a dedicated reader goroutine.
type tcpPool struct {
	addr  string
	conns [tcpPoolConns]*pipelinedConn // 8 persistent connections
	mu    sync.Mutex
	next  uint32
}

func newTCPPool(addr string) *tcpPool {
	return &tcpPool{addr: addr}
}

// Exchange sends a DNS query over a pipelined TCP connection and waits
// for the response. The caller's context controls the timeout.
func (p *tcpPool) Exchange(ctx context.Context, m *dns.Msg) (*dns.Msg, time.Duration, error) {
	start := time.Now()

	// Round-robin connection selection.
	idx := atomic.AddUint32(&p.next, 1) % tcpPoolConns

	pc, err := p.getConn(int(idx))
	if err != nil {
		return nil, time.Since(start), err
	}

	resp, err := pc.exchange(ctx, m)
	return resp, time.Since(start), err
}

// getConn returns an existing pipelined connection or creates a new one.
func (p *tcpPool) getConn(idx int) (*pipelinedConn, error) {
	p.mu.Lock()
	pc := p.conns[idx]
	if pc != nil && pc.alive() {
		p.mu.Unlock()
		return pc, nil
	}
	// Need new connection.
	p.mu.Unlock()

	conn, err := net.DialTimeout("tcp", p.addr, tcpDialTimeout)
	if err != nil {
		return nil, fmt.Errorf("tcp dial %s: %w", p.addr, err)
	}

	pc = newPipelinedConn(conn)

	p.mu.Lock()
	// Another goroutine may have created a connection while we dialed.
	if existing := p.conns[idx]; existing != nil && existing.alive() {
		p.mu.Unlock()
		conn.Close()
		return existing, nil
	}
	p.conns[idx] = pc
	p.mu.Unlock()

	return pc, nil
}

// pipelinedConn wraps a single TCP connection with support for
// multiple concurrent in-flight DNS queries. Queries are identified
// by their DNS transaction ID. A dedicated reader goroutine dispatches
// responses to waiting callers.
type pipelinedConn struct {
	conn   net.Conn
	writer *bufio.Writer
	wmu    sync.Mutex // protects writes only
	sem    chan struct{} // limits concurrent in-flight queries

	pending sync.Map    // map[uint16]chan *dns.Msg
	nextID  atomic.Uint32
	closed  atomic.Bool
	done    chan struct{}
}

func newPipelinedConn(conn net.Conn) *pipelinedConn {
	pc := &pipelinedConn{
		conn:   conn,
		writer: bufio.NewWriterSize(conn, 4096),
		sem:    make(chan struct{}, maxPendingPerConn),
		done:   make(chan struct{}),
	}
	go pc.readLoop()
	return pc
}

func (pc *pipelinedConn) alive() bool {
	return !pc.closed.Load()
}

// exchange sends a query and waits for the response matched by DNS ID.
func (pc *pipelinedConn) exchange(ctx context.Context, m *dns.Msg) (*dns.Msg, error) {
	if pc.closed.Load() {
		return nil, fmt.Errorf("connection closed")
	}

	// Limit concurrent in-flight queries per connection to avoid
	// overwhelming the remote server and ensure timely responses.
	select {
	case pc.sem <- struct{}{}:
		defer func() { <-pc.sem }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	// Assign a unique DNS transaction ID.
	id := uint16(pc.nextID.Add(1))
	origID := m.Id
	m.Id = id

	// Register a channel to receive the response.
	ch := make(chan *dns.Msg, 1)
	pc.pending.Store(id, ch)
	defer func() {
		pc.pending.Delete(id)
		m.Id = origID // restore original ID
	}()

	// Write the query (length-prefixed per TCP DNS framing).
	data, err := m.Pack()
	if err != nil {
		return nil, err
	}

	pc.wmu.Lock()
	// Set write deadline from context.
	deadline, ok := ctx.Deadline()
	if ok {
		pc.conn.SetWriteDeadline(deadline)
	} else {
		pc.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	}

	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(data)))
	_, err = pc.writer.Write(lenBuf[:])
	if err == nil {
		_, err = pc.writer.Write(data)
	}
	if err == nil {
		err = pc.writer.Flush()
	}
	pc.wmu.Unlock()

	if err != nil {
		pc.close()
		return nil, fmt.Errorf("tcp write: %w", err)
	}

	// Wait for response or context cancellation.
	select {
	case resp := <-ch:
		if resp == nil {
			return nil, fmt.Errorf("connection closed while waiting")
		}
		resp.Id = origID // restore caller's original ID
		return resp, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-pc.done:
		return nil, fmt.Errorf("connection closed while waiting")
	}
}

// readLoop reads DNS responses from the TCP connection and dispatches
// them to waiting callers by DNS transaction ID.
func (pc *pipelinedConn) readLoop() {
	defer pc.close()

	var lenBuf [2]byte
	for {
		// Read 2-byte length prefix.
		pc.conn.SetReadDeadline(time.Now().Add(tcpIdleTimeout))
		if _, err := io.ReadFull(pc.conn, lenBuf[:]); err != nil {
			return
		}
		msgLen := binary.BigEndian.Uint16(lenBuf[:])
		if msgLen == 0 || msgLen > 65535 {
			return
		}

		// Read the DNS message.
		buf := make([]byte, msgLen)
		if _, err := io.ReadFull(pc.conn, buf); err != nil {
			return
		}

		// Parse and dispatch.
		msg := new(dns.Msg)
		if err := msg.Unpack(buf); err != nil {
			continue // skip malformed message
		}

		if ch, ok := pc.pending.Load(msg.Id); ok {
			ch.(chan *dns.Msg) <- msg
		}
		// If no pending entry, the caller timed out — discard.
	}
}

// close shuts down the connection and wakes all pending callers.
func (pc *pipelinedConn) close() {
	if pc.closed.CompareAndSwap(false, true) {
		pc.conn.Close()
		close(pc.done)
		// Wake all pending callers with nil (they'll get an error).
		pc.pending.Range(func(key, value any) bool {
			ch := value.(chan *dns.Msg)
			select {
			case ch <- nil:
			default:
			}
			return true
		})
	}
}
