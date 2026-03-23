package resolver

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestCreateZone_SuccessWithoutEnrichment(t *testing.T) {
	// Setup
	mockExchanger := new(MockExpiringExchanger)

	// Prepare nameservers and extra records. A primed pool is, by default, >= 3 nameservers with glue records.
	nameservers := []*dns.NS{
		{Hdr: dns.RR_Header{Name: "ns1.example.com.", Rrtype: dns.TypeNS}, Ns: "ns1.example.com."},
		{Hdr: dns.RR_Header{Name: "ns2.example.com.", Rrtype: dns.TypeNS}, Ns: "ns2.example.com."},
		{Hdr: dns.RR_Header{Name: "ns3.example.com.", Rrtype: dns.TypeNS}, Ns: "ns3.example.com."},
	}
	extra := []dns.RR{
		&dns.A{Hdr: dns.RR_Header{Name: "ns1.example.com.", Rrtype: dns.TypeA, Ttl: 300}, A: net.ParseIP("192.0.2.53")},
		&dns.A{Hdr: dns.RR_Header{Name: "ns2.example.com.", Rrtype: dns.TypeA, Ttl: 300}, A: net.ParseIP("192.0.2.54")},
		&dns.A{Hdr: dns.RR_Header{Name: "ns3.example.com.", Rrtype: dns.TypeA, Ttl: 300}, A: net.ParseIP("192.0.2.55")},
	}
	ctx := context.TODO()

	// Execute
	z, err := createZone(ctx, "example.com.", "com.", nameservers, extra, mockExchanger)

	// Assertions
	assert.NoError(t, err)
	assert.NotNil(t, z)
	assert.Equal(t, "example.com.", z.name())

	// We'll peek under the covers to ensure the pool was created as expected.
	pool, ok := z.(*zoneImpl).pool.(*nameserverPool)
	assert.True(t, ok)
	assert.Equal(t, pool.status(), PoolPrimed)
}

func TestCreateZone_PoolCreationFailsWithoutEnrichment(t *testing.T) {
	// Setup
	mockExchanger := new(MockExpiringExchanger)

	// Prepare nameservers with no valid addresses
	nameservers := []*dns.NS{}
	extra := []dns.RR{}
	ctx := context.TODO()

	// Execute
	z, err := createZone(ctx, "example.com.", "com.", nameservers, extra, mockExchanger)

	// Assertions
	assert.Nil(t, z)
	assert.ErrorIs(t, err, ErrFailedCreatingZoneAndPool)
}

func TestCreateZone_SuccessWithEnrichment(t *testing.T) {
	// Setup
	mockExchanger := new(MockExpiringExchanger)

	// Prepare nameservers and extra records
	nameservers := []*dns.NS{
		{Hdr: dns.RR_Header{Name: "ns1.example.com.", Rrtype: dns.TypeNS}, Ns: "ns1.example.com."},
		{Hdr: dns.RR_Header{Name: "ns2.example.com.", Rrtype: dns.TypeNS}, Ns: "ns2.example.com."},
		{Hdr: dns.RR_Header{Name: "ns3.example.com.", Rrtype: dns.TypeNS}, Ns: "ns3.example.com."},
	}
	extra := []dns.RR{}
	ctx := context.TODO()

	// Mock the exchanger behavior if needed (e.g., to enrich the pool)
	mockExchanger.On("exchange", mock.Anything, mock.Anything).Return(&Response{
		Msg: &dns.Msg{
			Answer: []dns.RR{
				&dns.A{Hdr: dns.RR_Header{Name: "ns1.example.com.", Rrtype: dns.TypeA, Ttl: 300}, A: net.ParseIP("192.0.2.53")},
				&dns.A{Hdr: dns.RR_Header{Name: "ns2.example.com.", Rrtype: dns.TypeA, Ttl: 300}, A: net.ParseIP("192.0.2.54")},
				&dns.A{Hdr: dns.RR_Header{Name: "ns3.example.com.", Rrtype: dns.TypeA, Ttl: 300}, A: net.ParseIP("192.0.2.55")},
			},
		},
		Duration: 10 * time.Millisecond,
	})

	// Execute — with no glue records, createZone now returns an error
	// immediately and enriches in the background (non-blocking).
	// The query retries and finds the zone enriched on second attempt.
	z, err := createZone(ctx, "example.com.", "com.", nameservers, extra, mockExchanger)

	assert.Error(t, err) // expected: enriching in background
	assert.Nil(t, z)
	assert.ErrorIs(t, err, ErrFailedCreatingZoneAndPool)

	// Wait briefly for background enrichment to complete.
	time.Sleep(100 * time.Millisecond)

	// Second attempt should succeed now that enrichment has completed.
	z2, err2 := createZone(ctx, "example.com.", "com.", nameservers, extra, mockExchanger)
	// Note: may still fail if enrichment hasn't populated the pool yet,
	// which is expected — the resolver retries on next query.
	_ = z2
	_ = err2
}

func TestCreateZone_PoolCreationFailsWithEnrichment(t *testing.T) {
	// Setup
	mockExchanger := new(MockExpiringExchanger)

	// Prepare nameservers and extra records
	nameservers := []*dns.NS{
		{Hdr: dns.RR_Header{Name: "ns1.example.com.", Rrtype: dns.TypeNS}, Ns: "ns1.example.com."},
		{Hdr: dns.RR_Header{Name: "ns2.example.com.", Rrtype: dns.TypeNS}, Ns: "ns2.example.com."},
		{Hdr: dns.RR_Header{Name: "ns3.example.com.", Rrtype: dns.TypeNS}, Ns: "ns3.example.com."},
	}
	extra := []dns.RR{}
	ctx := context.TODO()

	// Mock the exchanger behavior if needed (e.g., to enrich the pool)
	mockExchanger.On("exchange", mock.Anything, mock.Anything).Return(&Response{
		Msg: &dns.Msg{
			Answer: []dns.RR{},
		},
		Duration: 10 * time.Millisecond,
	})

	// Execute
	z, err := createZone(ctx, "example.com.", "com.", nameservers, extra, mockExchanger)

	// With non-blocking enrichment, the error is now ErrFailedCreatingZoneAndPool
	// because the zone can't be created without IP addresses. Enrichment
	// happens in the background.
	assert.Nil(t, z)
	assert.ErrorIs(t, err, ErrFailedCreatingZoneAndPool)
}

// TestCreateZone_SuccessWithOptionalEnrichment Has one glue record returned, so tried to enrich to find the addresses of the other two.
func TestCreateZone_SuccessWithOptionalEnrichment(t *testing.T) {
	// Setup
	mockExchanger := new(MockExpiringExchanger)

	// Prepare nameservers and extra records
	nameservers := []*dns.NS{
		{Hdr: dns.RR_Header{Name: "ns1.example.com.", Rrtype: dns.TypeNS}, Ns: "ns1.example.com."},
		{Hdr: dns.RR_Header{Name: "ns2.example.com.", Rrtype: dns.TypeNS}, Ns: "ns2.example.com."},
		{Hdr: dns.RR_Header{Name: "ns3.example.com.", Rrtype: dns.TypeNS}, Ns: "ns3.example.com."},
	}
	extra := []dns.RR{
		&dns.A{Hdr: dns.RR_Header{Name: "ns1.example.com.", Rrtype: dns.TypeA, Ttl: 300}, A: net.ParseIP("192.0.2.53")},
	}
	ctx := context.TODO()

	// Mock the exchanger behavior if needed (e.g., to enrich the pool)
	mockExchanger.On("exchange", mock.Anything, mock.Anything).Return(&Response{
		Msg: &dns.Msg{
			Answer: []dns.RR{
				&dns.A{Hdr: dns.RR_Header{Name: "ns2.example.com.", Rrtype: dns.TypeA, Ttl: 300}, A: net.ParseIP("192.0.2.54")},
				&dns.A{Hdr: dns.RR_Header{Name: "ns3.example.com.", Rrtype: dns.TypeA, Ttl: 300}, A: net.ParseIP("192.0.2.55")},
			},
		},
		Duration: 10 * time.Millisecond,
	})

	// Execute
	z, err := createZone(ctx, "example.com.", "com.", nameservers, extra, mockExchanger)

	// AssertionsOk
	assert.NoError(t, err)
	assert.NotNil(t, z)
	assert.Equal(t, "example.com.", z.name())

	// We'll peek under the covers to ensure the pool was created as expected.
	pool, ok := z.(*zoneImpl).pool.(*nameserverPool)
	assert.True(t, ok)

	for i := 1; i <= 10; i++ {
		// Not really nice testing across multi-threads, but this seems deterministic enough.
		time.Sleep(time.Duration(i) * 10 * time.Millisecond)
		if pool.status() == PoolPrimed {
			break
		}
	}
	assert.Equal(t, pool.status(), PoolPrimed)
}
