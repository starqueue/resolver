package resolver

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// Mock DNS Client
type MockDNSClient struct {
	mock.Mock
}

func (m *MockDNSClient) ExchangeContext(ctx context.Context, msg *dns.Msg, addr string) (*dns.Msg, time.Duration, error) {
	args := m.Called(ctx, msg, addr)
	return args.Get(0).(*dns.Msg), args.Get(1).(time.Duration), args.Error(2)
}

func TestExchange_ValidDNSMessage(t *testing.T) {
	// Setup
	mockClient := new(MockDNSClient)
	factory := func(protocol string) dnsClient {
		return mockClient
	}
	ns := &nameserver{addr: "192.0.2.53", dnsClientFactory: factory}

	// Prepare the DNS message with a valid question
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn("example.com."), dns.TypeA)
	ctx := context.TODO()
	expectedResponse := new(dns.Msg)
	expectedDuration := 10 * time.Millisecond

	// Mock the ExchangeContext function to return the expected response and no error
	mockClient.On("ExchangeContext", ctx, msg, "192.0.2.53:53").Return(expectedResponse, expectedDuration, nil)

	// Execute
	response := ns.exchange(ctx, msg)

	// Assertions
	assert.NoError(t, response.Err)
	assert.Equal(t, expectedResponse, response.Msg)
	assert.Equal(t, expectedDuration, response.Duration)
}

func TestExchange_NilDNSMessage(t *testing.T) {
	// Setup
	mockClient := new(MockDNSClient)
	factory := func(protocol string) dnsClient {
		return mockClient
	}
	ns := &nameserver{addr: "192.0.2.53", dnsClientFactory: factory}

	ctx := context.TODO()

	// Execute
	response := ns.exchange(ctx, nil)

	// Assertions
	assert.ErrorIs(t, response.Err, ErrNilMessageSentToExchange)
}

func TestExchange_DNSClientError(t *testing.T) {
	// Setup

	mockClient := new(MockDNSClient)
	factory := func(protocol string) dnsClient {
		return mockClient
	}
	ns := &nameserver{addr: "192.0.2.53", dnsClientFactory: factory}

	// Prepare the DNS message with a valid question
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn("example.com."), dns.TypeA)
	ctx := context.TODO()
	expectedError := errors.New("mock client error")

	// Mock the ExchangeContext function to return an error
	mockClient.On("ExchangeContext", ctx, msg, "192.0.2.53:53").Return((*dns.Msg)(nil), time.Duration(0), expectedError)

	// Execute
	response := ns.exchange(ctx, msg)

	// Assertions
	assert.Error(t, response.Err)
	assert.Equal(t, expectedError, response.Err)
}

func TestExchange_TCPErrorFallbackToUDP(t *testing.T) {
	// TCP fails, UDP succeeds — verifies TCP-first with UDP fallback.
	udpClient := new(MockDNSClient)
	factory := func(protocol string) dnsClient {
		return udpClient
	}
	ns := &nameserver{addr: "192.0.2.53", dnsClientFactory: factory}
	// Force TCP pool to fail by pointing at unreachable address.
	ns.tcpPool = newTCPPool("192.0.2.99:53")
	ns.tcpPoolOnce.Do(func() {}) // mark as initialised

	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn("example.com."), dns.TypeA)
	ctx, cancel := context.WithTimeout(context.TODO(), 3*time.Second)
	defer cancel()

	expectedResponse := new(dns.Msg)
	expectedDuration := 10 * time.Millisecond

	udpClient.On("ExchangeContext", mock.Anything, mock.Anything, "192.0.2.53:53").
		Return(expectedResponse, expectedDuration, nil).Once()

	response := ns.exchange(ctx, msg)

	assert.NoError(t, response.Err)
	assert.NotNil(t, response.Msg)
	udpClient.AssertNumberOfCalls(t, "ExchangeContext", 1)
	assert.Equal(t, uint32(1), ns.numberOfUdpFallback.Load())
}

func TestExchange_BothTCPAndUDPReturnErrors(t *testing.T) {
	// Both TCP and UDP fail — verifies error propagation.
	udpClient := new(MockDNSClient)
	factory := func(protocol string) dnsClient {
		return udpClient
	}
	ns := &nameserver{addr: "192.0.2.53", dnsClientFactory: factory}
	ns.tcpPool = newTCPPool("192.0.2.99:53")
	ns.tcpPoolOnce.Do(func() {})

	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn("example.com."), dns.TypeA)
	ctx, cancel := context.WithTimeout(context.TODO(), 3*time.Second)
	defer cancel()

	udpError := errors.New("mock UDP error")
	udpClient.On("ExchangeContext", mock.Anything, mock.Anything, "192.0.2.53:53").
		Return((*dns.Msg)(nil), time.Duration(0), udpError).Once()

	response := ns.exchange(ctx, msg)

	assert.Error(t, response.Err)
	udpClient.AssertNumberOfCalls(t, "ExchangeContext", 1)
}

func TestExchange_IPv6AddressFormatting(t *testing.T) {
	// Setup
	mockClient := new(MockDNSClient)
	factory := func(protocol string) dnsClient {
		return mockClient
	}

	ns := &nameserver{addr: "2001:db8::1", dnsClientFactory: factory}

	// Prepare the DNS message with a valid question
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn("example.com."), dns.TypeA)
	ctx := context.TODO()

	expectedResponse := new(dns.Msg)
	expectedDuration := 10 * time.Millisecond

	// Mock the ExchangeContext to return a valid response
	mockClient.On("ExchangeContext", ctx, msg, "[2001:db8::1]:53").Return(expectedResponse, expectedDuration, nil).Once()

	// Execute
	response := ns.exchange(ctx, msg)

	// Assertions
	assert.NoError(t, response.Err)
	assert.Equal(t, expectedResponse, response.Msg)
	assert.Equal(t, expectedDuration, response.Duration)
	mockClient.AssertNumberOfCalls(t, "ExchangeContext", 1)
}

func TestDefaultDnsClientFactory_UDP(t *testing.T) {

	ns := &nameserver{addr: "2001:db8::1"}

	client := ns.defaultDnsClientFactory("udp")
	assert.IsType(t, &pooledUDPClient{}, client)
	typedClient, ok := client.(*pooledUDPClient)
	assert.True(t, ok)
	if ok {
		assert.Equal(t, DefaultTimeoutUDP, typedClient.timeout)
	}

}

func TestDefaultDnsClientFactory_TCP(t *testing.T) {

	ns := &nameserver{addr: "2001:db8::1"}

	client := ns.defaultDnsClientFactory("tcp")
	assert.IsType(t, new(dns.Client), client)
	typedClient, ok := client.(*dns.Client)
	assert.True(t, ok)
	if ok {
		assert.Equal(t, DefaultTimeoutTCP, typedClient.Timeout)
	}

}
