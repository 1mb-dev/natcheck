package stunserver

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/1mb-dev/natcheck/internal/probe"
	"github.com/pion/stun/v3"
)

func mustEncodeBindingRequest(t *testing.T) *stun.Message {
	t.Helper()
	m, err := stun.Build(stun.TransactionID, stun.BindingRequest)
	if err != nil {
		t.Fatalf("build binding request: %v", err)
	}
	m.Encode()
	return m
}

func TestHandle_BindingRequestIPv4(t *testing.T) {
	s := New(Options{})
	req := mustEncodeBindingRequest(t)
	src := netip.MustParseAddrPort("127.0.0.1:51234")

	out := s.Handle(req.Raw, src)
	if out == nil {
		t.Fatal("expected response, got nil")
	}
	resp := &stun.Message{Raw: out}
	if err := resp.Decode(); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Type != stun.BindingSuccess {
		t.Fatalf("type = %v, want BindingSuccess", resp.Type)
	}
	if resp.TransactionID != req.TransactionID {
		t.Fatal("transaction ID mismatch")
	}
	var xor stun.XORMappedAddress
	if err := xor.GetFrom(resp); err != nil {
		t.Fatalf("XOR-MAPPED-ADDRESS: %v", err)
	}
	got, _ := netip.AddrFromSlice(xor.IP)
	gotAP := netip.AddrPortFrom(got.Unmap(), uint16(xor.Port))
	if gotAP != src {
		t.Fatalf("mapped = %v, want %v", gotAP, src)
	}
}

func TestHandle_BindingRequestIPv6(t *testing.T) {
	s := New(Options{})
	req := mustEncodeBindingRequest(t)
	src := netip.MustParseAddrPort("[::1]:51234")

	out := s.Handle(req.Raw, src)
	if out == nil {
		t.Fatal("expected response, got nil")
	}
	resp := &stun.Message{Raw: out}
	if err := resp.Decode(); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	var xor stun.XORMappedAddress
	if err := xor.GetFrom(resp); err != nil {
		t.Fatalf("XOR-MAPPED-ADDRESS: %v", err)
	}
	got, ok := netip.AddrFromSlice(xor.IP)
	if !ok {
		t.Fatalf("invalid mapped IP %v", xor.IP)
	}
	if !got.Is6() {
		t.Fatalf("mapped IP = %v, want IPv6", got)
	}
	gotAP := netip.AddrPortFrom(got, uint16(xor.Port))
	if gotAP != src {
		t.Fatalf("mapped = %v, want %v", gotAP, src)
	}
}

func TestHandle_NonBindingType(t *testing.T) {
	s := New(Options{})
	m, err := stun.Build(stun.TransactionID, stun.BindingError)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	m.Encode()

	if out := s.Handle(m.Raw, netip.MustParseAddrPort("127.0.0.1:1")); out != nil {
		t.Fatalf("expected nil for BindingError, got %d bytes", len(out))
	}
}

func TestHandle_AllocateRequest(t *testing.T) {
	s := New(Options{})
	// AllocateRequest is a TURN method, not a STUN Binding method.
	allocate := stun.NewType(stun.MethodAllocate, stun.ClassRequest)
	m, err := stun.Build(stun.TransactionID, allocate)
	if err != nil {
		t.Fatalf("build allocate: %v", err)
	}
	m.Encode()

	if out := s.Handle(m.Raw, netip.MustParseAddrPort("127.0.0.1:1")); out != nil {
		t.Fatalf("expected nil for AllocateRequest, got %d bytes", len(out))
	}
}

func TestHandle_TooShort(t *testing.T) {
	s := New(Options{})
	if out := s.Handle([]byte{0xff, 0xff}, netip.MustParseAddrPort("127.0.0.1:1")); out != nil {
		t.Fatalf("expected nil for too-short input, got %d bytes", len(out))
	}
}

func TestHandle_Empty(t *testing.T) {
	s := New(Options{})
	if out := s.Handle(nil, netip.MustParseAddrPort("127.0.0.1:1")); out != nil {
		t.Fatalf("expected nil for nil input, got %d bytes", len(out))
	}
	if out := s.Handle([]byte{}, netip.MustParseAddrPort("127.0.0.1:1")); out != nil {
		t.Fatalf("expected nil for empty input, got %d bytes", len(out))
	}
}

func TestHandle_Garbled(t *testing.T) {
	s := New(Options{})
	garbage := make([]byte, 100)
	for i := range garbage {
		garbage[i] = 0xFF
	}
	if out := s.Handle(garbage, netip.MustParseAddrPort("127.0.0.1:1")); out != nil {
		t.Fatalf("expected nil for garbled input, got %d bytes", len(out))
	}
}

func TestServe_RoundTrip(t *testing.T) {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	udpAddr := conn.LocalAddr().(*net.UDPAddr)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	serveDone := make(chan error, 1)
	go func() { serveDone <- New(Options{}).Serve(ctx, conn) }()

	probeCtx, probeCancel := context.WithTimeout(context.Background(), time.Second)
	defer probeCancel()
	res := probe.NewSTUN().Probe(probeCtx, probe.Server{Host: "127.0.0.1", Port: udpAddr.Port})
	if res.Err != nil {
		t.Fatalf("probe: %v", res.Err)
	}
	if !res.Mapped.Addr().IsLoopback() {
		t.Fatalf("mapped = %v, want loopback", res.Mapped.Addr())
	}

	cancel()
	select {
	case err := <-serveDone:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("serve returned %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("serve did not return within 1s of cancel")
	}
}

func TestServe_ContextCancel(t *testing.T) {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	serveDone := make(chan error, 1)
	go func() { serveDone <- New(Options{}).Serve(ctx, conn) }()

	cancel()
	select {
	case err := <-serveDone:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("serve returned %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("serve did not return within 1s of cancel")
	}
}

func TestServe_ConnClosed(t *testing.T) {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx := context.Background()
	serveDone := make(chan error, 1)
	go func() { serveDone <- New(Options{}).Serve(ctx, conn) }()
	// No sleep: ReadFrom returns net.ErrClosed deterministically once we close,
	// regardless of whether Serve has entered the read yet.
	_ = conn.Close()
	select {
	case err := <-serveDone:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("serve returned %v, want net.ErrClosed", err)
		}
	case <-time.After(time.Second):
		t.Fatal("serve did not return within 1s of conn close")
	}
}
