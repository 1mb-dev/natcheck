package stunserver

import (
	"context"
	"encoding/binary"
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

// --- OTHER-ADDRESS tests ---

func TestHandle_OtherAddressIPv4(t *testing.T) {
	other := netip.MustParseAddrPort("192.0.2.1:3479")
	s := New(Options{Other: other})
	req := mustEncodeBindingRequest(t)
	src := netip.MustParseAddrPort("127.0.0.1:51234")

	out := s.Handle(req.Raw, src)
	if out == nil {
		t.Fatal("expected response, got nil")
	}
	resp := &stun.Message{Raw: out}
	if err := resp.Decode(); err != nil {
		t.Fatalf("decode: %v", err)
	}
	var oa stun.OtherAddress
	if err := oa.GetFrom(resp); err != nil {
		t.Fatalf("OTHER-ADDRESS missing: %v", err)
	}
	gotIP, _ := netip.AddrFromSlice(oa.IP)
	gotAP := netip.AddrPortFrom(gotIP.Unmap(), uint16(oa.Port))
	if gotAP != other {
		t.Fatalf("OTHER-ADDRESS = %v, want %v", gotAP, other)
	}
}

func TestHandle_OtherAddressIPv6(t *testing.T) {
	other := netip.MustParseAddrPort("[2001:db8::1]:3479")
	s := New(Options{Other: other})
	req := mustEncodeBindingRequest(t)
	src := netip.MustParseAddrPort("[::1]:51234")

	out := s.Handle(req.Raw, src)
	if out == nil {
		t.Fatal("expected response, got nil")
	}
	resp := &stun.Message{Raw: out}
	if err := resp.Decode(); err != nil {
		t.Fatalf("decode: %v", err)
	}
	var oa stun.OtherAddress
	if err := oa.GetFrom(resp); err != nil {
		t.Fatalf("OTHER-ADDRESS missing: %v", err)
	}
	gotIP, ok := netip.AddrFromSlice(oa.IP)
	if !ok {
		t.Fatalf("invalid OTHER-ADDRESS IP: %v", oa.IP)
	}
	if !gotIP.Is6() {
		t.Fatalf("OTHER-ADDRESS family = %v, want IPv6", gotIP)
	}
	gotAP := netip.AddrPortFrom(gotIP, uint16(oa.Port))
	if gotAP != other {
		t.Fatalf("OTHER-ADDRESS = %v, want %v", gotAP, other)
	}
}

func TestHandle_OtherAddressAbsent(t *testing.T) {
	s := New(Options{}) // no Other configured
	req := mustEncodeBindingRequest(t)
	src := netip.MustParseAddrPort("127.0.0.1:51234")

	out := s.Handle(req.Raw, src)
	if out == nil {
		t.Fatal("expected response, got nil")
	}
	resp := &stun.Message{Raw: out}
	if err := resp.Decode(); err != nil {
		t.Fatalf("decode: %v", err)
	}
	var oa stun.OtherAddress
	if err := oa.GetFrom(resp); !errors.Is(err, stun.ErrAttributeNotFound) {
		t.Fatalf("OTHER-ADDRESS GetFrom err = %v, want ErrAttributeNotFound", err)
	}
	// Regression backstop: with Options{}, response carries exactly one
	// attribute (XOR-MAPPED-ADDRESS). Future silent additions break this test.
	if got := len(resp.Attributes); got != 1 {
		t.Fatalf("attribute count = %d, want 1", got)
	}
	if resp.Attributes[0].Type != stun.AttrXORMappedAddress {
		t.Fatalf("sole attribute type = %v, want XOR-MAPPED-ADDRESS", resp.Attributes[0].Type)
	}
}

func TestHandle_SrcUnmapsToIPv4(t *testing.T) {
	// IPv4-mapped IPv6 src must be encoded as IPv4 family in XOR-MAPPED-ADDRESS.
	// Guards the src.Addr().Unmap() defensive call in Handle.
	s := New(Options{})
	req := mustEncodeBindingRequest(t)
	mappedSrc := netip.AddrPortFrom(netip.MustParseAddr("::ffff:192.0.2.1"), 51234)

	out := s.Handle(req.Raw, mappedSrc)
	resp := &stun.Message{Raw: out}
	if err := resp.Decode(); err != nil {
		t.Fatalf("decode: %v", err)
	}
	var xor stun.XORMappedAddress
	if err := xor.GetFrom(resp); err != nil {
		t.Fatalf("XOR-MAPPED-ADDRESS missing: %v", err)
	}
	if len(xor.IP) != 4 {
		t.Fatalf("XOR-MAPPED-ADDRESS IP length = %d, want 4 (IPv4 family)", len(xor.IP))
	}
	gotIP, _ := netip.AddrFromSlice(xor.IP)
	wantIP := netip.MustParseAddr("192.0.2.1")
	if gotIP.Unmap() != wantIP {
		t.Fatalf("XOR-MAPPED-ADDRESS IP = %v, want %v", gotIP.Unmap(), wantIP)
	}
}

func TestHandle_OtherAddressUnmaps(t *testing.T) {
	// IPv4-mapped IPv6 address must be encoded as IPv4 family in OTHER-ADDRESS.
	mapped := netip.AddrPortFrom(netip.MustParseAddr("::ffff:192.0.2.1"), 3479)
	s := New(Options{Other: mapped})
	req := mustEncodeBindingRequest(t)
	src := netip.MustParseAddrPort("127.0.0.1:51234")

	out := s.Handle(req.Raw, src)
	resp := &stun.Message{Raw: out}
	if err := resp.Decode(); err != nil {
		t.Fatalf("decode: %v", err)
	}
	var oa stun.OtherAddress
	if err := oa.GetFrom(resp); err != nil {
		t.Fatalf("OTHER-ADDRESS missing: %v", err)
	}
	if len(oa.IP) != 4 {
		t.Fatalf("OTHER-ADDRESS IP length = %d, want 4 (IPv4 family)", len(oa.IP))
	}
	wantIP := netip.MustParseAddr("192.0.2.1")
	gotIP, _ := netip.AddrFromSlice(oa.IP)
	if gotIP.Unmap() != wantIP {
		t.Fatalf("OTHER-ADDRESS IP = %v, want %v", gotIP.Unmap(), wantIP)
	}
}

// --- ParseChangeRequest tests ---

func buildBindingRequestWithChange(t *testing.T, flags uint32) *stun.Message {
	t.Helper()
	var v [4]byte
	binary.BigEndian.PutUint32(v[:], flags)
	m, err := stun.Build(stun.TransactionID, stun.BindingRequest, stun.RawAttribute{
		Type:   stun.AttrChangeRequest,
		Length: 4,
		Value:  v[:],
	})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	m.Encode()
	return m
}

func TestParseChangeRequest_BothFlags(t *testing.T) {
	m := buildBindingRequestWithChange(t, 0x06)
	ip, port, ok := ParseChangeRequest(m.Raw)
	if !ip || !port || !ok {
		t.Fatalf("got (%v, %v, %v), want (true, true, true)", ip, port, ok)
	}
}

func TestParseChangeRequest_ChangeIPOnly(t *testing.T) {
	m := buildBindingRequestWithChange(t, 0x04)
	ip, port, ok := ParseChangeRequest(m.Raw)
	if !ip || port || !ok {
		t.Fatalf("got (%v, %v, %v), want (true, false, true)", ip, port, ok)
	}
}

func TestParseChangeRequest_ChangePortOnly(t *testing.T) {
	m := buildBindingRequestWithChange(t, 0x02)
	ip, port, ok := ParseChangeRequest(m.Raw)
	if ip || !port || !ok {
		t.Fatalf("got (%v, %v, %v), want (false, true, true)", ip, port, ok)
	}
}

func TestParseChangeRequest_NoFlags(t *testing.T) {
	m := buildBindingRequestWithChange(t, 0x00)
	ip, port, ok := ParseChangeRequest(m.Raw)
	if ip || port || !ok {
		t.Fatalf("got (%v, %v, %v), want (false, false, true)", ip, port, ok)
	}
}

func TestParseChangeRequest_ReservedBitsIgnored(t *testing.T) {
	// All bits set; A=0x04, B=0x02 extracted, others ignored.
	m := buildBindingRequestWithChange(t, 0xFFFFFFFF)
	ip, port, ok := ParseChangeRequest(m.Raw)
	if !ip || !port || !ok {
		t.Fatalf("got (%v, %v, %v), want (true, true, true)", ip, port, ok)
	}
}

func TestParseChangeRequest_NoAttribute(t *testing.T) {
	m := mustEncodeBindingRequest(t)
	ip, port, ok := ParseChangeRequest(m.Raw)
	if ip || port || ok {
		t.Fatalf("got (%v, %v, %v), want (false, false, false)", ip, port, ok)
	}
}

func TestParseChangeRequest_WrongMessageType(t *testing.T) {
	cases := []struct {
		name  string
		build func(t *testing.T) *stun.Message
	}{
		{"BindingError", func(t *testing.T) *stun.Message {
			m, err := stun.Build(stun.TransactionID, stun.BindingError)
			if err != nil {
				t.Fatalf("build: %v", err)
			}
			m.Encode()
			return m
		}},
		{"BindingSuccess_with_CHANGE-REQUEST", func(t *testing.T) *stun.Message {
			var v [4]byte
			binary.BigEndian.PutUint32(v[:], 0x06)
			m, err := stun.Build(stun.TransactionID, stun.BindingSuccess, stun.RawAttribute{
				Type:   stun.AttrChangeRequest,
				Length: 4,
				Value:  v[:],
			})
			if err != nil {
				t.Fatalf("build: %v", err)
			}
			m.Encode()
			return m
		}},
		{"AllocateRequest", func(t *testing.T) *stun.Message {
			allocate := stun.NewType(stun.MethodAllocate, stun.ClassRequest)
			m, err := stun.Build(stun.TransactionID, allocate)
			if err != nil {
				t.Fatalf("build: %v", err)
			}
			m.Encode()
			return m
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := tc.build(t)
			ip, port, ok := ParseChangeRequest(m.Raw)
			if ip || port || ok {
				t.Fatalf("got (%v, %v, %v), want (false, false, false)", ip, port, ok)
			}
		})
	}
}

func TestParseChangeRequest_Malformed(t *testing.T) {
	cases := [][]byte{
		nil,
		{},
		{0xff, 0xff},
		make([]byte, 100),
	}
	// The 100-byte zeroed slice would parse as a Binding-Request method (type
	// = 0x0000) with a header but no attributes; ensure it returns
	// (false,false,false) because there's no CHANGE-REQUEST attribute.
	for i, in := range cases {
		ip, port, ok := ParseChangeRequest(in)
		if ip || port || ok {
			t.Fatalf("case %d: got (%v, %v, %v), want (false, false, false)", i, ip, port, ok)
		}
	}
}

func TestParseChangeRequest_WrongAttrLen(t *testing.T) {
	// CHANGE-REQUEST with 8-byte payload (RFC mandates 4).
	m, err := stun.Build(stun.TransactionID, stun.BindingRequest, stun.RawAttribute{
		Type:   stun.AttrChangeRequest,
		Length: 8,
		Value:  []byte{0, 0, 0, 0, 0, 0, 0, 0},
	})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	m.Encode()
	ip, port, ok := ParseChangeRequest(m.Raw)
	if ip || port || ok {
		t.Fatalf("got (%v, %v, %v), want (false, false, false)", ip, port, ok)
	}
}

func TestParseChangeRequest_DuplicateAttribute(t *testing.T) {
	// Two CHANGE-REQUEST attributes with different flags. Pion's Get returns
	// the first; document this behavior.
	var first, second [4]byte
	binary.BigEndian.PutUint32(first[:], 0x04)  // change-IP only
	binary.BigEndian.PutUint32(second[:], 0x02) // change-PORT only
	m, err := stun.Build(stun.TransactionID, stun.BindingRequest,
		stun.RawAttribute{Type: stun.AttrChangeRequest, Length: 4, Value: first[:]},
		stun.RawAttribute{Type: stun.AttrChangeRequest, Length: 4, Value: second[:]},
	)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	m.Encode()
	ip, port, ok := ParseChangeRequest(m.Raw)
	if !ok {
		t.Fatal("ok = false; expected first-wins parsing")
	}
	if !ip || port {
		t.Fatalf("got (%v, %v, %v), want first-wins (true, false, true)", ip, port, ok)
	}
}
