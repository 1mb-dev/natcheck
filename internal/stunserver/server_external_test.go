// External test package — breaks the import cycle that arises when
// internal/probe imports internal/stunserver (production) AND a stunserver
// test wants to drive Serve via internal/probe (test-only).
package stunserver_test

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/1mb-dev/natcheck/internal/probe"
	"github.com/1mb-dev/natcheck/internal/stunserver"
	"github.com/pion/stun/v3"
)

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
	go func() { serveDone <- stunserver.New(stunserver.Options{}).Serve(ctx, conn) }()

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

func TestBuildChangeRequest_RoundTrip(t *testing.T) {
	cases := []struct{ ip, port bool }{
		{false, false},
		{true, false},
		{false, true},
		{true, true},
	}
	for _, c := range cases {
		attr := stunserver.BuildChangeRequest(c.ip, c.port)
		if attr.Type != stun.AttrChangeRequest {
			t.Fatalf("(%v,%v): attr.Type = %v, want AttrChangeRequest", c.ip, c.port, attr.Type)
		}
		if len(attr.Value) != 4 {
			t.Fatalf("(%v,%v): attr.Value length = %d, want 4", c.ip, c.port, len(attr.Value))
		}
		// Sanity-check the byte payload directly: bit A = 0x04, bit B = 0x02.
		flags := binary.BigEndian.Uint32(attr.Value)
		wantIP := flags&0x04 != 0
		wantPort := flags&0x02 != 0
		if wantIP != c.ip || wantPort != c.port {
			t.Fatalf("(%v,%v): payload bits decode as (%v,%v)", c.ip, c.port, wantIP, wantPort)
		}
		// Build a full message and round-trip through ParseChangeRequest.
		m, err := stun.Build(stun.TransactionID, stun.BindingRequest, attr)
		if err != nil {
			t.Fatalf("(%v,%v) build: %v", c.ip, c.port, err)
		}
		m.Encode()
		gotIP, gotPort, ok := stunserver.ParseChangeRequest(m.Raw)
		if !ok {
			t.Fatalf("(%v,%v): ParseChangeRequest ok=false", c.ip, c.port)
		}
		if gotIP != c.ip || gotPort != c.port {
			t.Fatalf("(%v,%v) round-trip got (%v,%v)", c.ip, c.port, gotIP, gotPort)
		}
	}
}
