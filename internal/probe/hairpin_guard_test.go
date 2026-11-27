package probe

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/1mb-dev/natcheck/internal/stunserver"
)

// redirectConn sends what is addressed to target to fake instead, so a
// loopback responder can stand in for a server at any address.
type redirectConn struct {
	net.PacketConn
	target, fake netip.AddrPort
}

func (c redirectConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	if u, ok := addr.(*net.UDPAddr); ok && u.AddrPort() == c.target {
		addr = net.UDPAddrFromAddrPort(c.fake)
	}
	return c.PacketConn.WriteTo(b, addr)
}

// startReportingResponder answers every Binding request with XOR-MAPPED-ADDRESS
// set to mapped.Addr() and the observed source port.
func startReportingResponder(t *testing.T, mapped netip.Addr) netip.AddrPort {
	t.Helper()
	c, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	s := stunserver.New(stunserver.Options{})
	go func() {
		buf := make([]byte, 1500)
		for {
			n, src, err := c.ReadFrom(buf)
			if err != nil {
				return
			}
			port := uint16(src.(*net.UDPAddr).Port)
			if resp := s.Handle(append([]byte{}, buf[:n]...), netip.AddrPortFrom(mapped, port)); resp != nil {
				_, _ = c.WriteTo(resp, src)
			}
		}
	}()
	return c.LocalAddr().(*net.UDPAddr).AddrPort()
}

// TestHairpinAddrs_MappedOutsideScopeSendsNothing: a server that reports a
// mapped endpoint outside its own family and scope gets no tag.
func TestHairpinAddrs_MappedOutsideScopeSendsNothing(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name           string
		target, mapped string
		sent           bool
	}{
		{"public target, loopback mapped", "203.0.113.1", "127.0.0.1", false},
		{"public target, private mapped", "203.0.113.1", "192.168.1.2", false},
		{"public target, broadcast mapped", "203.0.113.1", "255.255.255.255", false},
		{"IPv6 target, IPv4 mapped", "2001:db8::1", "198.51.100.7", false},
		{"public target, public mapped", "203.0.113.1", "198.51.100.7", true},
		{"private target, private mapped", "192.168.1.1", "192.168.1.2", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			target := netip.MustParseAddr(tc.target)
			fake := startReportingResponder(t, netip.MustParseAddr(tc.mapped))
			server := Server{Host: tc.target, Port: 3478}
			listen := func(string, string) (net.PacketConn, error) {
				c, err := net.ListenPacket("udp4", "127.0.0.1:0")
				return redirectConn{c, netip.AddrPortFrom(target, 3478), fake}, err
			}
			var sends atomic.Int32
			send := func(context.Context, net.PacketConn, netip.AddrPort, []byte) error {
				sends.Add(1)
				return nil
			}
			recv := func(context.Context, net.PacketConn, []byte, time.Duration) (bool, error) { return false, nil }
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			res := hairpinAddrs(ctx, server, []netip.Addr{target}, 300*time.Millisecond, listen, send, recv)
			if got := sends.Load() == 1; got != tc.sent {
				t.Fatalf("sends = %d, Err = %v; want sent %v", sends.Load(), res.Err, tc.sent)
			}
			if tc.sent {
				if res.Err != nil || res.Detected == nil {
					t.Errorf("Detected = %v, Err = %v; want &false, nil", res.Detected, res.Err)
				}
				return
			}
			if res.Detected != nil {
				t.Errorf("Detected = %v; want nil", res.Detected)
			}
			if res.Err == nil || !strings.Contains(res.Err.Error(), "is an address natcheck does not send to") {
				t.Errorf("Err = %v; want the scope refusal", res.Err)
			}
		})
	}
}
