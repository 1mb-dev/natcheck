// Package probe runs STUN Binding requests against one or more servers and
// captures mapping behavior (mapped endpoint, RTT, errors).
package probe

import (
	"context"
	"net/netip"
	"time"
)

// Server identifies a STUN server to probe.
type Server struct {
	Host string
	Port int
}

// Result captures the outcome of a single probe. On success, Mapped and RTT
// are set and Err is nil. On failure, Err is non-nil and Mapped/RTT are zero.
//
// Target is the resolved, unmapped address the probe was sent to. It stays zero
// when no request could be sent.
//
// Other carries the OTHER-ADDRESS attribute (RFC 5780 §7.4) when the server
// advertised one. Zero-value (Other.IsValid() == false) means the server's
// response did not include OTHER-ADDRESS, so it does not support the §4.4
// filtering classification sequence.
type Result struct {
	Server Server
	Target netip.AddrPort
	Mapped netip.AddrPort
	Other  netip.AddrPort
	RTT    time.Duration
	Err    error
}

// Prober probes every server in one run and returns one Result per server, in
// input order. Taking the whole set is the point of the interface: probes must
// be able to share a local endpoint. Implementations must not panic on bad
// input and must respect context cancellation.
type Prober interface {
	ProbeAll(ctx context.Context, servers []Server) []Result
}

// pickNetwork returns the UDP network and wildcard listen address for ip's
// address family.
func pickNetwork(ip netip.Addr) (network, listenAddr string) {
	if ip.Unmap().Is4() {
		return "udp4", "0.0.0.0:0"
	}
	return "udp6", "[::]:0"
}
