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
// Other carries the OTHER-ADDRESS attribute (RFC 5780 §7.4) when the server
// advertised one. Zero-value (Other.IsValid() == false) means the server's
// response did not include OTHER-ADDRESS, so it does not support the §4.4
// filtering classification sequence.
type Result struct {
	Server Server
	Mapped netip.AddrPort
	Other  netip.AddrPort
	RTT    time.Duration
	Err    error
}

// Prober performs one STUN Binding probe per call. Implementations must not
// panic on bad input and must respect context cancellation.
type Prober interface {
	Probe(ctx context.Context, s Server) Result
}
