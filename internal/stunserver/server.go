// Package stunserver implements a stateless STUN responder for natcheck.
//
// The package exposes two consumption modes built on the same Handle function:
// pure byte-in/byte-out for in-process tests, and a PacketConn dispatch loop
// for use as a long-running responder. Currently supports plain BindingRequest;
// CHANGE-REQUEST handling planned per docs/design.md v0.2 addendum.
package stunserver

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"time"

	"github.com/pion/stun/v3"
)

// Options configures a Server. Empty for the plain-Binding responder;
// CHANGE-REQUEST-related fields (AltIP, AltPort) join when CHANGE-REQUEST
// support lands.
type Options struct{}

// Server is a stateless STUN responder. Construct via New. Handle is pure and
// safe for concurrent use across goroutines. Serve owns its PacketConn — do
// not call Serve concurrently with the same conn.
type Server struct{}

// New returns a Server configured with opts.
func New(opts Options) *Server {
	_ = opts
	return &Server{}
}

// Handle processes a single STUN request and returns the wire bytes of the
// response, or nil to indicate no reply (drop). The src argument is the
// observed source endpoint and is echoed in XOR-MAPPED-ADDRESS.
//
// Handle never panics. Malformed input, unsupported message types, and any
// build failure are silently dropped (return nil) per the diagnostic-responder
// posture. Response size is comparable to request size; no meaningful
// amplification factor.
func (s *Server) Handle(req []byte, src netip.AddrPort) []byte {
	msg := &stun.Message{Raw: req}
	if err := msg.Decode(); err != nil {
		return nil
	}
	if msg.Type != stun.BindingRequest {
		return nil
	}
	resp, err := stun.Build(
		stun.NewTransactionIDSetter(msg.TransactionID),
		stun.BindingSuccess,
		&stun.XORMappedAddress{IP: src.Addr().AsSlice(), Port: int(src.Port())},
	)
	if err != nil {
		return nil
	}
	return resp.Raw
}

// Serve runs a read-decode-Handle-write loop on conn until ctx is cancelled or
// conn returns net.ErrClosed. On ctx cancellation, Serve forces any in-flight
// ReadFrom to return immediately by setting a deadline in the past (matching
// the cancellation idiom in internal/probe/stun.go).
//
// Per-packet decode failures and non-UDP source addresses are swallowed; the
// loop continues. WriteTo errors (e.g., destination unreachable) are silently
// dropped — diagnostic-responder posture, not a delivery-guaranteed service.
//
// Returns ctx.Err() on cancellation or the underlying conn error (typically
// net.ErrClosed) on shutdown.
func (s *Server) Serve(ctx context.Context, conn net.PacketConn) error {
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.SetReadDeadline(time.Unix(1, 0))
		case <-done:
		}
	}()

	for {
		buf := make([]byte, 1500)
		n, from, err := conn.ReadFrom(buf)
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return ctxErr
			}
			if errors.Is(err, net.ErrClosed) {
				return err
			}
			continue
		}
		udp, ok := from.(*net.UDPAddr)
		if !ok {
			continue
		}
		addr, ok := netip.AddrFromSlice(udp.IP)
		if !ok {
			continue
		}
		src := netip.AddrPortFrom(addr.Unmap(), uint16(udp.Port))
		resp := s.Handle(buf[:n], src)
		if resp == nil {
			continue
		}
		_, _ = conn.WriteTo(resp, from)
	}
}
