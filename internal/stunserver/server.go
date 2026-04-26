// Package stunserver implements a stateless STUN responder for natcheck.
//
// The package exposes two consumption modes built on the same Handle function:
// pure byte-in/byte-out for in-process tests, and a PacketConn dispatch loop
// for use as a long-running responder. Supports BindingRequest with optional
// OTHER-ADDRESS responses (RFC 5780 §7.4). CHANGE-REQUEST routing is a caller
// concern — use ParseChangeRequest to extract flags from incoming requests.
package stunserver

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"time"

	"github.com/pion/stun/v3"
)

// Options configures a Server.
type Options struct {
	// Other is the address of the diagonal peer in an RFC 5780 §3 four-corner
	// topology. When set, Handle includes an OTHER-ADDRESS attribute pointing
	// to it. Zero-value disables the attribute.
	Other netip.AddrPort
}

// Server is a stateless STUN responder. Construct via New. Handle is pure and
// safe for concurrent use across goroutines. Serve owns its PacketConn — do
// not call Serve concurrently with the same conn.
type Server struct {
	opts Options
}

// New returns a Server configured with opts.
func New(opts Options) *Server {
	return &Server{opts: opts}
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
	srcAddr := src.Addr().Unmap()
	setters := []stun.Setter{
		stun.NewTransactionIDSetter(msg.TransactionID),
		stun.BindingSuccess,
		&stun.XORMappedAddress{IP: srcAddr.AsSlice(), Port: int(src.Port())},
	}
	if s.opts.Other.IsValid() {
		o := s.opts.Other.Addr().Unmap()
		setters = append(setters, &stun.OtherAddress{IP: o.AsSlice(), Port: int(s.opts.Other.Port())})
	}
	resp, err := stun.Build(setters...)
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

// ParseChangeRequest extracts CHANGE-REQUEST flags from a STUN BindingRequest.
// Returns ok=false for messages other than BindingRequest, malformed STUN,
// missing CHANGE-REQUEST attribute, or attribute payloads not exactly 4 bytes.
func ParseChangeRequest(req []byte) (changeIP, changePort, ok bool) {
	msg := &stun.Message{Raw: req}
	if err := msg.Decode(); err != nil {
		return false, false, false
	}
	if msg.Type != stun.BindingRequest {
		return false, false, false
	}
	v, err := msg.Get(stun.AttrChangeRequest)
	if err != nil || len(v) != 4 {
		return false, false, false
	}
	// RFC 5780 §7.2: bit A (0x04) = change IP, bit B (0x02) = change port.
	// Other bits MUST be zero per RFC; we extract A/B only and ignore the
	// rest (matches phase 1's silent-drop posture for diagnostic responder).
	flags := binary.BigEndian.Uint32(v)
	return flags&0x04 != 0, flags&0x02 != 0, true
}
