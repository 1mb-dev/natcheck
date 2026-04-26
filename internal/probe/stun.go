package probe

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"time"

	"github.com/pion/stun/v3"
)

// NewSTUN returns a Prober backed by pion/stun over UDP. A fresh UDP socket is
// opened per probe.
func NewSTUN() Prober {
	return stunProber{}
}

type stunProber struct{}

// Probe dials the server, sends a STUN Binding request, and returns the mapped
// endpoint plus RTT. Any failure is surfaced via Result.Err; Probe never panics.
// One-shot: no retransmissions. The caller's context bounds the total probe time.
func (stunProber) Probe(ctx context.Context, s Server) Result {
	res := Result{Server: s}
	if s.Host == "" || s.Port <= 0 || s.Port > 65535 {
		res.Err = fmt.Errorf("invalid server %q:%d", s.Host, s.Port)
		return res
	}

	addr := net.JoinHostPort(s.Host, strconv.Itoa(s.Port))

	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "udp", addr)
	if err != nil {
		res.Err = fmt.Errorf("dial %s: %w", addr, err)
		return res
	}
	defer func() { _ = conn.Close() }()

	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			// Past deadline forces in-flight Read/Write to error immediately.
			_ = conn.SetDeadline(time.Unix(1, 0))
		case <-done:
		}
	}()

	req, err := stun.Build(stun.TransactionID, stun.BindingRequest)
	if err != nil {
		res.Err = fmt.Errorf("build binding request: %w", err)
		return res
	}
	req.Encode()

	start := time.Now()
	if _, err := conn.Write(req.Raw); err != nil {
		res.Err = fmt.Errorf("write request: %w", err)
		return res
	}

	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil {
		res.Err = fmt.Errorf("read response: %w", err)
		return res
	}
	res.RTT = time.Since(start)

	resp := &stun.Message{Raw: append([]byte{}, buf[:n]...)}
	if err := resp.Decode(); err != nil {
		res.Err = fmt.Errorf("decode response: %w", err)
		return res
	}
	if resp.TransactionID != req.TransactionID {
		res.Err = errors.New("response transaction ID mismatch")
		return res
	}
	if resp.Type != stun.BindingSuccess {
		res.Err = fmt.Errorf("unexpected STUN message type: %s", resp.Type)
		return res
	}

	var xor stun.XORMappedAddress
	if err := xor.GetFrom(resp); err != nil {
		res.Err = fmt.Errorf("decode XOR-MAPPED-ADDRESS: %w", err)
		return res
	}
	ip, ok := netip.AddrFromSlice(xor.IP)
	if !ok {
		res.Err = fmt.Errorf("invalid mapped IP %v", xor.IP)
		return res
	}
	mapped := netip.AddrPortFrom(ip.Unmap(), uint16(xor.Port))
	if !mapped.IsValid() {
		res.Err = errors.New("mapped endpoint not valid")
		return res
	}
	res.Mapped = mapped

	// OTHER-ADDRESS (RFC 5780 §7.4) is optional: silently skip when absent.
	var oa stun.OtherAddress
	if err := oa.GetFrom(resp); err == nil {
		if otherIP, ok := netip.AddrFromSlice(oa.IP); ok {
			res.Other = netip.AddrPortFrom(otherIP.Unmap(), uint16(oa.Port))
		}
	}
	return res
}
