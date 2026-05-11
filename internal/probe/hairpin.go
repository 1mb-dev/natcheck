package probe

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"
)

// HairpinningResult captures the outcome of an RFC 5780 §4.3 hairpinning
// detection probe. Detected is tri-state:
//
//   - nil: probe could not run end-to-end (socket allocation, DNS, or per-socket
//     STUN probe failed); Err describes the underlying cause. Callers should
//     emit WarnHairpinUntested at the classifier layer.
//   - &true: tagged loopback packet arrived on socket B; the NAT supports
//     hairpinning for the (A→mB) path.
//   - &false: listen window elapsed with no tagged packet; either no hairpinning
//     or a per-NAT filtering rule suppressed the loopback (spec-acknowledged
//     false-negative case, see docs/design.md §4.3).
//
// Server echoes the input so consumers can attribute the result without
// re-threading state, mirroring FilteringResult.
type HairpinningResult struct {
	Server   Server
	Detected *bool
	Err      error
}

// ProbeHairpinning detects NAT hairpinning using two local UDP sockets:
//
//  1. Allocate sockets A and B, unconnected, address family inherited from the
//     resolved server IP.
//  2. STUN-probe each socket in parallel against `server` to learn mapped
//     endpoints mA and mB. Single-shot per probe — no retries. The wall-clock
//     budget below depends on this.
//  3. Send a 16-byte random nonce from A to mB.
//  4. Listen on B for the nonce. Timeout: T_hairpin (= `timeout`).
//
// Wall-clock budget: STUN phase (parallel) caps at min(timeout/2, 500ms);
// listen phase consumes up to `timeout`. Total ≤ 1.5 × timeout in the worst
// case. The caller orchestrates this in parallel with mapping probes; the
// non-functional target at docs/design.md:303 (<2s cold-start) is preserved
// for timeout ≤ 1s.
func ProbeHairpinning(ctx context.Context, server Server, timeout time.Duration) HairpinningResult {
	return probeHairpinning(ctx, server, timeout, realHairpinSend, realHairpinRecv)
}

// hairpinSender / hairpinReceiver abstract the tagged send + listen steps so
// tests can inject behavior that simulates a per-NAT filtering rule without
// requiring a real NAT in the localhost test environment. Production wires
// realHairpinSend / realHairpinRecv (real socket I/O). The spec at
// docs/design.md:428 names the port-restricted-filtering false-negative as a
// required test case; this seam is how that test is expressed.
type hairpinSender func(ctx context.Context, from net.PacketConn, to netip.AddrPort, tag []byte) error
type hairpinReceiver func(ctx context.Context, on net.PacketConn, tag []byte, timeout time.Duration) (bool, error)

func probeHairpinning(ctx context.Context, server Server, timeout time.Duration, send hairpinSender, recv hairpinReceiver) HairpinningResult {
	res := HairpinningResult{Server: server}
	if server.Host == "" || server.Port <= 0 || server.Port > 65535 {
		res.Err = fmt.Errorf("invalid server %q:%d", server.Host, server.Port)
		return res
	}

	var resolver net.Resolver
	ips, err := resolver.LookupNetIP(ctx, "ip", server.Host)
	if err != nil {
		res.Err = fmt.Errorf("resolve %s: %w", server.Host, err)
		return res
	}
	if len(ips) == 0 {
		res.Err = fmt.Errorf("resolve %s: no addresses", server.Host)
		return res
	}
	ip := ips[0].Unmap()
	remote := &net.UDPAddr{IP: net.IP(ip.AsSlice()), Port: server.Port}

	network, listenAddr := "udp4", "0.0.0.0:0"
	if ip.Is6() {
		network, listenAddr = "udp6", "[::]:0"
	}

	connA, err := net.ListenPacket(network, listenAddr)
	if err != nil {
		res.Err = fmt.Errorf("listen socket A: %w", err)
		return res
	}
	defer func() { _ = connA.Close() }()

	connB, err := net.ListenPacket(network, listenAddr)
	if err != nil {
		res.Err = fmt.Errorf("listen socket B: %w", err)
		return res
	}
	defer func() { _ = connB.Close() }()

	perProbe := timeout / 2
	if perProbe <= 0 || perProbe > 500*time.Millisecond {
		perProbe = 500 * time.Millisecond
	}

	type probeOut struct {
		mapped netip.AddrPort
		err    error
	}
	aCh, bCh := make(chan probeOut, 1), make(chan probeOut, 1)
	probeSocket := func(c net.PacketConn, ch chan<- probeOut) {
		r, err := sendBindingAndWait(c, remote, perProbe, nil)
		if err != nil {
			ch <- probeOut{err: err}
			return
		}
		ch <- probeOut{mapped: r.mapped}
	}
	go probeSocket(connA, aCh)
	go probeSocket(connB, bCh)
	aRes, bRes := <-aCh, <-bCh
	if aRes.err != nil {
		res.Err = fmt.Errorf("STUN probe on socket A: %w", aRes.err)
		return res
	}
	if bRes.err != nil {
		res.Err = fmt.Errorf("STUN probe on socket B: %w", bRes.err)
		return res
	}
	if !bRes.mapped.IsValid() {
		res.Err = errors.New("STUN probe on socket B returned invalid mapped endpoint")
		return res
	}

	tag := make([]byte, 16)
	if _, err := rand.Read(tag); err != nil {
		res.Err = fmt.Errorf("generate hairpin tag: %w", err)
		return res
	}

	if err := send(ctx, connA, bRes.mapped, tag); err != nil {
		res.Err = fmt.Errorf("hairpin send A→mB: %w", err)
		return res
	}

	arrived, err := recv(ctx, connB, tag, timeout)
	if err != nil {
		res.Err = fmt.Errorf("hairpin listen on B: %w", err)
		return res
	}
	res.Detected = &arrived
	return res
}

func realHairpinSend(ctx context.Context, from net.PacketConn, to netip.AddrPort, tag []byte) error {
	if deadline, ok := ctx.Deadline(); ok {
		_ = from.SetWriteDeadline(deadline)
	}
	addr := net.UDPAddrFromAddrPort(to)
	_, err := from.WriteTo(tag, addr)
	return err
}

func realHairpinRecv(ctx context.Context, on net.PacketConn, tag []byte, timeout time.Duration) (bool, error) {
	end := time.Now().Add(timeout)
	if deadline, ok := ctx.Deadline(); ok && deadline.Before(end) {
		end = deadline
	}
	buf := make([]byte, 64)
	for {
		if time.Until(end) <= 0 {
			return false, nil
		}
		if err := on.SetReadDeadline(end); err != nil {
			return false, err
		}
		n, _, err := on.ReadFrom(buf)
		if err != nil {
			// Deadline expired or fatal error — treat as timeout, no hairpin.
			return false, nil
		}
		if bytes.Equal(buf[:n], tag) {
			return true, nil
		}
		// Unrelated packet on the socket; discard and keep listening.
	}
}
