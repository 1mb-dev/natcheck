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
// non-functional target at docs/design.md (<2s cold-start) is preserved
// for timeout ≤ 1s.
func ProbeHairpinning(ctx context.Context, server Server, timeout time.Duration) HairpinningResult {
	return probeHairpinning(ctx, server, timeout, realHairpinSend, realHairpinRecv)
}

// hairpinSender / hairpinReceiver abstract the tagged send + listen steps so
// tests can inject behavior that simulates a per-NAT filtering rule without
// requiring a real NAT in the localhost test environment. Production wires
// realHairpinSend / realHairpinRecv (real socket I/O). The spec at
// docs/design.md names the port-restricted-filtering false-negative as a
// required test case; this seam is how that test is expressed.
type hairpinSender func(ctx context.Context, from net.PacketConn, to netip.AddrPort, tag []byte) error
type hairpinReceiver func(ctx context.Context, on net.PacketConn, tag []byte, timeout time.Duration) (bool, error)

func probeHairpinning(ctx context.Context, server Server, timeout time.Duration, send hairpinSender, recv hairpinReceiver) HairpinningResult {
	if server.Host == "" || server.Port <= 0 || server.Port > 65535 {
		return HairpinningResult{Server: server, Err: fmt.Errorf("invalid server %q:%d", server.Host, server.Port)}
	}
	ips, err := resolveHost(ctx, server.Host)
	if err != nil {
		return HairpinningResult{Server: server, Err: fmt.Errorf("resolve %s: %w", server.Host, err)}
	}
	if len(ips) == 0 {
		return HairpinningResult{Server: server, Err: fmt.Errorf("resolve %s: no addresses", server.Host)}
	}
	return hairpinAddrs(ctx, server, ips, timeout, net.ListenPacket, send, recv)
}

// hairpinAddrs uses the first address whose sockets bind and send, as
// probeAddrs does for the mapping probe. Silence does not fall through: it has
// already spent the probe's wait. Nothing falls through once ctx is done.
func hairpinAddrs(ctx context.Context, server Server, ips []netip.Addr, timeout time.Duration,
	listen func(network, address string) (net.PacketConn, error), send hairpinSender, recv hairpinReceiver) HairpinningResult {
	res := HairpinningResult{Server: server}

	perProbe := timeout / 2
	if perProbe <= 0 || perProbe > 500*time.Millisecond {
		perProbe = 500 * time.Millisecond
	}

	var pair *hairpinPair
	var mappedB netip.AddrPort
	for i, ip := range ips {
		if i > 0 && ctx.Err() != nil {
			res.Err = fmt.Errorf("%w: %w", ctx.Err(), res.Err)
			return res
		}
		ip = ip.Unmap()
		p, err := listenPair(ctx, ip, listen)
		if err != nil {
			res.Err = err
			continue
		}
		mappedB, err = p.mappedB(net.UDPAddrFromAddrPort(netip.AddrPortFrom(ip, uint16(server.Port))), perProbe)
		if err == nil {
			pair = p
			break
		}
		p.close()
		res.Err = err
		if !errors.Is(err, errSendFailed) {
			return res
		}
	}
	if pair == nil {
		return res
	}
	defer pair.close()
	res.Err = nil

	tag := make([]byte, 16)
	if _, err := rand.Read(tag); err != nil {
		res.Err = fmt.Errorf("generate hairpin tag: %w", err)
		return res
	}

	if err := send(ctx, pair.a, mappedB, tag); err != nil {
		res.Err = fmt.Errorf("hairpin send A→mB: %w", err)
		return res
	}

	arrived, err := recv(ctx, pair.b, tag, timeout)
	if err != nil {
		res.Err = fmt.Errorf("hairpin listen on B: %w", err)
		return res
	}
	res.Detected = &arrived
	return res
}

// hairpinPair is sockets A and B in one address family.
type hairpinPair struct {
	a, b net.PacketConn
	done chan struct{}
}

// listenPair binds both sockets and bridges ctx.Done() to their deadlines, so
// a cancel-without-deadline context unblocks in-flight reads and writes
// promptly.
func listenPair(ctx context.Context, ip netip.Addr, listen func(network, address string) (net.PacketConn, error)) (*hairpinPair, error) {
	network, listenAddr := pickNetwork(ip)
	a, err := listen(network, listenAddr)
	if err != nil {
		return nil, fmt.Errorf("listen socket A: %w", err)
	}
	b, err := listen(network, listenAddr)
	if err != nil {
		_ = a.Close()
		return nil, fmt.Errorf("listen socket B: %w", err)
	}
	p := &hairpinPair{a: a, b: b, done: make(chan struct{})}
	go func() {
		select {
		case <-ctx.Done():
			_ = a.SetDeadline(time.Unix(1, 0))
			_ = b.SetDeadline(time.Unix(1, 0))
		case <-p.done:
		}
	}()
	return p, nil
}

// close stops the ctx bridge before closing the sockets.
func (p *hairpinPair) close() {
	close(p.done)
	_ = p.a.Close()
	_ = p.b.Close()
}

// mappedB STUN-probes both sockets in parallel and returns B's mapped endpoint.
func (p *hairpinPair) mappedB(remote net.Addr, perProbe time.Duration) (netip.AddrPort, error) {
	type probeOut struct {
		mapped netip.AddrPort
		err    error
	}
	probeSocket := func(c net.PacketConn, ch chan<- probeOut) {
		r, err := sendBindingAndWait(c, remote, perProbe, nil)
		if err != nil {
			ch <- probeOut{err: err}
			return
		}
		ch <- probeOut{mapped: r.mapped}
	}
	aCh, bCh := make(chan probeOut, 1), make(chan probeOut, 1)
	go probeSocket(p.a, aCh)
	go probeSocket(p.b, bCh)
	aRes, bRes := <-aCh, <-bCh
	if aRes.err != nil {
		return netip.AddrPort{}, fmt.Errorf("STUN probe on socket A: %w", aRes.err)
	}
	if bRes.err != nil {
		return netip.AddrPort{}, fmt.Errorf("STUN probe on socket B: %w", bRes.err)
	}
	if !bRes.mapped.IsValid() {
		return netip.AddrPort{}, errors.New("STUN probe on socket B returned invalid mapped endpoint")
	}
	return bRes.mapped, nil
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
