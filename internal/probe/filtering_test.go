package probe

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/1mb-dev/natcheck/internal/stunserver"
)

// corner identifies one of the four §3 listeners.
type corner int

const (
	cornerPrimary corner = iota // (IP1, port1)
	cornerAltPort               // (IP1, port2) — CHANGE-PORT
	cornerAltIP                 // (IP2, port1) — CHANGE-IP
	cornerAltBoth               // (IP2, port2) — CHANGE-IP|CHANGE-PORT
)

// fakeFilteringServer is a 4-corner §3 STUN responder for in-process tests.
// Per-corner dropPolicy controls whether responses from that corner are sent
// (simulates filtering NAT behavior on the client side).
//
// Corner indices: 0=primary (IP1,port1), 1=alt-port (IP1,port2),
// 2=alt-IP (IP2,port1), 3=alt-both (IP2,port2). Diagonal pairs: 0<->3, 1<->2.
// In loopback tests "IP1" and "IP2" both resolve to 127.0.0.1; the four corners
// differ only by port — sufficient for §4.4 routing semantics.
type fakeFilteringServer struct {
	conns        [4]net.PacketConn
	addrs        [4]netip.AddrPort
	dropFrom     map[corner]bool
	mu           sync.Mutex
	respondCount int
	noiseAfter   int // if > 0, dispatcher injects one bogus-TXID packet after the Nth real response
	done         chan struct{}
	wg           sync.WaitGroup
}

// setNoiseAfter wires the regression-test knob: after the Nth real response,
// the dispatcher injects one bogus-TXID packet to the client. Mutex-protected
// so the dispatcher's read is race-free.
func (f *fakeFilteringServer) setNoiseAfter(n int) {
	f.mu.Lock()
	f.noiseAfter = n
	f.mu.Unlock()
}

// newFakeFilteringServer binds 4 loopback sockets and starts a single reader
// goroutine per conn plus a dispatcher that routes incoming requests per
// RFC 5780 §3 / §4.4.
func newFakeFilteringServer(t *testing.T, dropFrom ...corner) *fakeFilteringServer {
	t.Helper()
	f := &fakeFilteringServer{
		dropFrom: make(map[corner]bool),
		done:     make(chan struct{}),
	}
	for _, c := range dropFrom {
		f.dropFrom[c] = true
	}
	for i := range f.conns {
		c, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen %d: %v", i, err)
		}
		f.conns[i] = c
		u := c.LocalAddr().(*net.UDPAddr)
		a, _ := netip.AddrFromSlice(u.IP)
		f.addrs[i] = netip.AddrPortFrom(a.Unmap(), uint16(u.Port))
	}
	f.wg.Add(1)
	go f.serve()
	t.Cleanup(func() {
		close(f.done)
		for _, c := range f.conns {
			_ = c.Close()
		}
		f.wg.Wait()
	})
	return f
}

func (f *fakeFilteringServer) primaryServer() Server {
	return Server{Host: "127.0.0.1", Port: int(f.addrs[cornerPrimary].Port())}
}

// otherFor returns the diagonal corner's address for OTHER-ADDRESS in responses
// originating from the given corner. Diagonal pairs: 0<->3, 1<->2.
func (f *fakeFilteringServer) otherFor(c corner) netip.AddrPort {
	diagonal := []corner{cornerAltBoth, cornerAltIP, cornerAltPort, cornerPrimary}
	return f.addrs[diagonal[c]]
}

func (f *fakeFilteringServer) serve() {
	defer f.wg.Done()
	type packet struct {
		from corner
		data []byte
		src  net.Addr
	}
	ch := make(chan packet, 16)
	// Per-conn read pumps; tracked in f.wg so Cleanup waits for them.
	for i, c := range f.conns {
		i, c := corner(i), c
		f.wg.Add(1)
		go func() {
			defer f.wg.Done()
			buf := make([]byte, 1500)
			for {
				_ = c.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
				n, src, err := c.ReadFrom(buf)
				if err != nil {
					select {
					case <-f.done:
						return
					default:
						continue
					}
				}
				cp := append([]byte{}, buf[:n]...)
				select {
				case ch <- packet{from: i, data: cp, src: src}:
				case <-f.done:
					return
				}
			}
		}()
	}
	for {
		select {
		case <-f.done:
			return
		case p := <-ch:
			f.dispatch(p.from, p.data, p.src)
		}
	}
}

// dispatch parses CHANGE-REQUEST on the inbound packet, routes the response
// to the correct outbound corner per RFC 5780 §3, and writes from that corner.
func (f *fakeFilteringServer) dispatch(received corner, data []byte, src net.Addr) {
	changeIP, changePort, ok := stunserver.ParseChangeRequest(data)
	target := received
	if ok {
		switch {
		case changeIP && changePort:
			target = altIPAltPortFrom(received)
		case changeIP:
			target = altIPFrom(received)
		case changePort:
			target = altPortFrom(received)
		}
	}
	f.respond(target, data, src)
}

// respond builds the response on `target`'s Server (so OTHER-ADDRESS reflects
// target's diagonal) and writes from `target`'s conn — unless dropFrom[target].
// If noiseAfter is set, injects one packet that fails STUN Decode after the
// Nth real response (used by TestProbeFiltering_StalePacketDoesNotPollute).
func (f *fakeFilteringServer) respond(target corner, data []byte, src net.Addr) {
	if f.dropFrom[target] {
		return
	}
	udp, ok := src.(*net.UDPAddr)
	if !ok {
		return
	}
	ipa, _ := netip.AddrFromSlice(udp.IP)
	srcAP := netip.AddrPortFrom(ipa.Unmap(), uint16(udp.Port))
	s := stunserver.New(stunserver.Options{Other: f.otherFor(target)})
	resp := s.Handle(data, srcAP)
	if resp == nil {
		return
	}
	_, _ = f.conns[target].WriteTo(resp, src)

	f.mu.Lock()
	f.respondCount++
	count := f.respondCount
	noise := f.noiseAfter
	f.mu.Unlock()
	if noise > 0 && count == noise {
		// Send a bogus packet that fails STUN Decode. sendBindingAndWait must
		// loop on the decode failure and read the next packet within deadline.
		junk := []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
		_, _ = f.conns[target].WriteTo(junk, src)
	}
}

// Corner-routing helpers. Indexed by inbound corner; value is the outbound
// corner that should send the response. Per RFC 5780 §3, "alt-IP" flips IP1↔IP2,
// "alt-port" flips port1↔port2, "alt-IP+alt-port" flips both (= the diagonal).
//
// Corner numbering (see fakeFilteringServer doc): 0=primary, 1=alt-port,
// 2=alt-IP, 3=alt-both. Diagonals: 0↔3, 1↔2.
//
//	inbound:           0  1  2  3
//	alt-IP only:       2  3  0  1   (flip IP)
//	alt-port only:     1  0  3  2   (flip port)
//	alt-IP+alt-port:   3  2  1  0   (flip both = diagonal)
func altIPFrom(c corner) corner {
	return [4]corner{cornerAltIP, cornerAltBoth, cornerPrimary, cornerAltPort}[c]
}
func altPortFrom(c corner) corner {
	return [4]corner{cornerAltPort, cornerPrimary, cornerAltBoth, cornerAltIP}[c]
}
func altIPAltPortFrom(c corner) corner {
	return [4]corner{cornerAltBoth, cornerAltIP, cornerAltPort, cornerPrimary}[c]
}

// --- tests ---

func TestProbeFiltering_EndpointIndependent(t *testing.T) {
	f := newFakeFilteringServer(t) // no drops
	res := ProbeFiltering(context.Background(), f.primaryServer(), 2*time.Second)
	if res.Err != nil {
		t.Fatalf("Err = %v, want nil", res.Err)
	}
	if !res.Test2Received || !res.Test3Received {
		t.Fatalf("got Test2=%v Test3=%v, want both true", res.Test2Received, res.Test3Received)
	}
	if !res.Test1Other.IsValid() {
		t.Fatal("Test1Other should be set")
	}
}

func TestProbeFiltering_AddressDependent(t *testing.T) {
	// Drop responses from the alt-IP+alt-port corner (Test 2's target).
	f := newFakeFilteringServer(t, cornerAltBoth)
	res := ProbeFiltering(context.Background(), f.primaryServer(), 2*time.Second)
	if res.Err != nil {
		t.Fatalf("Err = %v, want nil", res.Err)
	}
	if res.Test2Received {
		t.Fatal("Test2 received; want dropped")
	}
	if !res.Test3Received {
		t.Fatal("Test3 not received; want received")
	}
}

func TestProbeFiltering_AddressAndPortDependent(t *testing.T) {
	f := newFakeFilteringServer(t, cornerAltBoth, cornerAltPort)
	res := ProbeFiltering(context.Background(), f.primaryServer(), 2*time.Second)
	if res.Err != nil {
		t.Fatalf("Err = %v, want nil", res.Err)
	}
	if res.Test2Received || res.Test3Received {
		t.Fatalf("got Test2=%v Test3=%v, want both false", res.Test2Received, res.Test3Received)
	}
}

func TestProbeFiltering_NoOtherAddress(t *testing.T) {
	// Bind a single conn that responds without OTHER-ADDRESS (phase-1 stunserver).
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = stunserver.New(stunserver.Options{}).Serve(ctx, conn) }()
	port := conn.LocalAddr().(*net.UDPAddr).Port

	res := ProbeFiltering(context.Background(), Server{Host: "127.0.0.1", Port: port}, time.Second)
	if !errors.Is(res.Err, ErrFilteringNotSupported) {
		t.Fatalf("Err = %v, want ErrFilteringNotSupported", res.Err)
	}
	if res.Test2Received || res.Test3Received {
		t.Fatal("Test2/3 should be false when not supported")
	}
}

func TestProbeFiltering_Test1Failed(t *testing.T) {
	// Grab a port then free it.
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := conn.LocalAddr().(*net.UDPAddr).Port
	_ = conn.Close()

	res := ProbeFiltering(context.Background(), Server{Host: "127.0.0.1", Port: port}, 200*time.Millisecond)
	if !errors.Is(res.Err, ErrTest1Failed) {
		t.Fatalf("Err = %v, want ErrTest1Failed", res.Err)
	}
}

func TestProbeFiltering_InvalidServer(t *testing.T) {
	res := ProbeFiltering(context.Background(), Server{Host: "", Port: 3478}, time.Second)
	if res.Err == nil {
		t.Fatal("expected error for empty host")
	}
}

func TestProbeFiltering_ZeroTimeoutFallsBack(t *testing.T) {
	// timeout=0 must not hang; sendBindingAndWait falls back to 500ms per test.
	f := newFakeFilteringServer(t)
	start := time.Now()
	res := ProbeFiltering(context.Background(), f.primaryServer(), 0)
	if res.Err != nil {
		t.Fatalf("Err = %v, want nil", res.Err)
	}
	// Worst case: 3 tests × 500ms each = 1.5s; loopback should be much faster.
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("elapsed %v exceeds fallback budget", elapsed)
	}
}

func TestProbeFiltering_CtxCancelAfterDial(t *testing.T) {
	// Per godoc: ctx governs dial only. A cancel after dial does NOT abort.
	f := newFakeFilteringServer(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancelled := make(chan struct{})
	go func() {
		time.Sleep(10 * time.Millisecond)
		cancel()
		close(cancelled)
	}()
	res := ProbeFiltering(ctx, f.primaryServer(), 2*time.Second)
	<-cancelled
	if res.Err != nil {
		t.Fatalf("Err = %v; ctx cancellation after dial must not abort", res.Err)
	}
}

func TestProbeFiltering_StalePacketDoesNotPollute(t *testing.T) {
	// Regression: late response from a prior test must not cause Test 3 to
	// record "no response". sendBindingAndWait must discard mismatched-TXID
	// packets and keep reading within the deadline.
	//
	// Setup: noiseAfter=2 means the dispatcher sends a junk packet to the
	// client immediately after answering Test 2 — that junk packet sits in the
	// kernel buffer when Test 3 starts reading. With the loop-on-mismatch fix,
	// sendBindingAndWait discards the junk and keeps reading for Test 3's
	// real response.
	f := newFakeFilteringServer(t)
	f.setNoiseAfter(2)
	res := ProbeFiltering(context.Background(), f.primaryServer(), 2*time.Second)
	if res.Err != nil {
		t.Fatalf("Err = %v", res.Err)
	}
	if !res.Test2Received || !res.Test3Received {
		t.Fatalf("Test2=%v Test3=%v; baseline must be EIF even with noise injection", res.Test2Received, res.Test3Received)
	}
}
