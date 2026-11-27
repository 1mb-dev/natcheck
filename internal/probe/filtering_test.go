package probe

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/1mb-dev/natcheck/internal/stunserver"
	"github.com/pion/stun/v3"
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
	noiseAfter   int                                   // if > 0, dispatcher injects one bogus-TXID packet after the Nth real response
	lost         map[[stun.TransactionIDSize]byte]bool // non-nil: lose the first copy of each CHANGE-REQUEST
	received     []request                             // every request, in arrival order
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

// loseFirstChangeRequests makes the server drop the first copy of each
// CHANGE-REQUEST transaction, as one lost packet per test would.
func (f *fakeFilteringServer) loseFirstChangeRequests() {
	f.mu.Lock()
	f.lost = map[[stun.TransactionIDSize]byte]bool{}
	f.mu.Unlock()
}

// loses reports whether data is the first copy of a CHANGE-REQUEST transaction
// while loseFirstChangeRequests is on.
func (f *fakeFilteringServer) loses(data []byte) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.lost == nil {
		return false
	}
	m := &stun.Message{Raw: append([]byte{}, data...)}
	if m.Decode() != nil || f.lost[m.TransactionID] {
		return false
	}
	f.lost[m.TransactionID] = true
	return true
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

// probeFiltering runs ProbeFiltering on s, which must name a literal IP.
func probeFiltering(s Server, timeout time.Duration) FilteringResult {
	return ProbeFiltering(s, netip.AddrPortFrom(netip.MustParseAddr(s.Host), uint16(s.Port)), timeout)
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
	f.mu.Lock()
	f.received = append(f.received, request{at: received, change: ok})
	f.mu.Unlock()
	target := received
	if ok && f.loses(data) {
		return
	}
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

type request struct {
	at     corner
	change bool // carried CHANGE-REQUEST
}

func (f *fakeFilteringServer) requests() []request {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]request(nil), f.received...)
}

// --- tests ---

func TestProbeFiltering_EndpointIndependent(t *testing.T) {
	f := newFakeFilteringServer(t) // no drops
	res := probeFiltering(f.primaryServer(), 2*time.Second)
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
	res := probeFiltering(f.primaryServer(), 2*time.Second)
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
	res := probeFiltering(f.primaryServer(), 2*time.Second)
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

	res := probeFiltering(Server{Host: "127.0.0.1", Port: port}, time.Second)
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

	res := probeFiltering(Server{Host: "127.0.0.1", Port: port}, 200*time.Millisecond)
	if !errors.Is(res.Err, ErrTest1Failed) {
		t.Fatalf("Err = %v, want ErrTest1Failed", res.Err)
	}
}

func TestProbeFiltering_InvalidTarget(t *testing.T) {
	for _, target := range []netip.AddrPort{
		{},
		netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), 0),
	} {
		res := ProbeFiltering(Server{Host: "h", Port: 3478}, target, time.Second)
		if res.Err == nil || errors.Is(res.Err, ErrTest1Failed) {
			t.Errorf("target %v: Err = %v, want rejection before any send", target, res.Err)
		}
	}
}

func TestProbeFiltering_ZeroTimeoutFallsBack(t *testing.T) {
	// timeout=0 must not hang; sendBindingAndWait falls back to 500ms per test.
	f := newFakeFilteringServer(t)
	start := time.Now()
	res := probeFiltering(f.primaryServer(), 0)
	if res.Err != nil {
		t.Fatalf("Err = %v, want nil", res.Err)
	}
	// Worst case: five windows of 500ms = 2.5s; loopback should be much faster.
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("elapsed %v exceeds fallback budget", elapsed)
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
	res := probeFiltering(f.primaryServer(), 2*time.Second)
	if res.Err != nil {
		t.Fatalf("Err = %v", res.Err)
	}
	if !res.Test2Received || !res.Test3Received {
		t.Fatalf("Test2=%v Test3=%v; baseline must be EIF even with noise injection", res.Test2Received, res.Test3Received)
	}
}

// TestProbeFiltering_ResendsLostChangeRequests: with the first copy of Tests 2
// and 3 lost, a resend of the same transaction gets its answer at cli's cap
// (1.5s, a 750ms window). At 1s the 500ms window ends before the resend, so the
// loss reads as not received. A new transaction ID would be lost too.
func TestProbeFiltering_ResendsLostChangeRequests(t *testing.T) {
	for _, tc := range []struct {
		budget time.Duration
		want   bool
	}{{1500 * time.Millisecond, true}, {time.Second, false}} {
		t.Run(tc.budget.String(), func(t *testing.T) {
			f := newFakeFilteringServer(t)
			f.loseFirstChangeRequests()
			res := probeFiltering(f.primaryServer(), tc.budget)
			if res.Err != nil {
				t.Fatalf("Err = %v, want nil", res.Err)
			}
			if res.Test2Received != tc.want || res.Test3Received != tc.want {
				t.Fatalf("Test2=%v Test3=%v, want both %v", res.Test2Received, res.Test3Received, tc.want)
			}
		})
	}
}

// failAfterReplyConn passes I/O through until a read returns a packet, then
// fails every call to the method named by fail: Test 1 completes and Tests 2
// and 3 cannot read or send.
type failAfterReplyConn struct {
	net.PacketConn
	fail    string
	mu      sync.Mutex
	replied bool
	started int // SetWriteDeadline calls once failing: one per test started
}

var (
	errWriteTo          = errors.New("write failed")
	errSetWriteDeadline = errors.New("set write deadline failed")
)

func (c *failAfterReplyConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, addr, err := c.PacketConn.ReadFrom(b)
	if err == nil {
		c.mu.Lock()
		c.replied = true
		c.mu.Unlock()
	}
	return n, addr, err
}

func (c *failAfterReplyConn) failing() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.replied
}

func (c *failAfterReplyConn) SetReadDeadline(t time.Time) error {
	if c.fail == "SetReadDeadline" && c.failing() {
		return errSetDeadline
	}
	return c.PacketConn.SetReadDeadline(t)
}

func (c *failAfterReplyConn) SetWriteDeadline(t time.Time) error {
	if c.failing() {
		c.mu.Lock()
		c.started++
		c.mu.Unlock()
	}
	if c.fail == "SetWriteDeadline" && c.failing() {
		return errSetWriteDeadline
	}
	return c.PacketConn.SetWriteDeadline(t)
}

func (c *failAfterReplyConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	if c.fail == "WriteTo" && c.failing() {
		return 0, errWriteTo
	}
	return c.PacketConn.WriteTo(b, addr)
}

// TestProbeFiltering_LocalFaultIsNotFiltering: a Test 2/3 read or send that
// fails is neither silence (a filtering verdict) nor ErrFilteringNotSupported.
func TestProbeFiltering_LocalFaultIsNotFiltering(t *testing.T) {
	for _, tc := range []struct {
		fail string
		want error
	}{
		{"SetReadDeadline", errSetDeadline},
		{"SetWriteDeadline", errSetWriteDeadline},
		{"WriteTo", errWriteTo},
	} {
		t.Run(tc.fail, func(t *testing.T) {
			f := newFakeFilteringServer(t)
			s := f.primaryServer()
			var conn *failAfterReplyConn
			listen := func(network, address string) (net.PacketConn, error) {
				c, err := net.ListenPacket(network, address)
				if err != nil {
					return nil, err
				}
				conn = &failAfterReplyConn{PacketConn: c, fail: tc.fail}
				return conn, nil
			}
			res := probeFilteringWith(listen, s, netip.AddrPortFrom(netip.MustParseAddr(s.Host), uint16(s.Port)), time.Second)
			if !errors.Is(res.Err, tc.want) || errors.Is(res.Err, ErrFilteringNotSupported) || errors.Is(res.Err, ErrTest1Failed) {
				t.Fatalf("Err = %v, want %v alone", res.Err, tc.want)
			}
			if res.Test2Received || res.Test3Received {
				t.Errorf("Test2Received = %v, Test3Received = %v; want false, false", res.Test2Received, res.Test3Received)
			}
			conn.mu.Lock()
			started := conn.started
			conn.mu.Unlock()
			if started != 2 {
				t.Errorf("%d tests started after the fault, want Tests 2 and 3 only: Tests II and III ran", started)
			}
		})
	}
}

// startChangeIgnoringServer advertises other as OTHER-ADDRESS but always replies
// from its own address. reply decides which requests get an answer.
func startChangeIgnoringServer(t *testing.T, other netip.AddrPort, reply func(req []byte) bool) Server {
	t.Helper()
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	srv := stunserver.New(stunserver.Options{Other: other})
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			if !reply(buf[:n]) {
				continue
			}
			udp := from.(*net.UDPAddr)
			if resp := srv.Handle(buf[:n], udp.AddrPort()); resp != nil {
				_, _ = conn.WriteTo(resp, from)
			}
		}
	}()
	return Server{Host: "127.0.0.1", Port: conn.LocalAddr().(*net.UDPAddr).Port}
}

func TestProbeFiltering_ServerIgnoresChangeRequest(t *testing.T) {
	tests := []struct {
		name  string
		reply func(req []byte) bool
	}{
		{"answers every test from its own address", func([]byte) bool { return true }},
		{"answers only test 3 from its own address", func(req []byte) bool {
			changeIP, changePort, ok := stunserver.ParseChangeRequest(req)
			return !ok || (changePort && !changeIP)
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := startChangeIgnoringServer(t, netip.MustParseAddrPort("198.51.100.1:3479"), tt.reply)
			res := probeFiltering(server, 300*time.Millisecond)
			if !errors.Is(res.Err, ErrFilteringNotSupported) {
				t.Fatalf("Err = %v, want ErrFilteringNotSupported; T2=%v T3=%v", res.Err, res.Test2Received, res.Test3Received)
			}
			if res.Test2Received || res.Test3Received {
				t.Errorf("T2=%v T3=%v, want neither counted", res.Test2Received, res.Test3Received)
			}
		})
	}
}

func TestProbeFiltering_ServerRejectsChangeRequest(t *testing.T) {
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = conn.Close() }()
	srv := stunserver.New(stunserver.Options{Other: netip.MustParseAddrPort("198.51.100.1:3479")})
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			if _, _, change := stunserver.ParseChangeRequest(buf[:n]); !change {
				_, _ = conn.WriteTo(srv.Handle(buf[:n], from.(*net.UDPAddr).AddrPort()), from)
				continue
			}
			req := &stun.Message{Raw: append([]byte{}, buf[:n]...)}
			if req.Decode() != nil {
				continue
			}
			resp, err := stun.Build(stun.NewTransactionIDSetter(req.TransactionID), stun.BindingError)
			if err == nil {
				_, _ = conn.WriteTo(resp.Raw, from)
			}
		}
	}()

	server := Server{Host: "127.0.0.1", Port: conn.LocalAddr().(*net.UDPAddr).Port}
	res := probeFiltering(server, 300*time.Millisecond)
	if !errors.Is(res.Err, ErrFilteringNotSupported) {
		t.Fatalf("Err = %v, want ErrFilteringNotSupported; T2=%v T3=%v", res.Err, res.Test2Received, res.Test3Received)
	}
}

func TestProbeFiltering_Test2ReplyMustChangeIP(t *testing.T) {
	primary, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = primary.Close() }()
	altPort, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = altPort.Close() }()

	srv := stunserver.New(stunserver.Options{Other: netip.MustParseAddrPort("198.51.100.1:3479")})
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := primary.ReadFrom(buf)
			if err != nil {
				return
			}
			out := primary
			if _, _, change := stunserver.ParseChangeRequest(buf[:n]); change {
				out = altPort
			}
			_, _ = out.WriteTo(srv.Handle(buf[:n], from.(*net.UDPAddr).AddrPort()), from)
		}
	}()

	server := Server{Host: "127.0.0.1", Port: primary.LocalAddr().(*net.UDPAddr).Port}
	res := probeFiltering(server, 300*time.Millisecond)
	if !errors.Is(res.Err, ErrFilteringNotSupported) {
		t.Fatalf("Err = %v, want ErrFilteringNotSupported; T2=%v T3=%v", res.Err, res.Test2Received, res.Test3Received)
	}
}

func TestChangeRequestIgnored(t *testing.T) {
	const (
		target    = "192.0.2.1:3478"
		altPort   = "192.0.2.1:3479"
		altIP     = "198.51.100.1:3479"
		loopback  = "127.0.0.1:3478"
		loopOther = "127.0.0.1:3479"
	)
	reply := func(source string) *bindingResult {
		if source == "" {
			return nil
		}
		return &bindingResult{source: netip.MustParseAddrPort(source)}
	}
	tests := []struct {
		name   string
		target string
		other  string
		t2, t3 string
		want   bool
	}{
		{"no replies", target, altIP, "", "", false},
		{"honored", target, altIP, altIP, altPort, false},
		{"test 2 from an unadvertised new IP", target, altIP, "203.0.113.9:3479", altPort, false},
		{"test 2 from the target", target, altIP, target, altPort, true},
		{"test 2 from the target IP on another port", target, altIP, altPort, altPort, true},
		{"test 2 from an OTHER-ADDRESS on the target IP", target, altPort, altPort, altPort, true},
		{"test 3 from the target", target, altIP, "", target, true},
		{"loopback rig replying from OTHER-ADDRESS", loopback, loopOther, loopOther, "", false},
		{"loopback reply not from OTHER-ADDRESS", loopback, loopOther, "127.0.0.1:3480", "", true},
		{"loopback test 3 from the target", loopback, loopOther, loopOther, loopback, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := changeRequestIgnored(netip.MustParseAddrPort(tt.target), netip.MustParseAddrPort(tt.other), reply(tt.t2), reply(tt.t3))
			if got != tt.want {
				t.Errorf("changeRequestIgnored = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestProbeFiltering_MappingTests: Tests II and III go to OTHER-ADDRESS's IP
// with the primary port, then to OTHER-ADDRESS, and only after Tests 2 and 3.
// A request to OTHER-ADDRESS first would open an address-dependent filter for
// Test 2's reply.
func TestProbeFiltering_MappingTests(t *testing.T) {
	f := newFakeFilteringServer(t)
	res := probeFiltering(f.primaryServer(), 2*time.Second)
	if res.Err != nil {
		t.Fatalf("Err = %v, want nil", res.Err)
	}
	// Loopback has no NAT, so every test maps to the same endpoint.
	if res.AltIPMapped != res.Test1Mapped || res.AltEndpointMapped != res.Test1Mapped {
		t.Fatalf("AltIPMapped = %v, AltEndpointMapped = %v, want both %v", res.AltIPMapped, res.AltEndpointMapped, res.Test1Mapped)
	}

	// On loopback OTHER-ADDRESS's IP is the primary IP, so Test II lands on
	// the primary corner.
	want := []request{{cornerPrimary, false}, {cornerPrimary, true}, {cornerPrimary, true}, {cornerPrimary, false}, {cornerAltBoth, false}}
	if got := f.requests(); !slices.Equal(got, want) {
		t.Fatalf("requests = %v, want %v", got, want)
	}
}

func TestProbeFiltering_MappingTestsNeedBothReplies(t *testing.T) {
	// Test III goes to the alt-both corner, which never answers.
	f := newFakeFilteringServer(t, cornerAltBoth)
	res := probeFiltering(f.primaryServer(), time.Second)
	if res.AltIPMapped.IsValid() || res.AltEndpointMapped.IsValid() {
		t.Fatalf("AltIPMapped = %v, AltEndpointMapped = %v, want both zero", res.AltIPMapped, res.AltEndpointMapped)
	}
}

// TestProbeFiltering_MappingTestsAfterIgnoredChangeRequest: Tests II and III run
// when the server ignored CHANGE-REQUEST, and Test III is not sent when Test II
// gets no reply.
func TestProbeFiltering_MappingTestsAfterIgnoredChangeRequest(t *testing.T) {
	for _, tc := range []struct {
		name   string
		testII bool // the server answers plain requests after Test 1
	}{
		{"both answered", true},
		{"Test II silent", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var atOther atomic.Int32
			alt := startChangeIgnoringServer(t, netip.MustParseAddrPort("198.51.100.1:3479"), func([]byte) bool {
				atOther.Add(1)
				return true
			})
			var plain atomic.Int32
			other := netip.AddrPortFrom(netip.MustParseAddr(alt.Host), uint16(alt.Port))
			server := startChangeIgnoringServer(t, other, func(req []byte) bool {
				if _, _, change := stunserver.ParseChangeRequest(req); change {
					return true
				}
				return plain.Add(1) == 1 || tc.testII
			})
			res := probeFiltering(server, 300*time.Millisecond)
			if !errors.Is(res.Err, ErrFilteringNotSupported) {
				t.Fatalf("Err = %v, want ErrFilteringNotSupported", res.Err)
			}
			if got := res.AltIPMapped.IsValid() && res.AltEndpointMapped.IsValid(); got != tc.testII {
				t.Errorf("AltIPMapped = %v, AltEndpointMapped = %v, want both set = %v", res.AltIPMapped, res.AltEndpointMapped, tc.testII)
			}
			if !tc.testII && atOther.Load() != 0 {
				t.Errorf("Test III sent after a silent Test II (%d requests at OTHER-ADDRESS)", atOther.Load())
			}
		})
	}
}

// TestSendBindingAndWait_SilenceEndsAtWindow: a test whose peer never answers
// returns no response, and no read waits past its window, resends included.
func TestSendBindingAndWait_SilenceEndsAtWindow(t *testing.T) {
	for _, window := range []time.Duration{100 * time.Millisecond, 700 * time.Millisecond} {
		t.Run(window.String(), func(t *testing.T) {
			t.Parallel()
			silent, err := net.ListenPacket("udp4", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("listen: %v", err)
			}
			defer func() { _ = silent.Close() }()
			c, err := net.ListenPacket("udp4", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("listen: %v", err)
			}
			conn := &deadlineLogConn{PacketConn: c}
			defer func() { _ = conn.Close() }()
			_, err = sendBindingAndWait(context.Background(), conn, silent.LocalAddr(), window, nil)
			if !errors.Is(err, errNoResponse) {
				t.Fatalf("err = %v, want errNoResponse", err)
			}
			conn.mu.Lock()
			defer conn.mu.Unlock()
			if len(conn.deadlines) == 0 {
				t.Fatal("no read deadline set")
			}
			// The window opens before the first send, so no deadline may pass
			// firstSend + window.
			for _, d := range conn.deadlines {
				if over := d.Sub(conn.firstSend) - window; over > 0 {
					t.Errorf("read deadline %v past the %v window", over, window)
				}
			}
		})
	}
}

// deadlineLogConn records when it first sends and every read deadline set.
type deadlineLogConn struct {
	net.PacketConn
	mu        sync.Mutex
	firstSend time.Time
	deadlines []time.Time
}

func (c *deadlineLogConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	c.mu.Lock()
	if c.firstSend.IsZero() {
		c.firstSend = time.Now()
	}
	c.mu.Unlock()
	return c.PacketConn.WriteTo(b, addr)
}

func (c *deadlineLogConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.deadlines = append(c.deadlines, t)
	c.mu.Unlock()
	return c.PacketConn.SetReadDeadline(t)
}

func TestMappingTestAllowed(t *testing.T) {
	public := netip.MustParseAddrPort("203.0.113.10:3478")
	private := netip.MustParseAddrPort("192.168.1.10:3478")
	loopback := netip.MustParseAddrPort("127.0.0.1:3478")
	publicV6 := netip.MustParseAddrPort("[2001:db8::10]:3478")
	cases := []struct {
		name          string
		target, other netip.AddrPort
		want          bool
	}{
		{"public target, public other", public, netip.MustParseAddrPort("203.0.113.11:3479"), true},
		{"other shares the IP, new port", public, netip.MustParseAddrPort("203.0.113.10:3479"), true},
		{"private target, private other", private, netip.MustParseAddrPort("192.168.1.11:3479"), true},
		{"loopback target, loopback other", loopback, netip.MustParseAddrPort("127.0.0.1:3479"), true},
		{"other on the target's port", public, netip.MustParseAddrPort("203.0.113.11:3478"), false},
		{"other port zero", public, netip.MustParseAddrPort("203.0.113.11:0"), false},
		{"other in another family", public, netip.MustParseAddrPort("[2001:db8::1]:3479"), false},
		{"public target, private other", public, netip.MustParseAddrPort("192.168.1.11:3479"), false},
		{"public target, loopback other", public, netip.MustParseAddrPort("127.0.0.1:3479"), false},
		{"public target, link-local other", public, netip.MustParseAddrPort("169.254.1.1:3479"), false},
		{"loopback target, public other", loopback, netip.MustParseAddrPort("203.0.113.11:3479"), false},
		{"multicast other", public, netip.MustParseAddrPort("224.0.0.1:3479"), false},
		{"unspecified other", public, netip.MustParseAddrPort("0.0.0.0:3479"), false},
		{"no other", public, netip.AddrPort{}, false},
		{"public target, shared-address other", public, netip.MustParseAddrPort("100.100.1.5:3479"), false},
		{"shared-address target, shared-address other", netip.MustParseAddrPort("100.64.0.10:3478"), netip.MustParseAddrPort("100.100.1.5:3479"), true},
		{"shared-address target, benchmark other", netip.MustParseAddrPort("100.64.0.10:3478"), netip.MustParseAddrPort("198.18.0.1:3479"), false},
		{"public target, this-network other", public, netip.MustParseAddrPort("0.1.2.3:3479"), false},
		{"public target, IETF protocol other", public, netip.MustParseAddrPort("192.0.0.9:3479"), false},
		{"public target, benchmark other", public, netip.MustParseAddrPort("198.18.0.1:3479"), false},
		{"public target, reserved other", public, netip.MustParseAddrPort("240.0.0.1:3479"), false},
		{"public target, broadcast other", public, netip.MustParseAddrPort("255.255.255.255:3479"), false},
		{"public IPv6 target, public IPv6 other", publicV6, netip.MustParseAddrPort("[2001:db8::11]:3479"), true},
		{"public IPv6 target, NAT64 other", publicV6, netip.MustParseAddrPort("[64:ff9b::a00:1]:3479"), false},
		{"public IPv6 target, local NAT64 other", publicV6, netip.MustParseAddrPort("[64:ff9b:1::a00:1]:3479"), false},
		{"public IPv6 target, Teredo other", publicV6, netip.MustParseAddrPort("[2001:0:a00:1::1]:3479"), false},
		{"public IPv6 target, 6to4 other", publicV6, netip.MustParseAddrPort("[2002:a00:1::1]:3479"), false},
		{"public IPv6 target, site-local other", publicV6, netip.MustParseAddrPort("[fec0::1]:3479"), false},
		{"public IPv6 target, IPv4-compatible other", publicV6, netip.MustParseAddrPort("[::a00:1]:3479"), false},
		{"public IPv6 target, SIIT other", publicV6, netip.MustParseAddrPort("[::ffff:0:a00:1]:3479"), false},
		{"public IPv6 target, discard-only other", publicV6, netip.MustParseAddrPort("[100::1]:3479"), false},
		{"public IPv6 target, IETF protocol other", publicV6, netip.MustParseAddrPort("[2001:2::1]:3479"), false},
		{"IETF protocol target, IETF protocol other", netip.MustParseAddrPort("[2001:2::10]:3478"), netip.MustParseAddrPort("[2001:2::11]:3479"), true},
		{"IPv6 loopback target, loopback other", netip.MustParseAddrPort("[::1]:3478"), netip.MustParseAddrPort("[::1]:3479"), true},
		{"NAT64 target, NAT64 other", netip.MustParseAddrPort("[64:ff9b::cb00:710a]:3478"), netip.MustParseAddrPort("[64:ff9b::a00:1]:3479"), false},
		{"6to4 target, 6to4 other", netip.MustParseAddrPort("[2002:cb00:710a::1]:3478"), netip.MustParseAddrPort("[2002:a00:1::1]:3479"), false},
		{"NAT64 target, public IPv6 other", netip.MustParseAddrPort("[64:ff9b::cb00:710a]:3478"), netip.MustParseAddrPort("[2001:db8::11]:3479"), true},
		{"unspecified target, public other", netip.MustParseAddrPort("0.0.0.0:3478"), netip.MustParseAddrPort("203.0.113.11:3479"), false},
		{"Teredo target, public IPv6 other", netip.MustParseAddrPort("[2001:0:cb00:710a::1]:3478"), netip.MustParseAddrPort("[2001:db8::11]:3479"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := mappingTestAllowed(tc.target, tc.other); got != tc.want {
				t.Errorf("mappingTestAllowed(%v, %v) = %v, want %v", tc.target, tc.other, got, tc.want)
			}
		})
	}
}
