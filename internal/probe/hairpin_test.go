package probe

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/1mb-dev/natcheck/internal/stunserver"
)

// fakeStunEcho is a single-corner STUN responder used by hairpin tests. It
// only does what hairpinning needs: reply with XOR-MAPPED-ADDRESS for the
// observed source. No CHANGE-REQUEST handling, no alt-address.
type fakeStunEcho struct {
	conn net.PacketConn
	addr netip.AddrPort
	done chan struct{}
}

func newFakeStunEcho(t *testing.T) *fakeStunEcho {
	t.Helper()
	c, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen fake STUN: %v", err)
	}
	u := c.LocalAddr().(*net.UDPAddr)
	a, _ := netip.AddrFromSlice(u.IP)
	f := &fakeStunEcho{
		conn: c,
		addr: netip.AddrPortFrom(a.Unmap(), uint16(u.Port)),
		done: make(chan struct{}),
	}
	go f.serve()
	t.Cleanup(func() {
		close(f.done)
		_ = c.Close()
	})
	return f
}

func (f *fakeStunEcho) serve() {
	buf := make([]byte, 1500)
	s := stunserver.New(stunserver.Options{})
	for {
		_ = f.conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		n, src, err := f.conn.ReadFrom(buf)
		if err != nil {
			select {
			case <-f.done:
				return
			default:
				continue
			}
		}
		udp, ok := src.(*net.UDPAddr)
		if !ok {
			continue
		}
		ipa, _ := netip.AddrFromSlice(udp.IP)
		srcAP := netip.AddrPortFrom(ipa.Unmap(), uint16(udp.Port))
		resp := s.Handle(append([]byte{}, buf[:n]...), srcAP)
		if resp == nil {
			continue
		}
		_, _ = f.conn.WriteTo(resp, src)
	}
}

func (f *fakeStunEcho) server() Server {
	return Server{Host: "127.0.0.1", Port: int(f.addr.Port())}
}

// hairpinHarness is the test seam for probeHairpinning. send/recv default to
// the real socket I/O implementations; tests override either to inject
// scenarios like "drop the tagged packet" without needing a real NAT.
type hairpinHarness struct {
	send hairpinSender
	recv hairpinReceiver
}

func defaultHarness() hairpinHarness {
	return hairpinHarness{send: realHairpinSend, recv: realHairpinRecv}
}

func runProbe(t *testing.T, server Server, timeout time.Duration, h hairpinHarness) HairpinningResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout+time.Second)
	defer cancel()
	return probeHairpinning(ctx, server, timeout, h.send, h.recv)
}

// TestProbeHairpinning_TaggedArrives drives the real send/recv path against
// a localhost STUN server. The tagged packet is delivered locally (no real
// NAT in the path); we assert that the recv side sees it and returns &true.
func TestProbeHairpinning_TaggedArrives(t *testing.T) {
	t.Parallel()
	f := newFakeStunEcho(t)
	res := runProbe(t, f.server(), 500*time.Millisecond, defaultHarness())
	if res.Err != nil {
		t.Fatalf("unexpected Err: %v", res.Err)
	}
	if res.Detected == nil {
		t.Fatal("Detected = nil; want &true")
	}
	if !*res.Detected {
		t.Errorf("Detected = &false; want &true (loopback should deliver)")
	}
}

// TestProbeHairpinning_Timeout injects a recv oracle that always times out,
// simulating the case where the tagged packet never arrives (no hairpinning).
func TestProbeHairpinning_Timeout(t *testing.T) {
	t.Parallel()
	f := newFakeStunEcho(t)
	h := defaultHarness()
	h.recv = func(_ context.Context, _ net.PacketConn, _ []byte, _ time.Duration) (bool, error) {
		return false, nil
	}
	res := runProbe(t, f.server(), 300*time.Millisecond, h)
	if res.Err != nil {
		t.Fatalf("unexpected Err: %v", res.Err)
	}
	if res.Detected == nil || *res.Detected {
		t.Errorf("Detected = %v; want &false", res.Detected)
	}
}

// TestProbeHairpinning_STUNFailure: server isn't running so both STUN probes
// time out; Detected stays nil and Err is set.
func TestProbeHairpinning_STUNFailure(t *testing.T) {
	t.Parallel()
	// Bind a UDP socket to claim a port, then close it — the port is now free
	// (kernel may reuse it) but for the short duration of this test we'll
	// most likely see a STUN read timeout. Even if a re-use coincidentally
	// happens, the STUN response won't match TXID and the probe still fails.
	c, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := c.LocalAddr().(*net.UDPAddr).Port
	_ = c.Close()

	server := Server{Host: "127.0.0.1", Port: port}
	res := runProbe(t, server, 200*time.Millisecond, defaultHarness())
	if res.Err == nil {
		t.Fatal("Err = nil; want STUN probe failure")
	}
	if res.Detected != nil {
		t.Errorf("Detected = %v; want nil on STUN failure", res.Detected)
	}
}

// TestProbeHairpinning_FalseNegative_PortRestrictedFiltering simulates the
// case docs/design.md names as required: the STUN probes succeed (mA, mB
// are known) but the NAT applies port-restricted filtering on the hairpin
// path — the tagged packet is dropped because B didn't initiate to A's mapped
// endpoint. The probe must return &false cleanly, no error.
//
// The simulation runs entirely via the oracle: send pretends to write
// (returns nil) but the recv oracle returns false to model the filtered drop.
func TestProbeHairpinning_FalseNegative_PortRestrictedFiltering(t *testing.T) {
	t.Parallel()
	f := newFakeStunEcho(t)
	h := defaultHarness()

	// Filtered send: succeeds at the OS level (packet leaves socket A), but
	// the recv oracle never observes the tag (NAT drops on the return path).
	h.send = func(_ context.Context, _ net.PacketConn, _ netip.AddrPort, _ []byte) error {
		return nil
	}
	h.recv = func(_ context.Context, _ net.PacketConn, _ []byte, _ time.Duration) (bool, error) {
		return false, nil
	}

	res := runProbe(t, f.server(), 300*time.Millisecond, h)
	if res.Err != nil {
		t.Fatalf("unexpected Err for filtered hairpin: %v", res.Err)
	}
	if res.Detected == nil {
		t.Fatal("Detected = nil; want &false for filtered hairpin")
	}
	if *res.Detected {
		t.Errorf("Detected = &true; want &false (port-restricted filter should suppress)")
	}
}

// TestProbeHairpinning_ContextCutIsUntested: a cancelled ctx ends the probe
// within 500ms of the cancel with no verdict and ctx's error, whether it was
// cancelled before the STUN phase or during the listen. The tag is never sent,
// so only ctx can end the 5s listen early.
func TestProbeHairpinning_ContextCutIsUntested(t *testing.T) {
	t.Parallel()
	const window = 5 * time.Second
	const cutAfter = 300 * time.Millisecond
	dropTag := func(context.Context, net.PacketConn, netip.AddrPort, []byte) error { return nil }
	cases := []struct {
		name string
		ctx  func() (context.Context, context.CancelFunc)
		send hairpinSender
		want error
	}{
		{"cancelled before the probe", func() (context.Context, context.CancelFunc) {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			return ctx, cancel
		}, realHairpinSend, context.Canceled},
		{"cancelled during the listen", func() (context.Context, context.CancelFunc) {
			ctx, cancel := context.WithCancel(context.Background())
			time.AfterFunc(cutAfter, cancel)
			return ctx, cancel
		}, dropTag, context.Canceled},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newFakeStunEcho(t)
			start := time.Now()
			ctx, cancel := tc.ctx()
			defer cancel()
			res := probeHairpinning(ctx, f.server(), window, tc.send, realHairpinRecv)
			if elapsed := time.Since(start); elapsed > cutAfter+500*time.Millisecond {
				t.Errorf("returned after %v, want within 500ms of the cut", elapsed)
			}
			if res.Detected != nil {
				t.Errorf("Detected = %v, want nil", *res.Detected)
			}
			if !errors.Is(res.Err, tc.want) {
				t.Errorf("Err = %v, want %v", res.Err, tc.want)
			}
		})
	}
}

// TestProbeHairpinning_SizesToTimeLeft: 300ms of a 900ms deadline is gone
// before the probe starts, as slow DNS would spend it. An 800ms budget would
// run past the deadline; sized to two thirds of the 600ms left, the listen
// finishes and reads false, not untested.
func TestProbeHairpinning_SizesToTimeLeft(t *testing.T) {
	t.Parallel()
	f := newFakeStunEcho(t)
	dropTag := func(context.Context, net.PacketConn, netip.AddrPort, []byte) error { return nil }
	ctx, cancel := context.WithTimeout(context.Background(), 900*time.Millisecond)
	defer cancel()
	time.Sleep(300 * time.Millisecond)
	res := probeHairpinning(ctx, f.server(), 800*time.Millisecond, dropTag, realHairpinRecv)
	if res.Err != nil || res.Detected == nil || *res.Detected {
		t.Fatalf("Detected = %v, Err = %v; want false, nil", res.Detected, res.Err)
	}
}

// TestRealHairpinRecv_DeadlineCutIsUntested: a ctx deadline before the window's
// end returns ctx's error, not false, within 500ms of the deadline.
func TestRealHairpinRecv_DeadlineCutIsUntested(t *testing.T) {
	t.Parallel()
	c, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = c.Close() }()
	const cut = 100 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), cut)
	defer cancel()
	start := time.Now()
	got, err := realHairpinRecv(ctx, c, []byte("tag"), 5*time.Second)
	if elapsed := time.Since(start); elapsed > cut+500*time.Millisecond {
		t.Errorf("returned after %v, want within 500ms of the deadline", elapsed)
	}
	if got || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("got %v, %v; want false, %v", got, err, context.DeadlineExceeded)
	}
}

// TestHairpinAddrs_NoTimeLeftBindsNothing: a deadline already gone returns
// DeadlineExceeded before any socket is bound.
func TestHairpinAddrs_NoTimeLeftBindsNothing(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	listen := func(string, string) (net.PacketConn, error) {
		t.Error("listen called with no time left")
		return nil, errors.New("unexpected listen")
	}
	ips := []netip.Addr{netip.MustParseAddr("127.0.0.1")}
	res := hairpinAddrs(ctx, Server{Host: "h", Port: 3478}, ips, 100*time.Millisecond, listen, realHairpinSend, realHairpinRecv)
	if res.Detected != nil || !errors.Is(res.Err, context.DeadlineExceeded) {
		t.Fatalf("Detected = %v, Err = %v; want nil, %v", res.Detected, res.Err, context.DeadlineExceeded)
	}
}

// lateConn wakes its read 60ms after the first read deadline, as a loaded
// scheduler can, and ignores later deadlines.
type lateConn struct {
	net.PacketConn
	mu       sync.Mutex
	deadline time.Time
}

func (c *lateConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.deadline.IsZero() {
		c.deadline = t
	}
	return nil
}

func (c *lateConn) ReadFrom([]byte) (int, net.Addr, error) {
	c.mu.Lock()
	wake := c.deadline.Add(60 * time.Millisecond)
	c.mu.Unlock()
	time.Sleep(time.Until(wake))
	return 0, nil, os.ErrDeadlineExceeded
}

// TestRealHairpinRecv_FullWindowReadsFalseAfterCtxEnds: the listen window runs
// out before ctx does, but the read returns after both. The window passed, so
// the answer is false, not ctx's error.
func TestRealHairpinRecv_FullWindowReadsFalseAfterCtxEnds(t *testing.T) {
	t.Parallel()
	const window = 50 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), window+30*time.Millisecond)
	defer cancel()
	got, err := realHairpinRecv(ctx, &lateConn{}, []byte("tag"), window)
	if got || err != nil {
		t.Fatalf("got %v, %v; want false, nil", got, err)
	}
}

// TestSendBindingAndWait_FullWindowIsNoResponseAfterCtxEnds: as for the
// hairpin listen, a window that ran out before the read returned reads as no
// response, not ctx's error.
func TestSendBindingAndWait_FullWindowIsNoResponseAfterCtxEnds(t *testing.T) {
	t.Parallel()
	c, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = c.Close() }()
	const window = 50 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), window+30*time.Millisecond)
	defer cancel()
	_, err = sendBindingAndWait(ctx, &lateConn{PacketConn: c}, c.LocalAddr(), window, nil)
	if !errors.Is(err, errNoResponse) {
		t.Fatalf("err = %v, want errNoResponse", err)
	}
}

// failDeadlineConn fails every SetReadDeadline.
type failDeadlineConn struct{ net.PacketConn }

var errSetDeadline = errors.New("set read deadline failed")

func (failDeadlineConn) SetReadDeadline(time.Time) error { return errSetDeadline }

func TestSendBindingAndWait_ReadErrorIsNotSilence(t *testing.T) {
	t.Parallel()
	c, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = c.Close() }()
	_, err = sendBindingAndWait(context.Background(), failDeadlineConn{c}, c.LocalAddr(), 100*time.Millisecond, nil)
	if !errors.Is(err, errSetDeadline) {
		t.Fatalf("err = %v, want %v", err, errSetDeadline)
	}
}

func TestRealHairpinRecv_ReadErrorIsNotFalse(t *testing.T) {
	t.Parallel()
	c, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = c.Close() }()
	got, err := realHairpinRecv(context.Background(), failDeadlineConn{c}, []byte("tag"), 100*time.Millisecond)
	if got || !errors.Is(err, errSetDeadline) {
		t.Fatalf("got %v, %v; want false, %v", got, err, errSetDeadline)
	}
}

// TestProbeHairpinning_InvalidServer covers the input-validation path:
// empty host, zero port, out-of-range port.
func TestProbeHairpinning_InvalidServer(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		server Server
	}{
		{"empty_host", Server{Host: "", Port: 3478}},
		{"zero_port", Server{Host: "127.0.0.1", Port: 0}},
		{"port_too_large", Server{Host: "127.0.0.1", Port: 70000}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := probeHairpinning(context.Background(), tc.server, 100*time.Millisecond,
				realHairpinSend, realHairpinRecv)
			if res.Err == nil {
				t.Errorf("Err = nil; want validation failure for %+v", tc.server)
			}
			if res.Detected != nil {
				t.Errorf("Detected = %v; want nil on invalid input", res.Detected)
			}
		})
	}
}

// TestProbeHairpinning_SendOracleError surfaces a send-side error as Err,
// not as Detected=&false. The caller distinguishes "we couldn't try" from
// "we tried and saw no loopback."
func TestProbeHairpinning_SendOracleError(t *testing.T) {
	t.Parallel()
	f := newFakeStunEcho(t)
	h := defaultHarness()
	sendErr := errors.New("simulated send failure")
	h.send = func(_ context.Context, _ net.PacketConn, _ netip.AddrPort, _ []byte) error {
		return sendErr
	}
	res := runProbe(t, f.server(), 200*time.Millisecond, h)
	if res.Err == nil || !errors.Is(res.Err, sendErr) {
		t.Errorf("Err = %v; want wraps sendErr", res.Err)
	}
	if res.Detected != nil {
		t.Errorf("Detected = %v; want nil on send error", res.Detected)
	}
}

// noRouteConn fails every send at once, as a socket does when its family has
// no route to the target.
type noRouteConn struct{ net.PacketConn }

func (noRouteConn) WriteTo([]byte, net.Addr) (int, error) {
	return 0, errors.New("network is unreachable")
}

// TestHairpinAddrs_FirstAddressFails: a host whose first address cannot be
// used falls through to the next, as the mapping probe does.
func TestHairpinAddrs_FirstAddressFails(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		calls int // listen calls the first address makes before it fails
		first func() (net.PacketConn, error)
	}{
		{"bind_fails", 1, func() (net.PacketConn, error) { return nil, errors.New("bind refused") }},
		{"send_fails", 2, func() (net.PacketConn, error) {
			c, err := net.ListenPacket("udp4", "127.0.0.1:0")
			return noRouteConn{c}, err
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newFakeStunEcho(t)
			var n int
			listen := func(network, address string) (net.PacketConn, error) {
				if n++; n <= tc.calls {
					return tc.first()
				}
				return net.ListenPacket(network, address)
			}
			ips := []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("127.0.0.1")}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			res := hairpinAddrs(ctx, f.server(), ips, 500*time.Millisecond, listen, realHairpinSend, realHairpinRecv)
			if res.Err != nil {
				t.Fatalf("expected fallback to the next address, got: %v", res.Err)
			}
			if res.Detected == nil || !*res.Detected {
				t.Errorf("Detected = %v; want &true over the next address", res.Detected)
			}
		})
	}
}

func TestHairpinAddrs_TriesIPv4First(t *testing.T) {
	t.Parallel()
	var networks []string
	listen := func(network, _ string) (net.PacketConn, error) {
		networks = append(networks, network)
		return nil, errors.New("no sockets")
	}
	ips := []netip.Addr{netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("127.0.0.1")}
	_ = hairpinAddrs(context.Background(), Server{Host: "h", Port: 3478}, ips, 100*time.Millisecond, listen, realHairpinSend, realHairpinRecv)
	if want := []string{"udp4", "udp6"}; !slices.Equal(networks, want) {
		t.Errorf("listened on %v, want %v", networks, want)
	}
}

// TestHairpinAddrs_EveryAddressFails reports the last failure and no verdict.
func TestHairpinAddrs_EveryAddressFails(t *testing.T) {
	t.Parallel()
	listenErr := errors.New("no sockets")
	listen := func(string, string) (net.PacketConn, error) { return nil, listenErr }
	ips := []netip.Addr{netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("127.0.0.1")}
	res := hairpinAddrs(context.Background(), Server{Host: "h", Port: 3478}, ips, 100*time.Millisecond, listen, realHairpinSend, realHairpinRecv)
	if !errors.Is(res.Err, listenErr) {
		t.Fatalf("Err = %v, want the bind failure", res.Err)
	}
	if res.Detected != nil {
		t.Errorf("Detected = %v; want nil", res.Detected)
	}
}

// cancelOnWrite fails its send as noRouteConn does, cancelling first.
type cancelOnWrite struct {
	noRouteConn
	cancel context.CancelFunc
}

func (c cancelOnWrite) WriteTo(b []byte, addr net.Addr) (int, error) {
	c.cancel()
	return c.noRouteConn.WriteTo(b, addr)
}

// TestHairpinAddrs_CancelStopsFallthrough: a cancel during the first address's
// attempt stops the next one, whatever made the first fail.
func TestHairpinAddrs_CancelStopsFallthrough(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		first    func(n int, cancel context.CancelFunc) (net.PacketConn, error)
		sendFail bool
	}{
		{"bind_fails", func(_ int, cancel context.CancelFunc) (net.PacketConn, error) {
			cancel()
			return nil, errors.New("bind refused")
		}, false},
		// Only socket A cancels, so B's probe cannot end A's before A sends.
		{"send_fails", func(n int, cancel context.CancelFunc) (net.PacketConn, error) {
			c, err := net.ListenPacket("udp4", "127.0.0.1:0")
			if n == 0 {
				return cancelOnWrite{noRouteConn{c}, cancel}, err
			}
			return noRouteConn{c}, err
		}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var boundNext bool
			var n int
			listen := func(network, _ string) (net.PacketConn, error) {
				if network == "udp6" {
					boundNext = true
					return nil, errors.New("udp6 must not be bound")
				}
				n++
				return tc.first(n-1, cancel)
			}
			ips := []netip.Addr{netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("192.0.2.1")}
			res := hairpinAddrs(ctx, Server{Host: "h", Port: 3478}, ips, 100*time.Millisecond, listen, realHairpinSend, realHairpinRecv)
			if boundNext {
				t.Fatal("fell through to the next address after cancel")
			}
			if !errors.Is(res.Err, context.Canceled) {
				t.Errorf("Err = %v, want context.Canceled", res.Err)
			}
			if tc.sendFail && !errors.Is(res.Err, errSendFailed) {
				t.Errorf("Err = %v, want the send failure", res.Err)
			}
			if res.Detected != nil {
				t.Errorf("Detected = %v; want nil", res.Detected)
			}
		})
	}
}
