package probe

import (
	"context"
	"errors"
	"net"
	"net/netip"
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
// case docs/design.md:428 names as required: the STUN probes succeed (mA, mB
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

// TestProbeHairpinning_CtxCancelUnblocksRecv verifies that ctx.Done() forces
// in-flight socket reads/writes to error immediately, mirroring the pattern
// in stun.go. Without the deadline-bridge goroutine inside probeHairpinning
// a cancel-without-deadline context would let the recv loop run until the
// timeout fully elapsed.
func TestProbeHairpinning_CtxCancelUnblocksRecv(t *testing.T) {
	t.Parallel()
	f := newFakeStunEcho(t)
	h := defaultHarness()
	// Force the recv path to actually wait — production realHairpinRecv
	// honors the deadline, so its blocking read is what cancel must unblock.
	// Use a deliberately long timeout so the test fails (hangs past test
	// timeout) if cancellation isn't bridged.

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	res := probeHairpinning(ctx, f.server(), 5*time.Second, h.send, h.recv)
	elapsed := time.Since(start)

	// Without the ctx.Done() bridge the call would block ~5s; with it,
	// the cancel at 50ms should unblock within a few hundred ms.
	if elapsed > 2*time.Second {
		t.Errorf("ProbeHairpinning blocked for %v after ctx cancel; expected <2s", elapsed)
	}
	// Result shape is allowed to vary (the cancel may interrupt different
	// phases on different runs); the test asserts only that the call
	// returned promptly.
	_ = res
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
