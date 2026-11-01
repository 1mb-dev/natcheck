package probe

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/1mb-dev/natcheck/internal/stunserver"
	"github.com/pion/stun/v3"
)

func fakeServer(f *fakeSTUN) Server {
	host, port := f.addr()
	return Server{Host: host, Port: port}
}

func TestProbeAll_ServersShareOneLocalEndpoint(t *testing.T) {
	a, b := newFakeSTUN(t, 0, behaviorNormal), newFakeSTUN(t, 0, behaviorNormal)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	res := NewSTUN().ProbeAll(ctx, []Server{fakeServer(a), fakeServer(b)})
	for i, r := range res {
		if r.Err != nil {
			t.Fatalf("result %d: %v", i, r.Err)
		}
	}
	if res[0].Mapped != res[1].Mapped {
		t.Errorf("mapped endpoints differ: %v and %v", res[0].Mapped, res[1].Mapped)
	}
}

func TestProbeAll_SetsResolvedTarget(t *testing.T) {
	f := newFakeSTUN(t, 0, behaviorNormal)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	s := fakeServer(f)
	res := NewSTUN().ProbeAll(ctx, []Server{s})[0]
	want := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(s.Port))
	if res.Target != want {
		t.Errorf("Target = %v, want %v", res.Target, want)
	}
}

func TestProbeAll_RunsConcurrently(t *testing.T) {
	a, b := newFakeSTUN(t, 200*time.Millisecond, behaviorNormal), newFakeSTUN(t, 200*time.Millisecond, behaviorNormal)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	start := time.Now()
	res := NewSTUN().ProbeAll(ctx, []Server{fakeServer(a), fakeServer(b)})
	elapsed := time.Since(start)
	for i, r := range res {
		if r.Err != nil {
			t.Fatalf("result %d: %v", i, r.Err)
		}
	}
	if elapsed > 390*time.Millisecond {
		t.Errorf("elapsed = %v, want about 200ms", elapsed)
	}
}

func TestProbeAll_ReversedRepliesKeepInputOrder(t *testing.T) {
	slow, fast := newFakeSTUN(t, 150*time.Millisecond, behaviorNormal), newFakeSTUN(t, 0, behaviorNormal)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	servers := []Server{fakeServer(slow), fakeServer(fast)}
	res := NewSTUN().ProbeAll(ctx, servers)
	for i, r := range res {
		if r.Err != nil {
			t.Fatalf("result %d: %v", i, r.Err)
		}
		if r.Server != servers[i] {
			t.Errorf("result %d server = %+v, want %+v", i, r.Server, servers[i])
		}
	}
	if res[0].RTT <= res[1].RTT {
		t.Errorf("RTTs not attributed to their server: slow=%v fast=%v", res[0].RTT, res[1].RTT)
	}
}

func TestProbeAll_BadServerDoesNotAffectGoodServer(t *testing.T) {
	tests := []struct {
		name     string
		behavior fakeBehavior
	}{
		{"silent", behaviorDrop},
		{"garbled", behaviorGarbled},
		{"wrong transaction ID", behaviorWrongTxID},
		{"wrong message type", behaviorWrongType},
		{"missing mapped address", behaviorOmitMapped},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bad, good := newFakeSTUN(t, 0, tt.behavior), newFakeSTUN(t, 20*time.Millisecond, behaviorNormal)
			ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
			defer cancel()

			res := NewSTUN().ProbeAll(ctx, []Server{fakeServer(bad), fakeServer(good)})
			if res[0].Err == nil {
				t.Error("bad server: expected error, got success")
			}
			if res[1].Err != nil {
				t.Errorf("good server failed: %v", res[1].Err)
			}
		})
	}
}

func TestProbeAll_DropsValidReplyFromWrongSource(t *testing.T) {
	server, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = server.Close() }()
	spoofer, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = spoofer.Close() }()

	go func() {
		buf := make([]byte, 1500)
		n, from, err := server.ReadFrom(buf)
		if err != nil {
			return
		}
		req := &stun.Message{Raw: append([]byte{}, buf[:n]...)}
		if req.Decode() != nil {
			return
		}
		udp := from.(*net.UDPAddr)
		_, _ = spoofer.WriteTo(buildResponse(behaviorNormal, req, udp), from)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	res := probeOne(ctx, Server{Host: "127.0.0.1", Port: server.LocalAddr().(*net.UDPAddr).Port})
	if res.Err == nil {
		t.Fatalf("accepted a reply from the wrong source: mapped=%v", res.Mapped)
	}
}

// A flood can fill the shared socket's receive buffer and crowd out another
// server's reply, so this pins the deadline only. That server then reads as
// failed, which costs a verdict but cannot produce a wrong one.
func TestProbeAll_FloodFromServerCannotExtendDeadline(t *testing.T) {
	flooder, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = flooder.Close() }()

	var sent atomic.Int64
	go func() {
		buf := make([]byte, 1500)
		_, client, err := flooder.ReadFrom(buf)
		if err != nil {
			return
		}
		for {
			if _, err := flooder.WriteTo([]byte{0xFF}, client); err != nil {
				return
			}
			sent.Add(1)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	start := time.Now()
	res := probeOne(ctx, Server{Host: "127.0.0.1", Port: flooder.LocalAddr().(*net.UDPAddr).Port})
	elapsed := time.Since(start)

	if sent.Load() < 100 {
		t.Fatalf("flood never ran: %d packets", sent.Load())
	}
	if res.Err == nil {
		t.Error("flooding server: expected error, got success")
	}
	if elapsed > 500*time.Millisecond {
		t.Errorf("elapsed = %v, want the 150ms deadline to hold", elapsed)
	}
}

// failingConn reports a socket error on every read until closed.
type failingConn struct {
	net.PacketConn
	reads  atomic.Int64
	closed atomic.Bool
}

func (c *failingConn) ReadFrom([]byte) (int, net.Addr, error) {
	c.reads.Add(1)
	if c.closed.Load() {
		return 0, nil, net.ErrClosed
	}
	return 0, nil, errors.New("socket failure")
}

func TestRead_PersistentErrorDoesNotSpin(t *testing.T) {
	conn := &failingConn{}
	run := newMappingRun()
	run.readers.Add(1)
	go run.read(conn)
	time.Sleep(50 * time.Millisecond)
	conn.closed.Store(true)
	run.readers.Wait()

	if n := conn.reads.Load(); n > 1000 {
		t.Errorf("%d reads in 50ms, want a paced retry", n)
	}
}

// linkLocalSocket returns a UDP socket on a link-local address, or skips where
// the host has none it can bind.
func linkLocalSocket(t *testing.T) (*net.UDPConn, net.Interface) {
	t.Helper()
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Skipf("interfaces: %v", err)
	}
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil || iface.Flags&net.FlagUp == 0 {
			continue
		}
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok || ipnet.IP.To4() != nil || !ipnet.IP.IsLinkLocalUnicast() {
				continue
			}
			conn, err := net.ListenUDP("udp6", &net.UDPAddr{IP: ipnet.IP, Zone: iface.Name})
			if err == nil {
				t.Cleanup(func() { _ = conn.Close() })
				return conn, iface
			}
		}
	}
	t.Skip("no bindable link-local address")
	return nil, net.Interface{}
}

func TestProbeAll_LinkLocalServerKeepsZone(t *testing.T) {
	conn, iface := linkLocalSocket(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	go func() { _ = stunserver.New(stunserver.Options{}).Serve(ctx, conn) }()
	local := conn.LocalAddr().(*net.UDPAddr)

	for _, zone := range []string{iface.Name, strconv.Itoa(iface.Index)} {
		t.Run(zone, func(t *testing.T) {
			res := probeOne(ctx, Server{Host: local.IP.String() + "%" + zone, Port: local.Port})
			if res.Err != nil {
				t.Fatalf("probe: %v", res.Err)
			}
			if res.Target.Addr().Zone() != zone {
				t.Errorf("Target zone = %q, want %q", res.Target.Addr().Zone(), zone)
			}
		})
	}
}

func TestProbeAddrs_FamilyBindFailureFallsThrough(t *testing.T) {
	f := newFakeSTUN(t, 0, behaviorNormal)
	s := fakeServer(f)

	run := newMappingRun()
	defer run.close()
	run.listen = func(network, address string) (net.PacketConn, error) {
		if network == "udp6" {
			return nil, errors.New("no IPv6 here")
		}
		return net.ListenPacket(network, address)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	ips := []netip.Addr{netip.MustParseAddr("::1"), netip.MustParseAddr("127.0.0.1")}
	res := run.probeAddrs(ctx, s, ips)
	if res.Err != nil {
		t.Fatalf("expected fallback to IPv4, got: %v", res.Err)
	}
	if !res.Target.Addr().Is4() {
		t.Errorf("Target = %v, want the IPv4 address", res.Target)
	}
}

func TestProbeAddrs_AllSendsFailed(t *testing.T) {
	run := newMappingRun()
	defer run.close()
	listenErr := errors.New("no sockets")
	run.listen = func(string, string) (net.PacketConn, error) { return nil, listenErr }

	res := run.probeAddrs(context.Background(), Server{Host: "h", Port: 3478}, []netip.Addr{netip.MustParseAddr("127.0.0.1")})
	if !errors.Is(res.Err, listenErr) {
		t.Fatalf("Err = %v, want the bind failure", res.Err)
	}
	if res.Target.IsValid() {
		t.Errorf("Target = %v, want zero when nothing was sent", res.Target)
	}
}

func TestProbeAll_ResolveFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res := probeOne(ctx, Server{Host: "natcheck.invalid", Port: 3478})
	if res.Err == nil {
		t.Fatal("expected resolve error, got success")
	}
}

func TestResolveHost_LiteralsSkipTheResolver(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, host := range []string{"192.0.2.1", "2001:db8::1", "fe80::1%eth0"} {
		ips, err := resolveHost(ctx, host)
		if err != nil {
			t.Fatalf("resolveHost(%q): %v", host, err)
		}
		if len(ips) != 1 || ips[0].String() != host {
			t.Errorf("resolveHost(%q) = %v", host, ips)
		}
	}
}

func TestComparableEndpoint(t *testing.T) {
	tests := []struct{ in, want string }{
		{"192.0.2.1:3478", "192.0.2.1:3478"},
		{"[::ffff:192.0.2.1]:3478", "192.0.2.1:3478"},
		{"[fe80::1%eth0]:3478", "[fe80::1]:3478"},
		{"[fe80::1%2]:3478", "[fe80::1]:3478"},
	}
	for _, tt := range tests {
		got := comparableEndpoint(netip.MustParseAddrPort(tt.in))
		if got.String() != tt.want {
			t.Errorf("comparableEndpoint(%s) = %s, want %s", tt.in, got, tt.want)
		}
	}
}

func TestPickNetwork(t *testing.T) {
	tests := []struct {
		ip          string
		wantNetwork string
		wantListen  string
	}{
		{"192.0.2.1", "udp4", "0.0.0.0:0"},
		{"2001:db8::1", "udp6", "[::]:0"},
		{"::ffff:192.0.2.1", "udp4", "0.0.0.0:0"},
	}
	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			network, listen := pickNetwork(netip.MustParseAddr(tt.ip))
			if network != tt.wantNetwork || listen != tt.wantListen {
				t.Errorf("pickNetwork(%s) = %q, %q; want %q, %q", tt.ip, network, listen, tt.wantNetwork, tt.wantListen)
			}
		})
	}
}
