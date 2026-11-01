package probe

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

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

func TestProbeAll_FloodCannotExtendDeadline(t *testing.T) {
	f := newFakeSTUN(t, 0, behaviorGarbled)
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		conn := f.conn
		for {
			select {
			case <-stop:
				return
			default:
				_, _ = conn.WriteTo([]byte{0xFF}, conn.LocalAddr())
			}
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	res := probeOne(ctx, fakeServer(f))
	if res.Err == nil {
		t.Fatal("expected error, got success")
	}
	if elapsed := time.Since(start); elapsed > 400*time.Millisecond {
		t.Errorf("elapsed = %v, want the 100ms deadline to hold", elapsed)
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
