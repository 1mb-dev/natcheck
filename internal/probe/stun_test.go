package probe

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/pion/stun/v3"
)

// fakeSTUN is a minimal in-process STUN responder for tests. It reads UDP
// packets, decodes them as STUN messages, and responds with a Binding Success
// + XOR-MAPPED-ADDRESS set to the sender's address. delay > 0 simulates a slow
// server; drop = true simulates a silent server that never responds.
type fakeSTUN struct {
	conn  net.PacketConn
	delay time.Duration
	drop  bool
	done  chan struct{}
}

func newFakeSTUN(t *testing.T, delay time.Duration, drop bool) *fakeSTUN {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	f := &fakeSTUN{conn: conn, delay: delay, drop: drop, done: make(chan struct{})}
	go f.serve()
	t.Cleanup(func() {
		close(f.done)
		_ = conn.Close()
	})
	return f
}

func (f *fakeSTUN) addr() (string, int) {
	udp := f.conn.LocalAddr().(*net.UDPAddr)
	return "127.0.0.1", udp.Port
}

func (f *fakeSTUN) serve() {
	buf := make([]byte, 1500)
	for {
		select {
		case <-f.done:
			return
		default:
		}
		_ = f.conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		n, from, err := f.conn.ReadFrom(buf)
		if err != nil {
			continue
		}
		if f.drop {
			continue
		}
		if f.delay > 0 {
			time.Sleep(f.delay)
		}
		req := &stun.Message{Raw: append([]byte{}, buf[:n]...)}
		if err := req.Decode(); err != nil {
			continue
		}
		udp, ok := from.(*net.UDPAddr)
		if !ok {
			continue
		}
		resp, err := stun.Build(
			stun.NewTransactionIDSetter(req.TransactionID),
			stun.BindingSuccess,
			&stun.XORMappedAddress{IP: udp.IP, Port: udp.Port},
		)
		if err != nil {
			continue
		}
		_, _ = f.conn.WriteTo(resp.Raw, from)
	}
}

func TestProbe_Success(t *testing.T) {
	f := newFakeSTUN(t, 0, false)
	host, port := f.addr()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	res := NewSTUN().Probe(ctx, Server{Host: host, Port: port})
	if res.Err != nil {
		t.Fatalf("unexpected error: %v", res.Err)
	}
	if !res.Mapped.IsValid() {
		t.Fatal("mapped endpoint not set")
	}
	if !res.Mapped.Addr().IsLoopback() {
		t.Fatalf("expected loopback mapped IP, got %v", res.Mapped.Addr())
	}
	if res.RTT <= 0 {
		t.Fatalf("expected positive RTT, got %v", res.RTT)
	}
}

func TestProbe_TimeoutShorterThanResponse(t *testing.T) {
	f := newFakeSTUN(t, 300*time.Millisecond, false)
	host, port := f.addr()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	start := time.Now()
	res := NewSTUN().Probe(ctx, Server{Host: host, Port: port})
	elapsed := time.Since(start)

	if res.Err == nil {
		t.Fatal("expected error on timeout, got success")
	}
	if elapsed > 500*time.Millisecond {
		t.Fatalf("probe did not cancel promptly: %v", elapsed)
	}
}

func TestProbe_ServerSilent(t *testing.T) {
	f := newFakeSTUN(t, 0, true)
	host, port := f.addr()

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	res := NewSTUN().Probe(ctx, Server{Host: host, Port: port})
	if res.Err == nil {
		t.Fatal("expected error against silent server, got success")
	}
}

func TestProbe_ServerNotListening(t *testing.T) {
	// Grab a port then free it so we know no one is listening there.
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := conn.LocalAddr().(*net.UDPAddr).Port
	_ = conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	res := NewSTUN().Probe(ctx, Server{Host: "127.0.0.1", Port: port})
	if res.Err == nil {
		t.Fatal("expected error against unlistened port, got success")
	}
}

func TestProbe_MalformedHostPort(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	cases := []Server{
		{Host: "", Port: 3478},
		{Host: "127.0.0.1", Port: 0},
		{Host: "127.0.0.1", Port: -1},
		{Host: "127.0.0.1", Port: 70000},
	}
	for _, c := range cases {
		res := NewSTUN().Probe(ctx, c)
		if res.Err == nil {
			t.Fatalf("expected error for %+v, got success", c)
		}
	}
}
