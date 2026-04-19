package probe

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/pion/stun/v3"
)

// fakeBehavior selects how the in-process fake STUN responder replies.
type fakeBehavior int

const (
	behaviorNormal     fakeBehavior = iota // build a valid BindingSuccess with correct XOR-MAPPED-ADDRESS
	behaviorDrop                           // never respond
	behaviorWrongTxID                      // BindingSuccess with a different transaction ID
	behaviorWrongType                      // respond with BindingError instead of BindingSuccess
	behaviorOmitMapped                     // BindingSuccess without XOR-MAPPED-ADDRESS attribute
	behaviorGarbled                        // write random bytes that don't parse as STUN
)

// fakeSTUN is an in-process STUN responder for tests. No network access required.
type fakeSTUN struct {
	conn     net.PacketConn
	delay    time.Duration
	behavior fakeBehavior
	done     chan struct{}
}

func newFakeSTUN(t *testing.T, delay time.Duration, behavior fakeBehavior) *fakeSTUN {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	f := &fakeSTUN{conn: conn, delay: delay, behavior: behavior, done: make(chan struct{})}
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
		if f.behavior == behaviorDrop {
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
		respBytes := buildResponse(f.behavior, req, udp)
		if respBytes == nil {
			continue
		}
		_, _ = f.conn.WriteTo(respBytes, from)
	}
}

func buildResponse(behavior fakeBehavior, req *stun.Message, udp *net.UDPAddr) []byte {
	switch behavior {
	case behaviorNormal:
		resp, err := stun.Build(
			stun.NewTransactionIDSetter(req.TransactionID),
			stun.BindingSuccess,
			&stun.XORMappedAddress{IP: udp.IP, Port: udp.Port},
		)
		if err != nil {
			return nil
		}
		return resp.Raw

	case behaviorWrongTxID:
		var wrong [stun.TransactionIDSize]byte
		for i := range wrong {
			wrong[i] = 0xAA
		}
		resp, err := stun.Build(
			stun.NewTransactionIDSetter(wrong),
			stun.BindingSuccess,
			&stun.XORMappedAddress{IP: udp.IP, Port: udp.Port},
		)
		if err != nil {
			return nil
		}
		return resp.Raw

	case behaviorWrongType:
		resp, err := stun.Build(
			stun.NewTransactionIDSetter(req.TransactionID),
			stun.BindingError,
		)
		if err != nil {
			return nil
		}
		return resp.Raw

	case behaviorOmitMapped:
		resp, err := stun.Build(
			stun.NewTransactionIDSetter(req.TransactionID),
			stun.BindingSuccess,
		)
		if err != nil {
			return nil
		}
		return resp.Raw

	case behaviorGarbled:
		// 8 bytes of non-STUN noise; too short to parse as a STUN message.
		return []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}

	default:
		return nil
	}
}

func TestProbe_Success(t *testing.T) {
	f := newFakeSTUN(t, 0, behaviorNormal)
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
	f := newFakeSTUN(t, 300*time.Millisecond, behaviorNormal)
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
	f := newFakeSTUN(t, 0, behaviorDrop)
	host, port := f.addr()

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	res := NewSTUN().Probe(ctx, Server{Host: host, Port: port})
	if res.Err == nil {
		t.Fatal("expected error against silent server, got success")
	}
}

func TestProbe_ServerNotListening(t *testing.T) {
	// Grab a port then free it so nothing listens there.
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

// Adversarial response paths: responder returns malformed / unexpected STUN
// messages. Probe must surface an error, never panic, never hang.

func TestProbe_WrongTransactionID(t *testing.T) {
	f := newFakeSTUN(t, 0, behaviorWrongTxID)
	host, port := f.addr()

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	res := NewSTUN().Probe(ctx, Server{Host: host, Port: port})
	if res.Err == nil {
		t.Fatal("expected error on transaction-ID mismatch, got success")
	}
}

func TestProbe_WrongMessageType(t *testing.T) {
	f := newFakeSTUN(t, 0, behaviorWrongType)
	host, port := f.addr()

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	res := NewSTUN().Probe(ctx, Server{Host: host, Port: port})
	if res.Err == nil {
		t.Fatal("expected error on unexpected STUN message type, got success")
	}
}

func TestProbe_MissingMappedAddress(t *testing.T) {
	f := newFakeSTUN(t, 0, behaviorOmitMapped)
	host, port := f.addr()

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	res := NewSTUN().Probe(ctx, Server{Host: host, Port: port})
	if res.Err == nil {
		t.Fatal("expected error on missing XOR-MAPPED-ADDRESS, got success")
	}
}

func TestProbe_GarbledResponse(t *testing.T) {
	f := newFakeSTUN(t, 0, behaviorGarbled)
	host, port := f.addr()

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	res := NewSTUN().Probe(ctx, Server{Host: host, Port: port})
	if res.Err == nil {
		t.Fatal("expected error on garbled response, got success")
	}
}
