package probe

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/pion/stun/v3"
)

// NewSTUN returns a Prober backed by pion/stun over UDP.
func NewSTUN() Prober {
	return stunProber{}
}

type stunProber struct{}

// ProbeAll sends one STUN Binding request to each server, concurrently, and
// returns results in input order. Servers in the same address family share one
// local socket: mapped endpoints are only comparable when they come from the
// same local endpoint. One-shot: no retransmissions. ctx bounds the whole run.
func (stunProber) ProbeAll(ctx context.Context, servers []Server) []Result {
	run := newMappingRun()
	defer run.close()

	results := make([]Result, len(servers))
	var wg sync.WaitGroup
	for i, s := range servers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i] = run.probe(ctx, s)
		}()
	}
	wg.Wait()
	return results
}

const readErrorPause = 10 * time.Millisecond

type transactionID = [stun.TransactionIDSize]byte

// mappingRun holds the per-family sockets and in-flight transactions of one
// ProbeAll call. Its sockets are unconnected, so the kernel no longer filters
// replies by source: every packet from the network is untrusted, and a bad one
// must be dropped without affecting any other probe.
type mappingRun struct {
	listen func(network, address string) (net.PacketConn, error)

	mu      sync.Mutex
	sockets map[string]familySocket
	pending map[transactionID]*transaction
	readers sync.WaitGroup
}

// familySocket caches a failed bind too, so one family's failure is reported
// once per run and never affects the other family.
type familySocket struct {
	conn net.PacketConn
	err  error
}

type transaction struct {
	target netip.AddrPort
	source netip.AddrPort // target as replies report it; see comparableEndpoint
	start  time.Time
	reply  chan transactionReply // buffered; the reader must not block on it
}

type transactionReply struct {
	binding *bindingResult
	rtt     time.Duration
	err     error
}

func newMappingRun() *mappingRun {
	return &mappingRun{
		listen:  net.ListenPacket,
		sockets: map[string]familySocket{},
		pending: map[transactionID]*transaction{},
	}
}

func (r *mappingRun) close() {
	r.mu.Lock()
	for _, s := range r.sockets {
		if s.conn != nil {
			_ = s.conn.Close()
		}
	}
	r.mu.Unlock()
	r.readers.Wait()
}

func (r *mappingRun) probe(ctx context.Context, s Server) Result {
	if s.Host == "" || s.Port <= 0 || s.Port > 65535 {
		return Result{Server: s, Err: fmt.Errorf("invalid server %q:%d", s.Host, s.Port)}
	}
	ips, err := resolveHost(ctx, s.Host)
	if err != nil {
		return Result{Server: s, Err: fmt.Errorf("resolve %s: %w", s.Host, err)}
	}
	if len(ips) == 0 {
		return Result{Server: s, Err: fmt.Errorf("resolve %s: no addresses", s.Host)}
	}
	return r.probeAddrs(ctx, s, ips)
}

// resolveHost keeps the zone of a literal address. LookupNetIP strips it, and a
// link-local address is unroutable without one.
func resolveHost(ctx context.Context, host string) ([]netip.Addr, error) {
	if ip, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{ip}, nil
	}
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

// probeAddrs uses the first address that accepts a send. A host with an AAAA
// record and no IPv6 route fails here at write time and falls through to its
// A record, which is the fallback a connected UDP dial would have given.
func (r *mappingRun) probeAddrs(ctx context.Context, s Server, ips []netip.Addr) Result {
	res := Result{Server: s}
	var tx *transaction
	for _, ip := range ips {
		var err error
		tx, err = r.send(netip.AddrPortFrom(ip.Unmap(), uint16(s.Port)))
		if err == nil {
			break
		}
		res.Err = err
	}
	if tx == nil {
		return res
	}
	res.Err = nil
	res.Target = tx.target

	select {
	case reply := <-tx.reply:
		if reply.err != nil {
			res.Err = reply.err
			return res
		}
		res.Mapped = reply.binding.mapped
		res.Other = reply.binding.other
		res.RTT = reply.rtt
	case <-ctx.Done():
		// An unconnected socket gets no ICMP errors, so a closed port shows up
		// here, at the deadline, rather than as an immediate refusal.
		res.Err = fmt.Errorf("no response from %s: %w", tx.target, ctx.Err())
	}
	return res
}

func (r *mappingRun) send(target netip.AddrPort) (*transaction, error) {
	conn, err := r.socket(target.Addr())
	if err != nil {
		return nil, err
	}
	req, err := stun.Build(stun.TransactionID, stun.BindingRequest)
	if err != nil {
		return nil, fmt.Errorf("build binding request: %w", err)
	}
	req.Encode()

	tx := &transaction{target: target, source: comparableEndpoint(target), start: time.Now(), reply: make(chan transactionReply, 1)}
	r.mu.Lock()
	r.pending[req.TransactionID] = tx
	r.mu.Unlock()

	if _, err := conn.WriteTo(req.Raw, net.UDPAddrFromAddrPort(target)); err != nil {
		r.mu.Lock()
		delete(r.pending, req.TransactionID)
		r.mu.Unlock()
		return nil, fmt.Errorf("write request to %s: %w", target, err)
	}
	return tx, nil
}

func (r *mappingRun) socket(ip netip.Addr) (net.PacketConn, error) {
	network, listenAddr := pickNetwork(ip)
	r.mu.Lock()
	defer r.mu.Unlock()
	if s, ok := r.sockets[network]; ok {
		return s.conn, s.err
	}
	conn, err := r.listen(network, listenAddr)
	if err != nil {
		err = fmt.Errorf("listen %s: %w", network, err)
		r.sockets[network] = familySocket{err: err}
		return nil, err
	}
	r.sockets[network] = familySocket{conn: conn}
	r.readers.Add(1)
	go r.read(conn)
	return conn, nil
}

func (r *mappingRun) read(conn net.PacketConn) {
	defer r.readers.Done()
	buf := make([]byte, 1500)
	for {
		n, addr, err := conn.ReadFrom(buf)
		if errors.Is(err, net.ErrClosed) {
			return
		}
		if err != nil {
			// Stay alive for the probes in flight, but a persistent error must
			// not spin until the deadline.
			time.Sleep(readErrorPause)
			continue
		}
		received := time.Now()
		udp, ok := addr.(*net.UDPAddr)
		if !ok {
			continue
		}
		r.deliver(buf[:n], comparableEndpoint(udp.AddrPort()), received)
	}
}

// comparableEndpoint normalizes an address for source checks. The zone is
// dropped because a target may name it by index while replies name it by
// interface, and it adds nothing to a transaction ID match.
func comparableEndpoint(ap netip.AddrPort) netip.AddrPort {
	return netip.AddrPortFrom(ap.Addr().Unmap().WithZone(""), ap.Port())
}

// deliver hands a packet to its transaction, or drops it. Order matters: source
// first, so an unrelated host cannot make us parse its data, then decode, then
// transaction ID. Nothing here may end the run; only a reply that belongs to a
// transaction can fail one, and only that one.
func (r *mappingRun) deliver(data []byte, src netip.AddrPort, received time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.expectsSource(src) {
		return
	}
	resp := &stun.Message{Raw: append([]byte{}, data...)}
	if err := resp.Decode(); err != nil {
		return
	}
	tx, ok := r.pending[resp.TransactionID]
	if !ok || tx.source != src {
		return
	}
	delete(r.pending, resp.TransactionID)
	binding, err := parseBindingSuccess(resp)
	tx.reply <- transactionReply{binding: binding, rtt: received.Sub(tx.start), err: err}
}

func (r *mappingRun) expectsSource(src netip.AddrPort) bool {
	for _, tx := range r.pending {
		if tx.source == src {
			return true
		}
	}
	return false
}

type bindingResult struct {
	mapped netip.AddrPort
	other  netip.AddrPort
	source netip.AddrPort // set by sendBindingAndWait only
}

// parseBindingSuccess reads the attributes of a decoded response. It knows
// nothing about where the response came from: source policy differs per caller,
// because RFC 5780 §4.4 tests expect replies from other addresses.
func parseBindingSuccess(resp *stun.Message) (*bindingResult, error) {
	if resp.Type != stun.BindingSuccess {
		return nil, fmt.Errorf("unexpected STUN message type: %s", resp.Type)
	}
	var xor stun.XORMappedAddress
	if err := xor.GetFrom(resp); err != nil {
		return nil, fmt.Errorf("decode XOR-MAPPED-ADDRESS: %w", err)
	}
	ip, ok := netip.AddrFromSlice(xor.IP)
	if !ok {
		return nil, fmt.Errorf("invalid mapped IP %v", xor.IP)
	}
	out := &bindingResult{mapped: netip.AddrPortFrom(ip.Unmap(), uint16(xor.Port))}
	if !out.mapped.IsValid() {
		return nil, errors.New("mapped endpoint not valid")
	}

	// OTHER-ADDRESS (RFC 5780 §7.4) is optional: silently skip when absent.
	var oa stun.OtherAddress
	if err := oa.GetFrom(resp); err == nil {
		if otherIP, ok := netip.AddrFromSlice(oa.IP); ok {
			out.other = netip.AddrPortFrom(otherIP.Unmap(), uint16(oa.Port))
		}
	}
	return out, nil
}
