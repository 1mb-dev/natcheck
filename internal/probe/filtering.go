package probe

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"time"

	"github.com/1mb-dev/natcheck/internal/stunserver"
	"github.com/pion/stun/v3"
)

// FilteringResult captures the outcome of an RFC 5780 §4.4 three-step
// filtering classification. When the server cannot run the sequence, because it
// advertised no OTHER-ADDRESS or it ignored CHANGE-REQUEST, Test2Received and
// Test3Received are both false and Err wraps ErrFilteringNotSupported.
//
// Server is the target of the §4.4 sequence (echoed from the ProbeFiltering
// argument so consumers can attribute the result without re-threading state).
type FilteringResult struct {
	Server        Server
	Test1Mapped   netip.AddrPort
	Test1Other    netip.AddrPort
	Test2Received bool
	Test3Received bool
	Err           error
}

// ErrFilteringNotSupported is returned in FilteringResult.Err when the target
// server cannot run the §4.4 sequence: it advertised no OTHER-ADDRESS, or it
// answered a CHANGE-REQUEST from the address the request was sent to.
var ErrFilteringNotSupported = errors.New("server does not support RFC 5780 CHANGE-REQUEST")

// ErrTest1Failed wraps the underlying transport / parse error from the initial
// Binding probe. The §4.4 sequence is skipped when this error is returned.
var ErrTest1Failed = errors.New("initial probe failed; cannot run §4.4 sequence")

// errNoResponse signals "no STUN response arrived before the per-test deadline."
// Package-internal: callers in this file translate it to Test{2,3}Received=false.
var errNoResponse = errors.New("no response within deadline")

// ProbeFiltering runs RFC 5780 §4.4 against server. Uses one unconnected UDP
// socket for all three tests so (a) the NAT mapping stays stable across tests
// and (b) the socket can receive responses from the server's alt-IP/alt-port
// sources (a connected UDP socket would filter those out). Tests 2/3 are
// one-shot; "no response within timeout/2" is the verdict, not an error.
//
// ctx governs the initial address resolution only; once resolution completes,
// per-test SetReadDeadline timers (timeout/2 each) drive the rest. Cancelling
// ctx mid-call has no effect on in-flight reads.
func ProbeFiltering(ctx context.Context, server Server, timeout time.Duration) FilteringResult {
	res := FilteringResult{Server: server}
	if server.Host == "" || server.Port <= 0 || server.Port > 65535 {
		res.Err = fmt.Errorf("invalid server %q:%d", server.Host, server.Port)
		return res
	}

	hostport := net.JoinHostPort(server.Host, strconv.Itoa(server.Port))
	var resolver net.Resolver
	ips, err := resolver.LookupNetIP(ctx, "ip", server.Host)
	if err != nil {
		res.Err = fmt.Errorf("resolve %s: %w", server.Host, err)
		return res
	}
	if len(ips) == 0 {
		res.Err = fmt.Errorf("resolve %s: no addresses", server.Host)
		return res
	}
	ip := ips[0].Unmap()
	target := netip.AddrPortFrom(ip, uint16(server.Port))
	remote := net.UDPAddrFromAddrPort(target)

	network, listenAddr := pickNetwork(ip)
	conn, err := net.ListenPacket(network, listenAddr)
	if err != nil {
		res.Err = fmt.Errorf("listen %s: %w", hostport, err)
		return res
	}
	defer func() { _ = conn.Close() }()

	perTest := timeout / 2
	if perTest <= 0 {
		perTest = 500 * time.Millisecond
	}

	// Test 1: plain Binding.
	t1, err := sendBindingAndWait(conn, remote, perTest, nil)
	if err != nil {
		res.Err = fmt.Errorf("%w: %w", ErrTest1Failed, err)
		return res
	}
	res.Test1Mapped = t1.mapped
	res.Test1Other = t1.other

	if !res.Test1Other.IsValid() {
		res.Err = ErrFilteringNotSupported
		return res
	}

	// Test 2: CHANGE-IP|CHANGE-PORT.
	t2, err2 := sendBindingAndWait(conn, remote, perTest, &changeRequestPayload{ip: true, port: true})

	// Test 3: CHANGE-PORT.
	t3, err3 := sendBindingAndWait(conn, remote, perTest, &changeRequestPayload{ip: false, port: true})

	// Only silence is a filtering result. Any other failure means a reply got
	// through and the test measured nothing.
	for _, err := range []error{err2, err3} {
		if err != nil && !errors.Is(err, errNoResponse) {
			res.Err = fmt.Errorf("%w: %w", ErrFilteringNotSupported, err)
			return res
		}
	}

	if changeRequestIgnored(target, res.Test1Other, t2, t3) {
		res.Err = ErrFilteringNotSupported
		return res
	}
	res.Test2Received = t2 != nil
	res.Test3Received = t3 != nil

	return res
}

// changeRequestIgnored reports whether a Test 2 or Test 3 reply lacks the change
// asked for, in which case neither test measured anything: Test 2 must come from
// a new IP, Test 3 from a new endpoint. The comparison is to the target, not
// OTHER-ADDRESS, because provider topologies can reply from an address other
// than the advertised one, and that must not read as stricter filtering.
//
// Loopback has one IP on macOS, so a loopback responder can only simulate a
// changed IP by replying from OTHER-ADDRESS. No routable server gets that pass:
// one IP cannot honor CHANGE-IP.
func changeRequestIgnored(target, other netip.AddrPort, t2, t3 *bindingResult) bool {
	source, advertised := comparableEndpoint(target), comparableEndpoint(other)
	if t3 != nil && t3.source == source {
		return true
	}
	if t2 == nil || t2.source.Addr() != source.Addr() {
		return false
	}
	return !(source.Addr().IsLoopback() && t2.source == advertised)
}

type changeRequestPayload struct {
	ip, port bool
}

// sendBindingAndWait sends one BindingRequest (with optional CHANGE-REQUEST)
// to remote and waits up to deadline for a matching response. The conn is an
// unconnected PacketConn so responses can arrive from sources other than
// remote (RFC 5780 §4.4: server replies from alt-IP/alt-port). Returns
// errNoResponse if the deadline expires with no matching reply. Discards
// stale packets with non-matching transaction IDs (e.g., late responses from
// a prior test) and keeps reading until either a matching response, deadline
// expiry, or fatal socket error. The result records the reply's source; judging
// it is the caller's job.
func sendBindingAndWait(conn net.PacketConn, remote net.Addr, deadline time.Duration, change *changeRequestPayload) (*bindingResult, error) {
	setters := []stun.Setter{stun.TransactionID, stun.BindingRequest}
	if change != nil {
		setters = append(setters, stunserver.BuildChangeRequest(change.ip, change.port))
	}
	req, err := stun.Build(setters...)
	if err != nil {
		return nil, fmt.Errorf("build: %w", err)
	}
	req.Encode()

	end := time.Now().Add(deadline)
	if err := conn.SetWriteDeadline(end); err != nil {
		return nil, fmt.Errorf("set write deadline: %w", err)
	}
	if _, err := conn.WriteTo(req.Raw, remote); err != nil {
		return nil, fmt.Errorf("write: %w", err)
	}

	buf := make([]byte, 1500)
	for {
		if time.Until(end) <= 0 {
			return nil, errNoResponse
		}
		if err := conn.SetReadDeadline(end); err != nil {
			return nil, fmt.Errorf("set read deadline: %w", err)
		}
		n, from, err := conn.ReadFrom(buf)
		if err != nil {
			// Deadline reached or fatal error.
			return nil, errNoResponse
		}
		resp := &stun.Message{Raw: append([]byte{}, buf[:n]...)}
		if err := resp.Decode(); err != nil {
			// Garbage on the socket; discard and keep reading.
			continue
		}
		if resp.TransactionID != req.TransactionID {
			// Stale response from a prior test; discard and keep reading.
			continue
		}
		out, err := parseBindingSuccess(resp)
		if err != nil {
			return nil, err
		}
		if udp, ok := from.(*net.UDPAddr); ok {
			out.source = comparableEndpoint(udp.AddrPort())
		}
		return out, nil
	}
}
