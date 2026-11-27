package probe

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"time"

	"github.com/1mb-dev/natcheck/internal/stunserver"
	"github.com/pion/stun/v3"
)

// FilteringResult captures the outcome of an RFC 5780 §4.4 three-step
// filtering classification. When the server cannot run the sequence, because it
// advertised no OTHER-ADDRESS or it ignored CHANGE-REQUEST, Test2Received and
// Test3Received are both false and Err wraps ErrFilteringNotSupported.
//
// Server is the server whose mapping target the §4.4 sequence ran against
// (echoed from the ProbeFiltering argument so consumers can attribute the
// result without re-threading state).
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

// errReadFailed marks a read that failed for a reason other than its deadline,
// so it measured nothing.
var errReadFailed = errors.New("read")

// errSendFailed marks a request that never left the host, such as a send with
// no route. The next resolved address may still work.
var errSendFailed = errors.New("write")

// ProbeFiltering runs RFC 5780 §4.4 against target, the address the mapping
// probe of server reached. Resolving the host again could reach a host that did
// not advertise OTHER-ADDRESS, or an address with no route. Uses one unconnected
// UDP socket for all three tests so (a) the NAT mapping stays stable across
// tests and (b) the socket can receive responses from the server's alt-IP/
// alt-port sources (a connected UDP socket would filter those out). Each test
// gets timeout/2, resent as sendBindingAndWait schedules; silence for the whole
// window is the Test 2/3 verdict, not an error. No ctx: cli runs filtering
// after the mapping probes and outside their --timeout context, so timeout is
// its only bound.
func ProbeFiltering(server Server, target netip.AddrPort, timeout time.Duration) FilteringResult {
	return probeFilteringWith(net.ListenPacket, server, target, timeout)
}

func probeFilteringWith(listen func(network, address string) (net.PacketConn, error), server Server, target netip.AddrPort, timeout time.Duration) FilteringResult {
	res := FilteringResult{Server: server}
	if !target.IsValid() || target.Port() == 0 {
		res.Err = fmt.Errorf("invalid target %v for %s:%d", target, server.Host, server.Port)
		return res
	}
	ip := target.Addr().Unmap()
	target = netip.AddrPortFrom(ip, target.Port())
	remote := net.UDPAddrFromAddrPort(target)

	network, listenAddr := pickNetwork(ip)
	conn, err := listen(network, listenAddr)
	if err != nil {
		res.Err = fmt.Errorf("listen %s: %w", target, err)
		return res
	}
	defer func() { _ = conn.Close() }()

	perTest := timeout / 2
	if perTest <= 0 {
		perTest = 500 * time.Millisecond
	}

	// Test 1: plain Binding.
	t1, err := sendBindingAndWait(context.Background(), conn, remote, perTest, nil)
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
	t2, err2 := sendBindingAndWait(context.Background(), conn, remote, perTest, &changeRequestPayload{ip: true, port: true})

	// Test 3: CHANGE-PORT.
	t3, err3 := sendBindingAndWait(context.Background(), conn, remote, perTest, &changeRequestPayload{ip: false, port: true})

	// Only silence is a filtering result. A failed send or read is a local
	// fault (TestProbeFiltering_LocalFaultIsNotFiltering); any other failure is
	// a reply that measured nothing.
	for _, err := range []error{err2, err3} {
		switch {
		case err == nil, errors.Is(err, errNoResponse):
		case errors.Is(err, errReadFailed), errors.Is(err, errSendFailed):
			res.Err = err
			return res
		default:
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
	return !source.Addr().IsLoopback() || t2.source != advertised
}

type changeRequestPayload struct {
	ip, port bool
}

// sendBindingAndWait sends one BindingRequest (with optional CHANGE-REQUEST)
// to remote and waits up to wait for a matching response, resending the same
// request on the retransmitGaps schedule while the next send falls inside the
// window (TestProbeFiltering_ResendsLostChangeRequests). The conn is an
// unconnected PacketConn so responses can arrive from sources other than
// remote (RFC 5780 §4.4: server replies from alt-IP/alt-port). Returns ctx's
// error if ctx is done before a reply or the window's end, and errNoResponse
// once the window ends with no matching reply, ctx done or not
// (TestSendBindingAndWait_FullWindowIsNoResponseAfterCtxEnds). Otherwise a
// read that fails for any reason but its deadline returns errReadFailed
// (TestSendBindingAndWait_ReadErrorIsNotSilence). Discards stale
// packets with non-matching transaction IDs (e.g., late responses from a prior
// test) and keeps reading. The result records the reply's source; judging it
// is the caller's job.
func sendBindingAndWait(ctx context.Context, conn net.PacketConn, remote net.Addr, wait time.Duration, change *changeRequestPayload) (*bindingResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	setters := []stun.Setter{stun.TransactionID, stun.BindingRequest}
	if change != nil {
		setters = append(setters, stunserver.BuildChangeRequest(change.ip, change.port))
	}
	req, err := stun.Build(setters...)
	if err != nil {
		return nil, fmt.Errorf("build: %w", err)
	}
	req.Encode()

	sent := time.Now()
	end := sent.Add(wait)
	if err := conn.SetWriteDeadline(end); err != nil {
		return nil, fmt.Errorf("%w: set write deadline: %w", errSendFailed, err)
	}
	if _, err := conn.WriteTo(req.Raw, remote); err != nil {
		return nil, fmt.Errorf("%w: %w", errSendFailed, err)
	}

	gaps := retransmitGaps
	buf := make([]byte, 1500)
	for {
		if !time.Now().Before(end) {
			return nil, errNoResponse
		}
		readEnd := end
		if len(gaps) > 0 && sent.Add(gaps[0]).Before(end) {
			readEnd = sent.Add(gaps[0])
		}
		n, from, err := readUntil(ctx, conn, buf, readEnd)
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil && time.Now().Before(end) {
				return nil, ctxErr
			}
			if !errors.Is(err, os.ErrDeadlineExceeded) {
				return nil, fmt.Errorf("%w: %w", errReadFailed, err)
			}
			if readEnd.Equal(end) {
				return nil, errNoResponse
			}
			_, _ = conn.WriteTo(req.Raw, remote)
			sent, gaps = readEnd, gaps[1:]
			continue
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

// readUntil reads one packet before deadline, or fails once ctx is done. The
// ctx hook is armed after the deadline is set, so setting the deadline cannot
// overwrite a cancel.
func readUntil(ctx context.Context, conn net.PacketConn, buf []byte, deadline time.Time) (int, net.Addr, error) {
	if err := conn.SetReadDeadline(deadline); err != nil {
		return 0, nil, err
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.SetReadDeadline(time.Unix(1, 0)) })
	defer stop()
	return conn.ReadFrom(buf)
}
