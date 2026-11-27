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
//
// AltIPMapped and AltEndpointMapped are the mapped endpoints of RFC 5780 §4.3
// Tests II and III, sent to OTHER-ADDRESS's IP with the target's port and to
// OTHER-ADDRESS itself. Both are zero unless both tests got a reply; they can be
// set when Err wraps ErrFilteringNotSupported
// (TestProbeFiltering_MappingTestsAfterIgnoredChangeRequest).
type FilteringResult struct {
	Server            Server
	Test1Mapped       netip.AddrPort
	Test1Other        netip.AddrPort
	Test2Received     bool
	Test3Received     bool
	AltIPMapped       netip.AddrPort
	AltEndpointMapped netip.AddrPort
	Err               error
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

// filteringWindows is the most tests ProbeFiltering waits on: Test 1, Tests 2
// and 3, then Tests II and III.
const filteringWindows = 5

// filteringWindow is each test's window for a ProbeFiltering timeout.
func filteringWindow(timeout time.Duration) time.Duration {
	if timeout/2 <= 0 {
		return 500 * time.Millisecond
	}
	return timeout / 2
}

// FilteringMaxDuration is filteringWindows windows for timeout
// (TestFilteringMaxDuration); ProbeFiltering runs at most Tests 1, 2, 3, II and
// III, in turn (TestProbeFiltering_MappingTests), each bounded by one window
// (TestSendBindingAndWait_SilenceEndsAtWindow).
func FilteringMaxDuration(timeout time.Duration) time.Duration {
	return filteringWindows * filteringWindow(timeout)
}

// ProbeFiltering runs RFC 5780 §4.4 against target, the address the mapping
// probe of server reached, then §4.3 Tests II and III when OTHER-ADDRESS allows
// them (mappingTestAllowed). Resolving the host again could reach a host that did
// not advertise OTHER-ADDRESS, or an address with no route. Uses one unconnected
// UDP socket for every test so (a) the NAT mapping stays stable across
// tests and (b) the socket can receive responses from the server's alt-IP/
// alt-port sources (a connected UDP socket would filter those out). Each test
// gets timeout/2, resent as sendBindingAndWait schedules; silence for the whole
// window is the Test 2/3 verdict, not an error. Tests II and III run last:
// sending to OTHER-ADDRESS's IP opens an address-dependent filter for Test 2's
// reply (TestProbeFiltering_MappingTests). No ctx: cli runs filtering
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

	perTest := filteringWindow(timeout)

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

	res.Err = judgeFiltering(target, res.Test1Other, t2, err2, t3, err3)
	switch {
	case res.Err == nil:
		res.Test2Received = t2 != nil
		res.Test3Received = t3 != nil
	case !errors.Is(res.Err, ErrFilteringNotSupported):
		return res // a local fault: no later test can be trusted
	}

	if mappingTestAllowed(target, res.Test1Other) {
		res.AltIPMapped, res.AltEndpointMapped = mappingTests(conn, target, res.Test1Other, perTest)
	}
	return res
}

// judgeFiltering returns nil when Tests 2 and 3 measured filtering. Only silence
// is a filtering result. A failed send or read is a local fault
// (TestProbeFiltering_LocalFaultIsNotFiltering); any other failure is a reply
// that measured nothing.
func judgeFiltering(target, other netip.AddrPort, t2 *bindingResult, err2 error, t3 *bindingResult, err3 error) error {
	for _, err := range []error{err2, err3} {
		switch {
		case err == nil, errors.Is(err, errNoResponse):
		case errors.Is(err, errReadFailed), errors.Is(err, errSendFailed):
			return err
		default:
			return fmt.Errorf("%w: %w", ErrFilteringNotSupported, err)
		}
	}
	if changeRequestIgnored(target, other, t2, t3) {
		return ErrFilteringNotSupported
	}
	return nil
}

// mappingTestAllowed reports whether Tests II and III can measure anything and
// may be sent: OTHER-ADDRESS passes serverChosenAllowed with a nonzero port
// other than the target's. On the target's port, Tests II and III would reach
// one endpoint and always agree (TestMappingTestAllowed).
func mappingTestAllowed(target, other netip.AddrPort) bool {
	if !other.IsValid() || other.Port() == 0 || other.Port() == target.Port() {
		return false
	}
	return serverChosenAllowed(target.Addr(), other.Addr())
}

// serverChosenAllowed reports whether natcheck may send to addr, an address a
// server chose, when the server is target. Apart from Tests II and III, the
// only such packet is the hairpin tag. addr must be in target's family and
// scope (addrScope), outside the never rows of specialRanges, and in 2000::/3
// when it is a public IPv6 address (TestMappingTestAllowed,
// TestSpecialRanges_MatchIANARegistry).
func serverChosenAllowed(target, addr netip.Addr) bool {
	t, a := target.Unmap(), addr.Unmap().WithZone("")
	if !a.IsValid() || a.Is4() != t.Is4() || a.IsMulticast() {
		return false
	}
	if specialRange(a, isNever) >= 0 {
		return false
	}
	scope := addrScope(a)
	if a.Is6() && scope == scopePublic && !globalUnicast6.Contains(a) {
		return false
	}
	return scope == addrScope(t)
}

// globalUnicast6 is the only IPv6 space a public server-chosen address may be
// in. Outside it lie unassigned space and the IPv4-compatible ::/96 and SIIT
// ::ffff:0:0:0/96 forms, which Unmap does not convert (TestMappingTestAllowed).
var globalUnicast6 = netip.MustParsePrefix("2000::/3")

// disposition is how serverChosenAllowed treats a specialRanges row
// (TestMappingTestAllowed_SpecialRanges, TestSpecialRanges_MatchIANARegistry).
type disposition uint8

const (
	std    disposition = iota // netip's loopback, link-local or private predicate gives the scope
	own                       // the prefix is its own scope
	never                     // never sent to
	public                    // public on purpose
)

type specialRangeRow struct {
	p netip.Prefix
	d disposition
}

// specialRanges is every block of the IANA IPv4 and IPv6 Special-Purpose
// Address Registries, as pinned in testdata, plus fec0::/10
// (TestSpecialRanges_MatchIANARegistry). No address in a never row is sent to
// (TestMappingTestAllowed_SpecialRanges).
var specialRanges = []specialRangeRow{
	{netip.MustParsePrefix("0.0.0.0/8"), own},
	{netip.MustParsePrefix("0.0.0.0/32"), never},
	{netip.MustParsePrefix("10.0.0.0/8"), std},
	{netip.MustParsePrefix("100.64.0.0/10"), own},
	{netip.MustParsePrefix("127.0.0.0/8"), std},
	{netip.MustParsePrefix("169.254.0.0/16"), std},
	{netip.MustParsePrefix("172.16.0.0/12"), std},
	{netip.MustParsePrefix("192.0.0.0/24"), own},
	{netip.MustParsePrefix("192.0.0.0/29"), own},
	{netip.MustParsePrefix("192.0.0.8/32"), own},
	{netip.MustParsePrefix("192.0.0.9/32"), own},
	{netip.MustParsePrefix("192.0.0.10/32"), own},
	{netip.MustParsePrefix("192.0.0.170/32"), own},
	{netip.MustParsePrefix("192.0.0.171/32"), own},
	{netip.MustParsePrefix("192.0.2.0/24"), public},
	{netip.MustParsePrefix("192.31.196.0/24"), public},
	{netip.MustParsePrefix("192.52.193.0/24"), public},
	{netip.MustParsePrefix("192.88.99.0/24"), public},
	{netip.MustParsePrefix("192.88.99.2/32"), own},
	{netip.MustParsePrefix("192.168.0.0/16"), std},
	{netip.MustParsePrefix("192.175.48.0/24"), public},
	{netip.MustParsePrefix("198.18.0.0/15"), own},
	{netip.MustParsePrefix("198.51.100.0/24"), public},
	{netip.MustParsePrefix("203.0.113.0/24"), public},
	{netip.MustParsePrefix("240.0.0.0/4"), own},
	{netip.MustParsePrefix("255.255.255.255/32"), never},

	{netip.MustParsePrefix("::1/128"), std},
	{netip.MustParsePrefix("::/128"), never},
	{netip.MustParsePrefix("::ffff:0:0/96"), never},
	{netip.MustParsePrefix("64:ff9b::/96"), never},
	{netip.MustParsePrefix("64:ff9b:1::/48"), never},
	{netip.MustParsePrefix("100::/64"), never},
	{netip.MustParsePrefix("100:0:0:1::/64"), never},
	{netip.MustParsePrefix("2001::/23"), own},
	{netip.MustParsePrefix("2001::/32"), never},
	{netip.MustParsePrefix("2001:1::1/128"), own},
	{netip.MustParsePrefix("2001:1::2/128"), own},
	{netip.MustParsePrefix("2001:1::3/128"), own},
	{netip.MustParsePrefix("2001:2::/48"), own},
	{netip.MustParsePrefix("2001:3::/32"), own},
	{netip.MustParsePrefix("2001:4:112::/48"), own},
	{netip.MustParsePrefix("2001:10::/28"), own},
	{netip.MustParsePrefix("2001:20::/28"), own},
	{netip.MustParsePrefix("2001:30::/28"), own},
	{netip.MustParsePrefix("2001:db8::/32"), public},
	{netip.MustParsePrefix("2002::/16"), never},
	{netip.MustParsePrefix("2620:4f:8000::/48"), public},
	{netip.MustParsePrefix("3fff::/20"), public},
	{netip.MustParsePrefix("5f00::/16"), never},
	{netip.MustParsePrefix("fc00::/7"), std},
	{netip.MustParsePrefix("fe80::/10"), std},
	{netip.MustParsePrefix("fec0::/10"), own}, // off-registry: deprecated site-local, RFC 3879
}

// specialRange returns the index of the longest row of specialRanges that
// contains a and passes keep, or -1.
func specialRange(a netip.Addr, keep func(disposition) bool) int {
	best := -1
	for i, r := range specialRanges {
		if keep(r.d) && r.p.Contains(a) && (best < 0 || r.p.Bits() > specialRanges[best].p.Bits()) {
			best = i
		}
	}
	return best
}

func isNever(d disposition) bool  { return d == never }
func notNever(d disposition) bool { return d != never }

// addrScope gives the scope serverChosenAllowed compares. A never row bars
// sending, not a scope, so an address in one takes the scope of the row around
// it, if any (TestMappingTestAllowed).
func addrScope(a netip.Addr) int {
	a = a.WithZone("")
	switch {
	case a.IsLoopback():
		return 0
	case a.IsLinkLocalUnicast():
		return 1
	case a.IsPrivate():
		return 2
	}
	if i := specialRange(a, notNever); i >= 0 && specialRanges[i].d == own {
		return 4 + i
	}
	return scopePublic
}

const scopePublic = 3

// mappingTests runs RFC 5780 §4.3 Tests II and III on conn. It returns zero
// endpoints unless both got a reply; Test III is skipped when Test II failed
// (TestProbeFiltering_MappingTestsNeedBothReplies).
func mappingTests(conn net.PacketConn, target, other netip.AddrPort, wait time.Duration) (altIP, altEndpoint netip.AddrPort) {
	altIPTarget := netip.AddrPortFrom(other.Addr().Unmap(), target.Port())
	t2, err := sendBindingAndWait(context.Background(), conn, net.UDPAddrFromAddrPort(altIPTarget), wait, nil)
	if err != nil {
		return netip.AddrPort{}, netip.AddrPort{}
	}
	t3, err := sendBindingAndWait(context.Background(), conn, net.UDPAddrFromAddrPort(other), wait, nil)
	if err != nil {
		return netip.AddrPort{}, netip.AddrPort{}
	}
	return t2.mapped, t3.mapped
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
