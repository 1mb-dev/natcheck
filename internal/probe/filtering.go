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
// filtering classification. Test1Other.IsValid() == false means the server
// did not advertise OTHER-ADDRESS; in that case Test2Received and
// Test3Received are both false and Err wraps ErrFilteringNotSupported.
type FilteringResult struct {
	Test1Mapped   netip.AddrPort
	Test1Other    netip.AddrPort
	Test2Received bool
	Test3Received bool
	Err           error
}

// ErrFilteringNotSupported is returned in FilteringResult.Err when the target
// server's BindingResponse does not include an OTHER-ADDRESS attribute, so the
// §4.4 sequence cannot be attempted.
var ErrFilteringNotSupported = errors.New("server did not advertise OTHER-ADDRESS")

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
	res := FilteringResult{}
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
	remote := &net.UDPAddr{IP: net.IP(ips[0].Unmap().AsSlice()), Port: server.Port}

	conn, err := net.ListenPacket("udp", ":0")
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
	t2, _ := sendBindingAndWait(conn, remote, perTest, &changeRequestPayload{ip: true, port: true})
	res.Test2Received = t2 != nil

	// Test 3: CHANGE-PORT.
	t3, _ := sendBindingAndWait(conn, remote, perTest, &changeRequestPayload{ip: false, port: true})
	res.Test3Received = t3 != nil

	return res
}

type bindingResult struct {
	mapped netip.AddrPort
	other  netip.AddrPort
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
// expiry, or fatal socket error.
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
		n, _, err := conn.ReadFrom(buf)
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
		if resp.Type != stun.BindingSuccess {
			return nil, fmt.Errorf("unexpected message type: %s", resp.Type)
		}
		var xor stun.XORMappedAddress
		if err := xor.GetFrom(resp); err != nil {
			return nil, fmt.Errorf("XOR-MAPPED-ADDRESS: %w", err)
		}
		mappedIP, ok := netip.AddrFromSlice(xor.IP)
		if !ok {
			return nil, errors.New("invalid mapped IP")
		}
		out := &bindingResult{
			mapped: netip.AddrPortFrom(mappedIP.Unmap(), uint16(xor.Port)),
		}
		var oa stun.OtherAddress
		if err := oa.GetFrom(resp); err == nil {
			otherIP, ok := netip.AddrFromSlice(oa.IP)
			if ok {
				out.other = netip.AddrPortFrom(otherIP.Unmap(), uint16(oa.Port))
			}
		}
		return out, nil
	}
}
