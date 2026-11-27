package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"sync"
	"testing"

	"github.com/1mb-dev/natcheck/internal/probe"
	"github.com/1mb-dev/natcheck/internal/stunserver"
)

// natSim is a userspace NAT in front of loopback STUN servers. Each server is
// reached through a door: the client sends to the door, the packet leaves
// through an external socket chosen by the mapping rule, and the reply returns
// from that door. These tests must use the real prober, since a stub cannot
// observe which local socket a probe left from.
type natSim struct {
	t              *testing.T
	perDestination bool
	servers        []*net.UDPAddr
	doors          []*net.UDPConn

	mu       sync.Mutex
	external map[string]*net.UDPConn
}

func listenLoopback(t *testing.T) *net.UDPConn {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func startSTUNServers(t *testing.T, n int) []*net.UDPAddr {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	addrs := make([]*net.UDPAddr, n)
	for i := range addrs {
		c := listenLoopback(t)
		addrs[i] = c.LocalAddr().(*net.UDPAddr)
		go func() { _ = stunserver.New(stunserver.Options{}).Serve(ctx, c) }()
	}
	return addrs
}

func startNATSim(t *testing.T, servers []*net.UDPAddr, perDestination bool) []*net.UDPAddr {
	t.Helper()
	doors := make([]*net.UDPConn, len(servers))
	for i := range doors {
		doors[i] = listenLoopback(t)
	}
	return startNATSimOn(t, servers, doors, perDestination)
}

func startNATSimOn(t *testing.T, servers []*net.UDPAddr, doors []*net.UDPConn, perDestination bool) []*net.UDPAddr {
	t.Helper()
	n := &natSim{t: t, perDestination: perDestination, servers: servers, doors: doors, external: map[string]*net.UDPConn{}}
	front := make([]*net.UDPAddr, len(servers))
	for i, d := range doors {
		front[i] = d.LocalAddr().(*net.UDPAddr)
		go n.forward(i)
	}
	return front
}

// dualStackDoors binds n IPv4 loopback doors, each with an IPv6 loopback STUN
// server on the same port, so one host:port reaches both. It skips the test
// when ::1 does not bind.
func dualStackDoors(t *testing.T, n int) (doors []*net.UDPConn, v6 []*net.UDPAddr) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	for len(doors) < n {
		d := listenLoopback(t)
		port := d.LocalAddr().(*net.UDPAddr).Port
		c, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback, Port: port})
		if err != nil {
			if _, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback}); err != nil {
				t.Skipf("IPv6 loopback unavailable: %v", err)
			}
			continue
		}
		t.Cleanup(func() { _ = c.Close() })
		go func() { _ = stunserver.New(stunserver.Options{}).Serve(ctx, c) }()
		doors = append(doors, d)
		v6 = append(v6, c.LocalAddr().(*net.UDPAddr))
	}
	return doors, v6
}

func (n *natSim) forward(door int) {
	buf := make([]byte, 1500)
	for {
		size, client, err := n.doors[door].ReadFromUDP(buf)
		if err != nil {
			return
		}
		_, _ = n.socketFor(client, door).WriteToUDP(buf[:size], n.servers[door])
	}
}

func (n *natSim) socketFor(client *net.UDPAddr, door int) *net.UDPConn {
	key := client.String()
	if n.perDestination {
		key = fmt.Sprintf("%s>%d", key, door)
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if c, ok := n.external[key]; ok {
		return c
	}
	c := listenLoopback(n.t)
	n.external[key] = c
	go n.reverse(c, client)
	return c
}

func (n *natSim) reverse(ext *net.UDPConn, client *net.UDPAddr) {
	buf := make([]byte, 1500)
	for {
		size, from, err := ext.ReadFromUDP(buf)
		if err != nil {
			return
		}
		for i, s := range n.servers {
			if s.Port == from.Port {
				_, _ = n.doors[i].WriteToUDP(buf[:size], client)
			}
		}
	}
}

// distinctTargets keeps real socket results and gives each probe its own
// synthetic server IP. Loopback offers one IP on macOS, and the diversity guard
// correctly refuses to call that EIM, so without this the cone scenarios cannot
// reach the verdict they exist to pin.
type distinctTargets struct{ probe.Prober }

func (d distinctTargets) ProbeAll(ctx context.Context, servers []probe.Server) []probe.Result {
	results := d.Prober.ProbeAll(ctx, servers)
	var n4, n6 byte
	for i, r := range results {
		switch {
		case !r.Target.IsValid():
		case r.Target.Addr().Is4():
			n4++
			results[i].Target = netip.AddrPortFrom(netip.AddrFrom4([4]byte{198, 51, 100, n4}), r.Target.Port())
		default:
			n6++
			results[i].Target = netip.AddrPortFrom(netip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, 15: n6}), r.Target.Port())
		}
	}
	return results
}

type mappingReport struct {
	NATType        string `json:"nat_type"`
	WebRTCForecast struct {
		DirectP2P string `json:"direct_p2p"`
	} `json:"webrtc_forecast"`
	Warnings []string `json:"warnings"`
}

func decodeMappingReport(t *testing.T, out, errOut string) mappingReport {
	t.Helper()
	var report mappingReport
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatalf("decode report: %v; out=%q errOut=%q", err, out, errOut)
	}
	return report
}

func TestRun_OneServerIPCannotProveEIM(t *testing.T) {
	tests := []struct {
		name         string
		targets      func(t *testing.T, servers []*net.UDPAddr) []*net.UDPAddr
		wantType     string
		wantForecast string
		wantWarning  bool
	}{
		{
			name:         "no NAT",
			targets:      func(_ *testing.T, servers []*net.UDPAddr) []*net.UDPAddr { return servers },
			wantType:     "Unknown",
			wantForecast: "unknown",
			wantWarning:  true,
		},
		{
			name: "endpoint-independent NAT",
			targets: func(t *testing.T, servers []*net.UDPAddr) []*net.UDPAddr {
				return startNATSim(t, servers, false)
			},
			wantType:     "Unknown",
			wantForecast: "unknown",
			wantWarning:  true,
		},
		{
			name: "per-destination NAT",
			targets: func(t *testing.T, servers []*net.UDPAddr) []*net.UDPAddr {
				return startNATSim(t, servers, true)
			},
			wantType:     "ADM",
			wantForecast: "unlikely",
		},
		{
			name: "duplicate server",
			targets: func(_ *testing.T, servers []*net.UDPAddr) []*net.UDPAddr {
				return []*net.UDPAddr{servers[0], servers[0]}
			},
			wantType:     "Unknown",
			wantForecast: "unknown",
			wantWarning:  true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			targets := tt.targets(t, startSTUNServers(t, 2))
			code, out, errOut := run(t, probe.NewSTUN(), "--json", "--timeout", "2s",
				"--server", targets[0].String(), "--server", targets[1].String())

			report := decodeMappingReport(t, out, errOut)
			if report.NATType != tt.wantType {
				t.Errorf("nat_type = %q, want %q; out=%s", report.NATType, tt.wantType, out)
			}
			if report.WebRTCForecast.DirectP2P != tt.wantForecast {
				t.Errorf("direct_p2p = %q, want %q", report.WebRTCForecast.DirectP2P, tt.wantForecast)
			}
			if code != 1 {
				t.Errorf("exit code = %d, want 1", code)
			}
			if got := slices.Contains(report.Warnings, "insufficient_server_diversity"); got != tt.wantWarning {
				t.Errorf("warning present = %v, want %v; warnings=%v", got, tt.wantWarning, report.Warnings)
			}
		})
	}
}

func TestRun_MappingBehaviorOverRealSockets(t *testing.T) {
	tests := []struct {
		name         string
		targets      func(t *testing.T, servers []*net.UDPAddr) []*net.UDPAddr
		wantType     string
		wantForecast string
		wantCode     int
		wantNoNAT    bool
	}{
		{
			name:         "no NAT",
			targets:      func(_ *testing.T, servers []*net.UDPAddr) []*net.UDPAddr { return servers },
			wantType:     "EIM",
			wantForecast: "possible",
			wantCode:     0,
			wantNoNAT:    true,
		},
		{
			name: "endpoint-independent NAT",
			targets: func(t *testing.T, servers []*net.UDPAddr) []*net.UDPAddr {
				return startNATSim(t, servers, false)
			},
			wantType:     "EIM",
			wantForecast: "possible",
			wantCode:     0,
		},
		{
			name: "per-destination NAT",
			targets: func(t *testing.T, servers []*net.UDPAddr) []*net.UDPAddr {
				return startNATSim(t, servers, true)
			},
			wantType:     "ADM",
			wantForecast: "unlikely",
			wantCode:     1,
		},
		// A carrier NAT in front of the home NAT: the probes cross both, so the
		// verdict covers both (docs/design.md § CGNAT detection).
		{
			name: "endpoint-independent NAT behind a per-destination NAT",
			targets: func(t *testing.T, servers []*net.UDPAddr) []*net.UDPAddr {
				return startNATSim(t, startNATSim(t, servers, true), false)
			},
			wantType:     "ADM",
			wantForecast: "unlikely",
			wantCode:     1,
		},
		{
			name: "per-destination NAT behind an endpoint-independent NAT",
			targets: func(t *testing.T, servers []*net.UDPAddr) []*net.UDPAddr {
				return startNATSim(t, startNATSim(t, servers, false), true)
			},
			wantType:     "ADM",
			wantForecast: "unlikely",
			wantCode:     1,
		},
		{
			name: "endpoint-independent NAT behind an endpoint-independent NAT",
			targets: func(t *testing.T, servers []*net.UDPAddr) []*net.UDPAddr {
				return startNATSim(t, startNATSim(t, servers, false), false)
			},
			wantType:     "EIM",
			wantForecast: "possible",
			wantCode:     0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			targets := tt.targets(t, startSTUNServers(t, 2))
			code, out, errOut := run(t, distinctTargets{probe.NewSTUN()}, "--json", "--timeout", "2s",
				"--server", targets[0].String(), "--server", targets[1].String())

			report := decodeMappingReport(t, out, errOut)
			if report.NATType != tt.wantType {
				t.Errorf("nat_type = %q, want %q; out=%s", report.NATType, tt.wantType, out)
			}
			if report.WebRTCForecast.DirectP2P != tt.wantForecast {
				t.Errorf("direct_p2p = %q, want %q", report.WebRTCForecast.DirectP2P, tt.wantForecast)
			}
			if code != tt.wantCode {
				t.Errorf("exit code = %d, want %d", code, tt.wantCode)
			}
			if got := slices.Contains(report.Warnings, "no_nat"); got != tt.wantNoNAT {
				t.Errorf("no_nat present = %v, want %v; warnings=%v", got, tt.wantNoNAT, report.Warnings)
			}
		})
	}
}

// A hostname with both A and AAAA records, IPv6 first as DNS prefers: IPv6
// reaches the servers untranslated, IPv4 crosses a per-destination NAT. The
// IPv4 verdict decides (docs/design.md § Address families).
func TestRun_DualStackHostnameProbesBothFamilies(t *testing.T) {
	doors, v6 := dualStackDoors(t, 2)
	startNATSimOn(t, startSTUNServers(t, 2), doors, true)
	lookup := func(_ context.Context, _, _ string) ([]netip.Addr, error) {
		return []netip.Addr{netip.IPv6Loopback(), netip.MustParseAddr("127.0.0.1")}, nil
	}
	prober := distinctTargets{probe.NewSTUNWithResolver(lookup)}
	code, out, errOut := run(t, prober, "--json", "--timeout", "2s",
		"--server", fmt.Sprintf("dual-a.test:%d", v6[0].Port), "--server", fmt.Sprintf("dual-b.test:%d", v6[1].Port))

	report := decodeMappingReport(t, out, errOut)
	if report.NATType != "ADM" || report.WebRTCForecast.DirectP2P != "unlikely" || code != 1 {
		t.Errorf("nat_type, direct_p2p, exit = %q, %q, %d; want ADM, unlikely, 1; out=%s", report.NATType, report.WebRTCForecast.DirectP2P, code, out)
	}
}
