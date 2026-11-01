package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
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
	n := &natSim{t: t, perDestination: perDestination, servers: servers, external: map[string]*net.UDPConn{}}
	front := make([]*net.UDPAddr, len(servers))
	for i := range servers {
		d := listenLoopback(t)
		n.doors = append(n.doors, d)
		front[i] = d.LocalAddr().(*net.UDPAddr)
	}
	for i := range n.doors {
		go n.forward(i)
	}
	return front
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

func TestRun_MappingBehaviorOverRealSockets(t *testing.T) {
	tests := []struct {
		name         string
		targets      func(t *testing.T, servers []*net.UDPAddr) []*net.UDPAddr
		wantType     string
		wantForecast string
		wantCode     int
	}{
		{
			name:         "no NAT",
			targets:      func(_ *testing.T, servers []*net.UDPAddr) []*net.UDPAddr { return servers },
			wantType:     "EIM",
			wantForecast: "likely",
			wantCode:     0,
		},
		{
			name: "endpoint-independent NAT",
			targets: func(t *testing.T, servers []*net.UDPAddr) []*net.UDPAddr {
				return startNATSim(t, servers, false)
			},
			wantType:     "EIM",
			wantForecast: "likely",
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
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			targets := tt.targets(t, startSTUNServers(t, 2))
			code, out, errOut := run(t, probe.NewSTUN(), "--json", "--timeout", "2s",
				"--server", targets[0].String(), "--server", targets[1].String())

			var report struct {
				NATType        string `json:"nat_type"`
				WebRTCForecast struct {
					DirectP2P string `json:"direct_p2p"`
				} `json:"webrtc_forecast"`
			}
			if err := json.Unmarshal([]byte(out), &report); err != nil {
				t.Fatalf("decode report: %v; out=%q errOut=%q", err, out, errOut)
			}
			if report.NATType != tt.wantType {
				t.Errorf("nat_type = %q, want %q; out=%s", report.NATType, tt.wantType, out)
			}
			if report.WebRTCForecast.DirectP2P != tt.wantForecast {
				t.Errorf("direct_p2p = %q, want %q", report.WebRTCForecast.DirectP2P, tt.wantForecast)
			}
			if code != tt.wantCode {
				t.Errorf("exit code = %d, want %d", code, tt.wantCode)
			}
		})
	}
}
