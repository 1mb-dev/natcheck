# Running natcheck filtering classification against coturn

natcheck implements RFC 5780 §4.4 filtering classification, but the public default servers (`stun.l.google.com`, `stun.cloudflare.com`) don't advertise the `OTHER-ADDRESS` attribute that §4.4 requires. To get a filtering verdict, point natcheck at a STUN server that supports CHANGE-REQUEST — coturn is the most common one.

This page is the minimum coturn config to test filtering. **Diagnostic-test posture:** no auth, no TLS, no rate limiting. Don't expose this config as a production STUN/TURN service.

## Topology requirement

coturn refuses to participate in §4.4 unless the VM provides **two distinct routable IPs** that the coturn process can both bind to and source traffic from. With one IP, coturn logs `WARNING: ... only one IP address is provided` and natcheck reports `filtering: untested`.

The right setup varies by provider:

| Provider | Topology | What you need |
|---|---|---|
| AWS EC2, GCP, Azure VM | Public IP NAT'd to a separate private NIC IP — two distinct IPs already | Use both as listed in the conf: `YOUR_FIRST_IP` = public, `YOUR_SECOND_IP` = the private IP from `ip addr` (e.g., `10.0.0.5`). |
| DigitalOcean basic droplet, Linode Nanode, Hetzner Cloud single-IP | eth0's IP IS the public IP | Add a second routable IP (DO Reserved IP / Linode Extra IP / Hetzner Floating IP), alias it to eth0 with `ip addr add SECOND_IP/32 dev eth0`. |
| Bare metal with two NICs | Two routable IPs natively | List both NIC IPs. |

### Worked example: DigitalOcean basic droplet

1. Create a Reserved IP in the same region as your droplet, assign it to the droplet.
2. SSH to the droplet, alias the Reserved IP to eth0 (substitute your own — the script in the automated path below does this for you):
   ```sh
   ip addr add <your-reserved-ip>/32 dev eth0
   ```
3. In the conf, `YOUR_FIRST_IP` is the droplet's primary public IP; `YOUR_SECOND_IP` is the Reserved IP.

## What you need

- A VM matching one of the topology shapes above.
- Two free UDP ports on the VM (defaults: `3478` + `3479`).
- coturn installed (`apt install coturn` on Debian/Ubuntu — ships 4.5/4.6 on Ubuntu 24.04; `brew install coturn` on macOS — ships 4.10+).

## The config

Copy [`examples/coturn-natcheck.conf`](../examples/coturn-natcheck.conf) to your VM. Replace `YOUR_FIRST_IP` and `YOUR_SECOND_IP` per the topology table above. Start coturn:

```sh
turnserver -c /path/to/coturn-natcheck.conf
```

Open UDP `3478` + `3479` in the VM's firewall / cloud security group.

## Verification

Confirm coturn does NOT log either of these:

```
WARNING: ... only one IP address is provided
INFO:    RFC5780 disabled! /NAT behavior discovery/
```

The first means topology is wrong (need two distinct routable IPs the way the table above describes). The second means coturn ≥4.10 is missing the `rfc5780` directive (older coturn doesn't emit this; the bundled conf already has the directive for forward compat).

### Automated path

[`scripts/validate-coturn.sh`](../scripts/validate-coturn.sh) does the install + conf + ufw + verification in one shot. Pipe via SSH:

```sh
# AWS/GCP topology (public IP + private NIC IP differ naturally):
ssh root@<vm-ip> 'bash -s' < scripts/validate-coturn.sh

# Single-public-IP provider after attaching a second IP:
ssh root@<vm-ip> "SECOND_IP=<reserved-ip> bash -s" < scripts/validate-coturn.sh
```

The script aliases `SECOND_IP` to eth0 if needed, writes the multi-IP conf, installs coturn, opens the firewall, starts coturn in tmux, and greps the log for the two warning lines above. Exits non-zero with `FAIL: ...` if either appears — so a misconfigured droplet doesn't silently produce `filtering: untested` samples.

## Verifying with natcheck

From any client network:

```sh
natcheck --server YOUR_FIRST_IP:3478 --json
```

The JSON output's top-level `"filtering"` object will show one of:

- `"endpoint-independent"` — most permissive; direct P2P likely
- `"address-dependent"` or `"address-and-port-dependent"` — restrictive; direct P2P possible (depends on ICE)
- `"untested"` — re-check the verification step

Run from at least three different client networks (home, mobile hotspot, café Wi-Fi) to characterise your NAT against more than one source. After capture, tear down the VM — the diagnostic-posture config is not safe to leave running.

## What's NOT covered

- **Production hardening** — auth (`lt-cred-mech`), TLS (`tls-listening-port`, `cert`/`pkey`), rate limiting, persistence, metrics. coturn's own README covers these. natcheck doesn't and shouldn't.
- **Bundled `natcheck server` subcommand** — planned for v0.1.4 (see `docs/design.md` v0.2 addendum). Until then, coturn is the path.
