# Running natcheck filtering classification against coturn

natcheck implements RFC 5780 §4.4 filtering classification, but the public default servers (`stun.l.google.com`, `stun.cloudflare.com`) don't advertise the `OTHER-ADDRESS` attribute that §4.4 requires. To get a filtering verdict, point natcheck at a STUN server that supports CHANGE-REQUEST — coturn is the most common one.

This page describes the minimum coturn config to test filtering. It's a **diagnostic-test posture**: no auth, no TLS, no rate limiting. Don't expose this configuration as a production STUN/TURN service.

## What you need

- A VM with a public IP (a $5 VPS works fine).
- Two free UDP ports on that VM (defaults below: `3478` + `3479`).
- coturn installed (`apt install coturn` on Debian/Ubuntu, `brew install coturn` on macOS).

## The config

Copy [`examples/coturn-natcheck.conf`](../examples/coturn-natcheck.conf) to your VM, then:

1. Replace `YOUR_PUBLIC_IP` with the VM's external IP. On cloud VMs, the external IP is **not** the same as the interface IP shown by `ip addr` — use the IP your provider assigned (the one you'd `ssh` to). Getting this wrong is the most common cause of "filtering: untested" results.
2. Start coturn pointing at the file:

   ```sh
   turnserver -c /path/to/coturn-natcheck.conf
   ```

3. Open UDP ports 3478 and 3479 in the VM's firewall / cloud security group.

## Verifying with natcheck

From any client network:

```sh
natcheck --server YOUR_PUBLIC_IP:3478 --json
```

The JSON output's top-level `"filtering"` object will show one of:

- `"endpoint-independent"` — most permissive; direct P2P likely
- `"address-dependent"` or `"address-and-port-dependent"` — restrictive; direct P2P possible (depends on ICE)
- `"untested"` — coturn isn't responding from the alt port (config or firewall problem)

Run from at least three different client networks (home, mobile hotspot, café Wi-Fi) to characterise your NAT against more than one source. After capture, tear down the VM — the diagnostic-posture config is not safe to leave running.

## What's NOT covered

- **CHANGE-IP** (RFC 5780 §7.2 bit A) requires coturn to listen on **two** IPs. The bundled config uses one IP and two ports, which only exercises bit B (CHANGE-PORT). For two-IP testing, add a second `listening-ip` line and ensure both addresses are reachable from the public internet.
- **Production hardening** — auth (`lt-cred-mech`), TLS (`tls-listening-port`, `cert`/`pkey`), rate limiting, persistence, metrics. coturn's own README covers these. natcheck doesn't and shouldn't.
- **Bundled `natcheck server` subcommand** — planned for v0.1.4 (see `docs/design.md` v0.2 addendum). Until then, coturn is the path.
