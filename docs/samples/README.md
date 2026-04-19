# Sample outputs

Real `natcheck` runs captured across networks. Any address that could identify a specific machine is redacted: public IPs to RFC 5737 (IPv4 `203.0.113.0/24`) and RFC 3849 (IPv6 `2001:db8::/32`) documentation ranges; private RFC 1918 source addresses to generic placeholders (e.g., `192.168.1.2`). Ports, RTTs, error message shapes, and external STUN server IPs are real.

## Captured

| File | Network | Servers | Outcome |
|------|---------|---------|---------|
| [`dev-machine-default.txt`](dev-machine-default.txt) / [`.json`](dev-machine-default.json) | Residential dual-stack (IPv4 + IPv6) | default (Google + Cloudflare) | IPv6 preferred by DNS; Google IPv6 responds; Cloudflare IPv6 times out → 1/2 probes → `Unknown` verdict, exit 1 |
| [`dev-machine-ipv4.txt`](dev-machine-ipv4.txt) / [`.json`](dev-machine-ipv4.json) | Same network, IPv4-forced via A-record `--server` | Google `74.125.250.129:19302`, Cloudflare `162.159.207.0:3478` | Google IPv4 responds; Cloudflare IPv4 also times out → same `Unknown` verdict |

## Contributing

Run `natcheck` and `natcheck --json`, redact public IPs to documentation ranges, commit the files here, and add a row to the table above.
