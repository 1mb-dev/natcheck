# Sample outputs

Real `natcheck` runs captured across networks. Any address that could identify a specific machine is redacted: public IPs to RFC 5737 (IPv4 `203.0.113.0/24`, `198.51.100.0/24`) and RFC 3849 (IPv6 `2001:db8::/32`) documentation ranges; private RFC 1918 source addresses to generic placeholders (e.g., `192.168.1.2`). Ports, RTTs, error message shapes, and external STUN server IPs (Google, Cloudflare) are real. Ephemeral test-infrastructure IPs (e.g., a destroy-after coturn droplet) are redacted to RFC 5737 placeholders since they get reassigned after destroy.

## Captured

Each sample states what it proves. Lab samples are real coturn and real Linux netfilter NAT on local Docker networks, not a consumer router.

| File | Network | Servers | Outcome |
|------|---------|---------|---------|
| [`ipv6-native.txt`](ipv6-native.txt) / [`.json`](ipv6-native.json) | Residential dual-stack, native IPv6 | default (Google + Cloudflare) | `possible`, equal mapped ports, `ipv4_untested`. Shows the false symmetric is gone; no NAT is involved, so it does not show cone detection |
| [`ipv4-symmetric.txt`](ipv4-symmetric.txt) / [`.json`](ipv4-symmetric.json) | Same network, IPv4 via A-record `--server` | Google `74.125.250.129:19302`, Cloudflare `162.159.207.0:3478` | ADM, `unlikely`, differing ports. This network's IPv4 NAT is genuinely symmetric |
| [`filtering.txt`](filtering.txt) / [`.json`](filtering.json) | Lab, client behind `MASQUERADE` | coturn on two IPs | EIM with address-and-port-dependent filtering, `possible` |
| [`symmetric.txt`](symmetric.txt) / [`.json`](symmetric.json) | Lab, client behind `MASQUERADE --random-fully` | coturn on two IPs | ADM, `unlikely`, differing ports |
| [`hairpinning.txt`](hairpinning.txt) / [`.json`](hairpinning.json) | Lab, no NAT | coturn on two IPs | EIM, endpoint-independent filtering, hairpinning true, `likely` |

## Contributing

Run `natcheck` and `natcheck --json`, redact public IPs to documentation ranges, commit the files here, and add a row to the table above.
