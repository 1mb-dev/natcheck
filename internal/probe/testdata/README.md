IANA IPv4 and IPv6 Special-Purpose Address Registries, CSV form, fetched 2026-11-27 (Last-Modified 2026-10-13) from:

- https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry-1.csv
- https://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry-1.csv

sha256:

    cbc4b7653c8bc640ba1e8e5d4ebbf11e7c7a1d867e7f1593aad001d3f8632aac  iana-ipv4-special-registry.csv
    bf56772aef97fbf9b4a27c98b8511f2bb1ba96da4b9ccc12ab203a2496faba66  iana-ipv6-special-registry.csv

To refresh: fetch both, replace these files, and update `specialRanges` in `../filtering.go` until `TestSpecialRanges_MatchIANARegistry` passes.
