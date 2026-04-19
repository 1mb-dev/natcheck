// Command natcheck diagnoses NAT type using STUN probes.
//
// Scaffold only. See docs/PRD.md and docs/TRD.md for design. Implementation
// lands in phased PRs per docs/HANDOFF.md.
package main

import (
	"fmt"
	"os"
)

var version = "v0.1.0-dev"

func main() {
	fmt.Fprintf(os.Stderr, "natcheck %s - scaffold only, not implemented yet\n", version)
	fmt.Fprintln(os.Stderr, "See docs/PRD.md for scope, docs/HANDOFF.md for next steps.")
	os.Exit(2)
}
