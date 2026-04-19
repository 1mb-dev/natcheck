// Command natcheck diagnoses NAT type using STUN probes.
//
// Scaffold only. See docs/design.md for the spec.
package main

import (
	"fmt"
	"os"
)

var version = "v0.1.0-dev"

func main() {
	fmt.Fprintf(os.Stderr, "natcheck %s - scaffold only, not implemented yet\n", version)
	fmt.Fprintln(os.Stderr, "See docs/design.md for the spec.")
	os.Exit(2)
}
