// Command natcheck diagnoses NAT type using STUN probes.
//
// See docs/design.md for the spec.
package main

import (
	"context"
	"os"

	"github.com/1mb-dev/natcheck/internal/cli"
)

// version is overridden at build time via ldflags:
//
//	go build -ldflags "-X main.version=v0.1.0"
var version = "dev"

func main() {
	cli.Version = version
	os.Exit(cli.Run(context.Background(), os.Args[1:], os.Stdout, os.Stderr))
}
