// Command natcheck diagnoses NAT type using STUN probes.
//
// See docs/design.md for the spec.
package main

import (
	"context"
	"os"
	"runtime/debug"

	"github.com/1mb-dev/natcheck/internal/cli"
)

// version is overridden at build time via ldflags:
//
//	go build -ldflags "-X main.version=v0.1.0"
//
// When built via `go install github.com/1mb-dev/natcheck/cmd/natcheck@vX.Y.Z`
// (no ldflags), resolveVersion falls back to runtime/debug.ReadBuildInfo so
// the installed binary still reports the correct tag.
var version = "dev"

func resolveVersion() string {
	if version != "dev" {
		return version
	}
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
		return info.Main.Version
	}
	return "dev"
}

func main() {
	cli.Version = resolveVersion()
	os.Exit(cli.Run(context.Background(), os.Args[1:], os.Stdout, os.Stderr))
}
