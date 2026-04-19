package main

import "testing"

func TestResolveVersion_LdflagsOverride(t *testing.T) {
	saved := version
	t.Cleanup(func() { version = saved })

	version = "v9.9.9"
	if got := resolveVersion(); got != "v9.9.9" {
		t.Errorf("resolveVersion() = %q, want v9.9.9", got)
	}
}
