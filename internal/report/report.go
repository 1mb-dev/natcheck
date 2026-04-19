// Package report renders verdicts as human-readable text or JSON.
//
// The human format is hand-rolled and forecast-first: the Direct P2P line
// leads so the WebRTC-developer persona gets the answer on line 1. The JSON
// format is a public contract pinned by golden-file tests; only additive
// changes are permitted after v0.1. See docs/design.md §UX shape.
package report

import (
	"fmt"
	"io"

	"github.com/1mb-dev/natcheck/internal/classify"
	"github.com/1mb-dev/natcheck/internal/probe"
)

// Format selects the output format for Render.
type Format int

const (
	// FormatHuman produces a screen-friendly report leading with the forecast.
	FormatHuman Format = iota
	// FormatJSON produces the machine-readable report. The schema is a public
	// contract from v0.1 onward; only additive changes permitted.
	FormatJSON
)

// Render writes a Verdict + probe results to w in the requested format.
// Writer and encoding errors are returned verbatim.
func Render(w io.Writer, v classify.Verdict, probes []probe.Result, format Format) error {
	switch format {
	case FormatHuman:
		return renderHuman(w, v, probes)
	case FormatJSON:
		return renderJSON(w, v, probes)
	default:
		return fmt.Errorf("unknown report format: %d", format)
	}
}
