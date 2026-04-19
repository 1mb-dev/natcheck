#!/usr/bin/env bash
# ci-guard.sh — fail the build if the current network can't support direct P2P.
# Uses natcheck's --json output + jq. Drop into your CI pipeline as a gate.
#
# Required in $PATH: natcheck, jq.
# natcheck exit codes already encode the answer (0/1/2); this script parses
# JSON instead to demonstrate the full interface and surface richer detail.

set -uo pipefail

output=$(natcheck --json --timeout 10s)
natcheck_exit=$?

if [ "$natcheck_exit" -eq 2 ]; then
  echo "natcheck: probe or flag error (exit 2)" >&2
  echo "$output" >&2
  exit 2
fi

forecast=$(echo "$output" | jq -r '.webrtc_forecast.direct_p2p')

case "$forecast" in
  likely|possible)
    echo "P2P: $forecast — proceeding"
    ;;
  unlikely|unknown)
    echo "P2P: $forecast — build should not assume direct P2P" >&2
    echo "$output" | jq . >&2
    exit 1
    ;;
  *)
    echo "P2P: unrecognized forecast ($forecast)" >&2
    exit 2
    ;;
esac
