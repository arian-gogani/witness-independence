#!/usr/bin/env bash
# Run every vector and compare the measured level to the expected one.
#
# This script returns the result. A suite that prints a failure and exits 0 is
# not a suite, and that failure is the reason this file has an explicit exit.
set -uo pipefail
cd "$(dirname "$0")"

TRUST="anchors/trust-set.json"
GRAPH="anchors/operator-graph.json"
FAILED=0
TOTAL=0

printf '%-32s %-6s %-6s %s\n' VECTOR EXPECT ACTUAL RESULT
printf '%-32s %-6s %-6s %s\n' "--------------------------------" "------" "------" "------"

for f in vectors/*.json; do
    name=$(basename "$f" .json)
    TOTAL=$((TOTAL + 1))
    g="$GRAPH"
    case "$name" in A7-*) g="anchors/operator-graph-silent.json";; esac
    out=$(python3 -m wil.cli "$f" --trust-set "$TRUST" --operator-graph "$g" --json 2>&1)
    rc=$?
    expect=$(printf '%s' "$out" | python3 -c "import json,sys; print(json.load(sys.stdin).get('expected','?'))" 2>/dev/null || echo "?")
    actual=$(printf '%s' "$out" | python3 -c "import json,sys; print(json.load(sys.stdin).get('set_level','ERR'))" 2>/dev/null || echo "ERR")
    if [ "$rc" -eq 0 ] && [ "$expect" = "$actual" ]; then
        printf '%-32s %-6s %-6s %s\n' "$name" "$expect" "$actual" "pass"
    else
        printf '%-32s %-6s %-6s %s\n' "$name" "$expect" "$actual" "FAIL"
        FAILED=$((FAILED + 1))
    fi
done

echo
echo "$((TOTAL - FAILED)) of $TOTAL vectors matched."
if [ "$FAILED" -ne 0 ]; then
    echo "NON-CONFORMANT: $FAILED vector(s) did not match."
    exit 1
fi
echo "CONFORMANT"
exit 0
