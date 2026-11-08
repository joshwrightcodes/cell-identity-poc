#!/usr/bin/env bash
# Run the end-to-end tests of one milestone. Usage: gate.sh m1 [go test arguments]
source "$(dirname "$0")/lib.sh"

cd "$ROOT"
milestone="${1:?usage: gate.sh m1|m2 [go test arguments]}"
shift
pattern="$(echo "$milestone" | tr '[:lower:]' '[:upper:]')"
exec go test -tags e2e -count=1 -timeout 30m ./test/e2e/ -run "$pattern" "$@"
