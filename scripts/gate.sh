#!/usr/bin/env bash
# Run the end-to-end tests of one milestone. Usage: gate.sh m1 [go test arguments]
# The run fails when it takes longer than GATE_<MILESTONE>_BUDGET_MINUTES in harness/versions.env.
source "$(dirname "$0")/lib.sh"

cd "$ROOT"
source "$ROOT/harness/versions.env"
milestone="${1:?usage: gate.sh m1|m2 [go test arguments]}"
shift
pattern="$(echo "$milestone" | tr '[:lower:]' '[:upper:]')"
budget_var="GATE_${pattern}_BUDGET_MINUTES"
budget_minutes="${!budget_var:-}"

# Build the test binary first, so that the budget covers only the test run.
build_start=$SECONDS
go test -tags e2e -count=1 -run '^$' ./test/e2e/ >/dev/null || die "the end-to-end tests do not build"
log "gate $milestone build took $((SECONDS - build_start))s"

start=$SECONDS
status=0
go test -tags e2e -count=1 -timeout 30m ./test/e2e/ -run "$pattern" "$@" || status=$?
elapsed=$((SECONDS - start))
log "gate $milestone tests took ${elapsed}s"

if [[ -n "$budget_minutes" ]] && ((elapsed > budget_minutes * 60)); then
  printf 'FAIL: gate %s took %ss, over the budget of %s minutes\n' "$milestone" "$elapsed" "$budget_minutes" >&2
  exit 1
fi
exit "$status"
