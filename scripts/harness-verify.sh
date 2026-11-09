#!/usr/bin/env bash
# Run cell:verify on every cluster that has components in harness/topology.yaml, in topology
# order. A failed cluster does not stop the others. The summary at the end names each cluster.
source "$(dirname "$0")/lib.sh"

cd "$ROOT"
names="$(yq -r '.clusters[] | select(.components | length > 0) | .name' "$ROOT/harness/topology.yaml")"
[[ -n "$names" ]] || die "no cluster in harness/topology.yaml has components"
summary=()
failed=0
for name in $names; do
  log "verifying $name"
  if CELL="$name" mise run cell:verify; then
    summary+=("PASS  $name")
  else
    summary+=("FAIL  $name: run CELL=$name mise run cell:verify for the details")
    failed=$((failed + 1))
  fi
done
printf '%s\n' "${summary[@]}"
((failed == 0)) || die "$failed cluster(s) failed cell:verify"
log "every cluster passed cell:verify"
