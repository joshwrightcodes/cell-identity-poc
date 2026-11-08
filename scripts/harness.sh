#!/usr/bin/env bash
# Create or delete all five clusters through the host service. The up command then sets up the
# base cell on every cluster that has components in harness/topology.yaml.
source "$(dirname "$0")/lib.sh"

cd "$ROOT"
topology="$ROOT/harness/topology.yaml"

case "${1:-}" in
  up)
    mise run hostsvc -- up
    names="$(yq -r '.clusters[] | select(.components | length > 0) | .name' "$topology")"
    [[ -n "$names" ]] || die "no cluster in $topology has components"
    for name in $names; do
      log "setting up the base cell on $name"
      CELL="$name" mise run cell:up
    done
    ;;
  down)
    mise run hostsvc -- down
    names="$(yq -r '.clusters[].name' "$topology")"
    [[ -n "$names" ]] || die "no cluster in $topology"
    for name in $names; do
      rm -rf "${BUILD_ROOT:?}/${name:?}"
    done
    ;;
  *) die "usage: harness.sh up|down" ;;
esac
