#!/usr/bin/env bash
# Create or delete all five clusters through the host service. The up command then builds the
# images and sets up the base cell on every cluster that has components in harness/topology.yaml,
# in topology order. cell:up of dev-cp also connects its secret store, as scripts/up.sh says.
source "$(dirname "$0")/lib.sh"

cd "$ROOT"
topology="$ROOT/harness/topology.yaml"

case "${1:-}" in
  up)
    mise run hostsvc -- up
    # The dev-cp render reads the plugin images from the local registry.
    mise run images
    names="$(yq -r '.clusters[] | select(.components | length > 0) | .name' "$topology")"
    [[ -n "$names" ]] || die "no cluster in $topology has components"
    read -r -a order <<<"$(echo $names)"
    for i in "${!order[@]}"; do
      log "setting up the base cell on ${order[$i]}"
      if ! CELL="${order[$i]}" mise run cell:up; then
        log "cell:up of ${order[$i]} failed. Fix the cause, then run these commands in this order:"
        for name in "${order[@]:$i}"; do
          printf '  CELL=%s mise run cell:up\n' "$name" >&2
        done
        exit 1
      fi
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
