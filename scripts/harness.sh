#!/usr/bin/env bash
# Create or delete all five clusters through the host service. The up command then builds the
# images and sets up the base cell on every cluster that has components in harness/topology.yaml,
# in topology order. cell:up of dev-cp also connects its secret store, as scripts/up.sh says.
# A cluster with link components (management) comes first with the link phase skipped, because its
# links need the other clusters. Its link phase runs last, with cell:link.
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
    linked=()
    for name in "${order[@]}"; do
      n="$(CELL="$name" bash -c 'source "$1/scripts/lib.sh"; echo "${#LINK_COMPONENTS[@]}"' _ "$ROOT")" \
        || die "could not read the component sets of $name"
      ((n == 0)) || linked+=("$name")
    done
    # remaining <index> prints the commands that finish the harness from step <index>.
    remaining() {
      local name i="$1"
      for name in "${order[@]:$i}"; do
        if [[ " ${linked[*]-} " == *" $name "* ]]; then
          printf '  CELL_UP_SKIP_LINK=1 CELL=%s mise run cell:up\n' "$name" >&2
        else
          printf '  CELL=%s mise run cell:up\n' "$name" >&2
        fi
      done
      for name in ${linked[@]+"${linked[@]}"}; do
        printf '  CELL=%s mise run cell:link\n' "$name" >&2
      done
    }
    for i in "${!order[@]}"; do
      log "setting up the base cell on ${order[$i]}"
      skip=""
      [[ " ${linked[*]-} " == *" ${order[$i]} "* ]] && skip=1
      if ! CELL_UP_SKIP_LINK="$skip" CELL="${order[$i]}" mise run cell:up; then
        log "cell:up of ${order[$i]} failed. Fix the cause, then run these commands in this order:"
        remaining "$i"
        exit 1
      fi
    done
    for name in ${linked[@]+"${linked[@]}"}; do
      log "running the link phase of $name"
      if ! CELL="$name" mise run cell:link; then
        log "cell:link of $name failed. Fix the cause, then run: CELL=$name mise run cell:link"
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
