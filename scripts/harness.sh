#!/usr/bin/env bash
# Create or delete all five clusters through the host service. The up command then builds the
# images and sets up the base cell on every cluster that has components in harness/topology.yaml,
# in topology order. cell:up of dev-cp also connects its secret store, as scripts/up.sh says.
# A cluster with link components (management) comes first with the link phase skipped, because its
# links need the other clusters. Its first link step runs only mgmt-api, right after its cell:up and
# before dev-cp. The same step runs again right after the cell:up of dev-cp, which adds the dev-cp
# root that mgmtd needs to accept envd. The full link phase runs last, with cell:link. When a step fails, the script
# prints that step and every later one. harness:down stops the host service first.
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
    linked=() early=() again=()
    for name in "${order[@]}"; do
      comps="$(CELL="$name" bash -c 'source "$1/scripts/lib.sh"; printf "%s\n" ${LINK_COMPONENTS[@]+"${LINK_COMPONENTS[@]%%:*}"}' _ "$ROOT")" \
        || die "could not read the component sets of $name"
      [[ -z "$comps" ]] || linked+=("$name")
      # mgmt-api runs right after the cluster is up, before dev-cp exists, because dev-cp reads its key.
      if grep -qx mgmt-api <<<"$comps"; then
        early+=("$name")
        # The cluster that holds the SPIRE server whose root mgmt-api needs, as <cluster>:<link cluster>.
        vcp="$(CELL="$name" bash -c 'source "$1/scripts/lib.sh"; printf "%s" "${VIEW_CONTROL_PLANE:-}"' _ "$ROOT")" \
          || die "could not read VIEW_CONTROL_PLANE of $name"
        [[ -z "$vcp" ]] || again+=("$vcp:$name")
      fi
    done
    # steps holds the commands of the order, as <environment>|<task>.
    steps=()
    for name in "${order[@]}"; do
      if [[ " ${linked[*]-} " == *" $name "* ]]; then
        steps+=("CELL_UP_SKIP_LINK=1 CELL=$name|cell:up")
      else
        steps+=("CELL=$name|cell:up")
      fi
      [[ " ${early[*]-} " != *" $name "* ]] || steps+=("CELL=$name LINK_ONLY=mgmt-api|cell:link")
      for pair in ${again[@]+"${again[@]}"}; do
        [[ "${pair%%:*}" != "$name" ]] || steps+=("CELL=${pair#*:} LINK_ONLY=mgmt-api|cell:link")
      done
    done
    for name in ${linked[@]+"${linked[@]}"}; do steps+=("CELL=$name|cell:link"); done
    for i in "${!steps[@]}"; do
      log "step $((i + 1)) of ${#steps[@]}: ${steps[$i]%%|*} mise run ${steps[$i]#*|}"
      # shellcheck disable=SC2086
      if ! env ${steps[$i]%%|*} mise run "${steps[$i]#*|}"; then
        log "${steps[$i]%%|*} mise run ${steps[$i]#*|} failed. Fix the cause, then run these commands in this order:"
        for ((j = i; j < ${#steps[@]}; j++)); do
          printf '  %s mise run %s\n' "${steps[$j]%%|*}" "${steps[$j]#*|}" >&2
        done
        exit 1
      fi
    done
    ;;
  down)
    # The host service runs the steps that create and admit cells. Stop it first, so that no stage runs while the
    # clusters go, and no step re-creates a cell that this command deletes.
    "${HOSTSVC_SERVE:-$ROOT/scripts/hostsvc-serve.sh}" stop
    mise run hostsvc -- down
    names="$(yq -r '.clusters[].name' "$topology")"
    [[ -n "$names" ]] || die "no cluster in $topology"
    for name in $names; do
      rm -rf "${BUILD_ROOT:?}/${name:?}"
    done
    ;;
  *) die "usage: harness.sh up|down" ;;
esac
