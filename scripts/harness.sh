#!/usr/bin/env bash
# Create or delete all five clusters. The up command creates management, dev-cp and rogue through the host service, builds the
# images and sets up the base cell on every other cluster that has components in harness/topology.yaml, in topology order. A
# cluster with the cell-identity set (a cell) gets no cell:up: the host service creates a cell only for a signed step, so
# the portal request asks for every cell and the portal wait polls until each one is valid. A request for a cell that is already
# requested counts as a success, so the two commands are safe to run again. cell:up of dev-cp also connects its secret store, as
# scripts/up.sh says.
# A cluster with link components (management) comes first with the link phase skipped, because its links need the other clusters.
# Its first link step runs only mgmt-api, right after its cell:up and before dev-cp. The same step runs again right after the
# cell:up of dev-cp, which adds the dev-cp root that mgmtd needs to accept envd. The full link phase runs last, with cell:link,
# after the cells are valid. The last step publishes a signed bundle set to each cell (bundle -- publish --wait). When a step
# fails, the script prints that step and every later one. harness:down stops the host service first.
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
    cells="$(catalog_cells)" || die "could not read the cells of $topology"
    linked=() early=() again=() cellargs=() targetargs=()
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
    # steps holds the commands of the order, as <environment>|<arguments of mise run>.
    steps=()
    for name in "${order[@]}"; do
      # A cell exists only through its signed step, so cell:up of a cell would refuse. The portal steps follow the loop.
      if grep -qx -- "$name" <<<"$cells"; then
        cellargs+=(--cell "$name")
        targetargs+=(--target "$name")
        continue
      fi
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
    # The request skips a cell that mgmtd holds already, and the wait ends when each cell is valid, so a second run
    # of harness:up, or a rerun after a failed step, reaches the same end.
    if ((${#cellargs[@]} > 0)); then
      steps+=("|portal -- request ${cellargs[*]}" "|portal -- wait ${cellargs[*]}")
    fi
    for name in ${linked[@]+"${linked[@]}"}; do steps+=("CELL=$name|cell:link"); done
    # Each cell applies its own signed set. The last step signs one set for every cell of the catalog and waits until each cell is healthy.
    if ((${#targetargs[@]} > 0)); then
      steps+=("|bundle -- publish ${targetargs[*]} --wait")
    fi
    # show_step <entry> prints the command of a step as a person types it.
    show_step() { local env="${1%%|*}"; printf '%smise run %s' "${env:+$env }" "${1#*|}"; }
    for i in "${!steps[@]}"; do
      log "step $((i + 1)) of ${#steps[@]}: $(show_step "${steps[$i]}")"
      # The arguments of mise run are words, so they split here on purpose.
      # shellcheck disable=SC2086
      if ! env ${steps[$i]%%|*} mise run ${steps[$i]#*|}; then
        log "$(show_step "${steps[$i]}") failed. Fix the cause, then run these commands in this order:"
        for ((j = i; j < ${#steps[@]}; j++)); do
          printf '  %s\n' "$(show_step "${steps[$j]}")" >&2
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
    # The journal, the step logs and the stored spec name clusters that go now. The log of the service and its key files stay.
    rm -rf "${BUILD_ROOT:?}/hostsvc/steps"
    # The marker of gate:m6:provision names cells that go now, and gate:m6:repair would take a healthy new harness for an interrupted run.
    rm -f "${BUILD_ROOT:?}/gate/m6-provision"
    names="$(yq -r '.clusters[].name' "$topology")"
    [[ -n "$names" ]] || die "no cluster in $topology"
    for name in $names; do
      rm -rf "${BUILD_ROOT:?}/${name:?}"
    done
    ;;
  *) die "usage: harness.sh up|down" ;;
esac
