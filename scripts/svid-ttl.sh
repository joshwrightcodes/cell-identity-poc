#!/usr/bin/env bash
# Switch the SVID lifetime of dev-cp for the slow tier of gate:m9, and back.
#
# Usage:
#   svid-ttl.sh set <ttl>   write the lifetime to build/gate/m9-svid-ttl, run CELL=dev-cp mise run cell:up, and wait. It refuses while
#                           build/gate/m9-svid-ttl.restoring exists
#   svid-ttl.sh restore     write build/gate/m9-svid-ttl.restoring, remove the marker, run CELL=dev-cp mise run cell:up, then cell:restart
#                           of dev-cp and of each live cell, wait, and remove the stamp
#   svid-ttl.sh show        print the lifetimes of cells/dev-cp.env, of the marker and of the live server config
#
# scripts/lib.sh reads the marker for CELL=dev-cp, so the render of cell:up takes the lifetime from it. The switch goes through the signed
# path, so set and restore need dev-cp connected to management, as the Shared names value "Connected" of the M9 plan defines it. A lifetime
# equal to SPIRE_SVID_TTL of cells/dev-cp.env skips the switch of set. Any other lifetime must be 2.5 times that one or more, or 2.5 times less,
# because the wait can tell two lifetimes apart only then. The wait ends when the live agent_ttl is the new lifetime and every
# live agent has it (svid_ttl_settled in scripts/lib.sh). After a longer lifetime, set then waits one old lifetime, so that workload SVIDs
# renew too. After a shorter one, the cell:restart of restore gives every agent and workload a new SVID.
# SVID_TTL_WAIT bounds the wait in seconds. The default is half the longer of the two lifetimes plus 5 minutes, and at least 20 minutes:
# an agent that cell:restart did not reach would renew only when half its old lifetime is left. Every agent of the SPIRE server of dev-cp
# runs in a workload of dev-cp or of a cell, so restore restarts them all, and the bound is a margin. SVID_TTL_POLL sets the seconds between
# two checks (default 10). Each command prints one JSON line. A failed set keeps the marker, and a failed restore keeps the stamp
# build/gate/m9-svid-ttl.restoring, so every other gate refuses and mise run gate:m9:repair finds it. scripts/lib.sh does not read the stamp,
# so a render takes the lifetime of cells/dev-cp.env, and scripts/bundle.sh counts it as an input of dev-cp.
export CELL=dev-cp
source "$(dirname "$0")/lib.sh"
source "$ROOT/components/lib/operator-key.sh"

usage() { die "usage: svid-ttl set <ttl> | restore | show"; }

# connected <what> stops the script unless dev-cp is connected to management.
connected() {
  local reason
  reason="$(operator_connected 2>&1)" \
    || die "$1 goes through the signed path, so it needs dev-cp connected to management, and the check says: ${reason#error: }. Repair it with: mise run gate:m9:repair"
}

# wait_settled <ttl> <old ttl> waits until the live agent_ttl of dev-cp is <ttl> and every live agent has it, then waits one old lifetime when
# <ttl> is the longer one.
wait_settled() {
  local ttl="$1" old="$2" want have bound poll waited=0 live reason
  want="$(ttl_seconds "$ttl")"
  have="$(ttl_seconds "$old" 2>/dev/null)" || have=0
  bound=$(((want > have ? want : have) / 2 + 300))
  ((bound >= 1200)) || bound=1200
  bound="${SVID_TTL_WAIT:-$bound}"
  poll="${SVID_TTL_POLL:-10}"
  log "waiting up to ${bound}s until every SVID of dev-cp has the lifetime $ttl"
  while :; do
    if ! live="$(svid_ttl_live 2>/dev/null)"; then
      reason="the server config of dev-cp could not be read"
    elif [[ "$live" != "$ttl" ]]; then
      reason="the live server config of dev-cp sets agent_ttl '$live'"
    elif reason="$(svid_ttl_settled "$ttl" 2>&1)"; then
      break
    fi
    ((waited < bound)) || die "the SVIDs of dev-cp did not settle at $ttl within ${bound}s: $reason. Read the lifetimes with: mise run svid-ttl -- show. Then run: mise run gate:m9:repair"
    sleep "$poll"
    waited=$((waited + poll))
  done
  if ((want > have && have > 0)); then
    log "every agent of dev-cp has the lifetime $ttl. Waiting one old lifetime ($old), so that workload SVIDs renew too"
    sleep "$have"
  fi
}

cmd_set() {
  local ttl="${1:-}" file live have start small big
  (($# == 1)) || usage
  [[ "$ttl" =~ ^[1-9][0-9]*[smh]$ ]] && (($(ttl_seconds "$ttl") >= 60)) \
    || die "the lifetime '$ttl' is not of the form <n>s, <n>m or <n>h with 1m or more, such as 1h"
  [[ ! -e "$SVID_TTL_MARKER.restoring" ]] \
    || die "an earlier restore of the SVID lifetime did not finish, so build/gate/m9-svid-ttl.restoring exists and a new switch would hide it. Run: mise run svid-ttl -- restore"
  file="$(svid_ttl_file)"
  if [[ "$ttl" != "$file" ]]; then
    small="$(ttl_seconds "$file")" big="$(ttl_seconds "$ttl")"
    ((small < big)) || { small="$big" big="$(ttl_seconds "$file")"; }
    ((big * 2 >= small * 5)) \
      || die "the lifetime $ttl is less than 2.5 times apart from SPIRE_SVID_TTL=$file of cells/dev-cp.env, so the wait cannot tell the two apart. Take a lifetime of $(((small * 5 + 1) / 2))s or more"
  fi
  if [[ -e "$SVID_TTL_MARKER" ]]; then
    have="$(tr -d '[:space:]' <"$SVID_TTL_MARKER")"
    [[ "$have" == "$ttl" ]] \
      || die "the slow-tier marker build/gate/m9-svid-ttl holds $have, so another slow tier runs or stopped early. Repair it with: mise run gate:m9:repair"
  fi
  live="$(svid_ttl_live)" || die "could not read agent_ttl of the SPIRE server config in dev-cp. Run: mise run harness:status"
  if [[ "$ttl" == "$file" && ! -e "$SVID_TTL_MARKER" ]]; then
    [[ "$live" == "$file" ]] \
      || die "the SPIRE server of dev-cp sets agent_ttl '$live', and cells/dev-cp.env sets SPIRE_SVID_TTL=$file, with no slow-tier marker. Repair it with: mise run gate:m9:repair"
    log "the lifetime $ttl is the one of cells/dev-cp.env, so the switch is skipped"
    jq -nc --arg ttl "$ttl" '{ttl: $ttl, switched: false, seconds: 0}'
    return
  fi
  connected "the switch of the SVID lifetime"
  start="$(date +%s)"
  mkdir -p "$(dirname "$SVID_TTL_MARKER")"
  printf '%s\n' "$ttl" >"$SVID_TTL_MARKER"
  log "the slow-tier marker holds $ttl. Rendering dev-cp"
  CELL=dev-cp mise run cell:up || die "CELL=dev-cp mise run cell:up failed with the slow-tier marker in place. Repair it with: mise run gate:m9:repair"
  wait_settled "$ttl" "$live"
  jq -nc --arg ttl "$ttl" --arg from "$live" --argjson seconds "$(($(date +%s) - start))" '{ttl: $ttl, from: $from, switched: true, seconds: $seconds}'
}

cmd_restore() {
  local file live cells c start
  (($# == 0)) || usage
  file="$(svid_ttl_file)"
  live="$(svid_ttl_live 2>/dev/null)" || live=""
  connected "the restore of the SVID lifetime"
  start="$(date +%s)"
  # The stamp stays until every SVID has the lifetime of the file. A marker that goes leaves no file, so the stamp also tells the stale-build
  # rule of scripts/bundle.sh that the render of dev-cp changed.
  mkdir -p "$(dirname "$SVID_TTL_MARKER")"
  touch "$SVID_TTL_MARKER.restoring"
  rm -f "$SVID_TTL_MARKER"
  log "the slow-tier marker is gone. Rendering dev-cp with SPIRE_SVID_TTL=$file of cells/dev-cp.env"
  CELL=dev-cp mise run cell:up || die "CELL=dev-cp mise run cell:up failed. Run: mise run svid-ttl -- restore"
  cells="$(live_cells)" || die "the live cells are unknown, so their agents keep the old SVIDs. Run: mise run svid-ttl -- restore"
  for c in dev-cp $cells; do
    log "restarting $c, so that its agents and workloads get SVIDs of $file"
    CELL="$c" mise run cell:restart || die "CELL=$c mise run cell:restart failed. Run: mise run svid-ttl -- restore"
  done
  wait_settled "$file" "$live"
  rm -f "$SVID_TTL_MARKER.restoring"
  jq -nc --arg ttl "$file" --arg from "$live" --argjson seconds "$(($(date +%s) - start))" '{ttl: $ttl, from: $from, restored: true, seconds: $seconds}'
}

sub="${1:-}"
(($#)) && shift
case "$sub" in
  set) cmd_set "$@" ;;
  restore) cmd_restore "$@" ;;
  show) (($# == 0)) || usage; svid_ttl_json ;;
  *) usage ;;
esac
