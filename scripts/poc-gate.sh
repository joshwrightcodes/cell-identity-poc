#!/usr/bin/env bash
# Run the gates of the PoC as tiers. Usage: poc-gate.sh fast|slow|all
#   fast  gate:m1 to gate:m8 and gate:m15, with gate:m6:provision after gate:m6. It stops at the first failure. GATE_FAST_BUDGET_MINUTES in
#         harness/versions.env bounds the tier when it is set.
#   slow  gate:m9, the slow tier at the SVID lifetime of GATE_M9_SVID_TTL, which takes the night.
#   all   fast, then slow.
# gate:m4:rotate, gate:m5:soak and gate:m5:drill stay manual drills. The script runs under keep_awake, and it refuses a start on battery
# power unless GATE_ALLOW_BATTERY=1. It prints one JSON line with the tier, the gates that passed and the seconds.
source "$(dirname "$0")/lib.sh"

tier="${1:-}"
case "$tier" in
  fast | slow | all) ;;
  *) die "usage: poc-gate.sh fast|slow|all" ;;
esac
(($# == 1)) || die "usage: poc-gate.sh fast|slow|all"
keep_awake "$@"
refuse_battery
cd "$ROOT"
source "$ROOT/harness/versions.env"

fast=(gate:m1 gate:m2 gate:m3 gate:m4 gate:m5 gate:m6 gate:m6:provision gate:m7 gate:m8 gate:m15)
passed=()
start="$(date +%s)"

# run_gates <gate...> runs each gate in order and stops at the first failure.
run_gates() {
  local gate began
  for gate in "$@"; do
    began="$(date +%s)"
    log "poc:gate runs $gate"
    mise run "$gate" || die "$gate failed after $(($(date +%s) - began))s, so poc:gate $tier stops. Passed: ${passed[*]:-none}"
    log "$gate passed in $(($(date +%s) - began))s"
    passed+=("$gate")
  done
}

if [[ "$tier" == fast || "$tier" == all ]]; then
  run_gates "${fast[@]}"
  took=$(($(date +%s) - start))
  if [[ -n "${GATE_FAST_BUDGET_MINUTES:-}" ]] && ((took > GATE_FAST_BUDGET_MINUTES * 60)); then
    die "the fast tier took ${took}s, over the budget of $GATE_FAST_BUDGET_MINUTES minutes (GATE_FAST_BUDGET_MINUTES)"
  fi
  log "the fast tier passed in ${took}s"
fi
[[ "$tier" == fast ]] || run_gates gate:m9
jq -nc --arg tier "$tier" --argjson seconds "$(($(date +%s) - start))" '{tier: $tier, passed: $ARGS.positional, seconds: $seconds}' --args ${passed[@]+"${passed[@]}"}
