#!/usr/bin/env bash
# The portal stand-in: mise run portal -- <command>. One command is one mgmtd ctl portal call and one commit.
#   request --cell <c>... [--wait]     Ask for cells. A cell that is requested already counts as a success.
#   wait --cell <c>...                 Poll mgmt -- status until each cell is valid.
#   withdraw --cell <c>...             Retire the cells and cancel their steps.
#   recreate --cell <c> [--wait]       Request a cell again after its cluster was deleted.
#   retry --cell <c> [--force] [--wait]  Sign a new step for a cell whose step failed, was refused, or expired. It refuses while the host
#                                      service shows the step in a running stage, unless --force. --force stays here, because mgmtd
#                                      refuses a force field.
#   cancel --cell <c>                  Drop the open step of a cell.
# request, recreate and retry run mise run hostsvc -- bootstrap-digest first, once, and send its digest with the call.
# wait and --wait poll every PORTAL_POLL_SECONDS seconds (default 15), for up to PORTAL_WAIT_SECONDS seconds (default 5400, 90
# minutes), until each named cell is valid. They log each change of the step state and the path of the step log to standard
# error, and they read the step by its ID, never by the cell, so the state of an older step never counts. A cell ends the wait
# when its step is refused, failed, failed_final or expired, and the hint is mise run portal -- retry --cell <c>. A timeout with
# the step still running gives mise run portal -- wait --cell <c>.
# Standard output holds one JSON line: the answer of mgmtd, with a field wait when the command waited. A refusal of mgmtd is one
# error line with the fields error and reason, and the exit status is 1. A wait that ends with a failed cell exits with 1.
# HOSTSVC_SERVE names another host service script, for the tests.
export CELL=management
source "$(dirname "$0")/lib.sh"

serve="${HOSTSVC_SERVE:-$ROOT/scripts/hostsvc-serve.sh}"
usage="usage: portal.sh request --cell <c>... [--wait] | wait --cell <c>... | withdraw --cell <c>... | recreate --cell <c> [--wait] | retry --cell <c> [--force] [--wait] | cancel --cell <c>"

command="${1:-}"
[[ -n "$command" ]] || json_fail portal "$usage"
shift
case "$command" in request | wait | withdraw | recreate | retry | cancel) ;; *) json_fail portal "unknown command '$command'; $usage" ;; esac

cells=() wait=0 force=0
while (($# > 0)); do
  case "$1" in
    --cell) [[ $# -ge 2 && "$2" != --* ]] || json_fail portal "--cell needs a cell name; $usage"; cells+=("$2"); shift 2 ;;
    --wait) [[ "$command" == request || "$command" == recreate || "$command" == retry ]] || json_fail portal "--wait does not apply to $command; $usage"; wait=1; shift ;;
    --force) [[ "$command" == retry ]] || json_fail portal "--force applies only to retry; $usage"; force=1; shift ;;
    *) json_fail portal "unknown argument '$1'; $usage" ;;
  esac
done
((${#cells[@]} > 0)) || json_fail portal "$command needs --cell; $usage"
case "$command" in recreate | retry | cancel) ((${#cells[@]} == 1)) || json_fail portal "$command takes exactly one --cell; $usage" ;; esac

cell_args=()
for c in "${cells[@]}"; do cell_args+=(--cell "$c"); done

# mgmt_call <args...> runs mise run mgmt -- <args> from the repository root. The output goes to standard output as it is.
mgmt_call() { (cd "$ROOT" && mise run mgmt -- "$@"); }

# running_stage <cell> prints "<id> <state>" when the host service shows a step of the cell in a stage.
running_stage() {
  local running json
  running="$("$serve" status | jq -r '.running')" || return 0
  [[ "$running" == true ]] || return 0
  json="$("$serve" steps)" || return 0
  jq -r --arg cell "$1" '.steps[]? | select(.cell == $cell)
    | select(.state == "creating" or .state == "admitting" or .state == "bootstrapping") | "\(.id) \(.state)"' <<<"$json" | head -n 1
}

digest=""
if [[ "$command" == request || "$command" == recreate || "$command" == retry ]]; then
  if [[ "$command" == retry && "$force" == 0 ]]; then
    stage="$(running_stage "${cells[0]}")"
    [[ -z "$stage" ]] || json_fail portal "the step ${stage% *} of ${cells[0]} runs a stage (${stage#* }), and a retry would cancel it. Wait for it with: mise run portal -- wait --cell ${cells[0]}. To cancel it anyway, add --force" reason=step_running
  fi
  digest_out="$(cd "$ROOT" && mise run hostsvc -- bootstrap-digest)" || json_fail portal "mise run hostsvc -- bootstrap-digest failed: ${digest_out:-no output}"
  digest="$(jq -r '.bootstrapSHA256 // ""' <<<"$digest_out")"
  [[ "$digest" =~ ^[0-9a-f]{64}$ ]] || json_fail portal "the bootstrap digest is '$digest', not 64 hexadecimal characters"
fi

result=""
if [[ "$command" != wait ]]; then
  args=(portal "$command" "${cell_args[@]}")
  [[ -z "$digest" ]] || args+=(--bootstrap-sha256 "$digest")
  rc=0
  result="$(mgmt_call "${args[@]}")" || rc=$?
  if ((rc != 0)); then
    printf '%s\n' "$result"
    exit "$rc"
  fi
  if ((!wait)); then
    printf '%s\n' "$result"
    exit 0
  fi
fi

# The wait. expected holds the step ID that the request signed for each cell, or nothing for a cell that has none.
poll="${PORTAL_POLL_SECONDS:-15}"
limit="${PORTAL_WAIT_SECONDS:-5400}"
expected=() last=() outcome=() detail=()
for c in "${cells[@]}"; do
  id=""
  [[ -z "$result" ]] || id="$(jq -r --arg c "$c" '[.steps[]? | select(.cell == $c) | .stepID][0] // ""' <<<"$result")"
  expected+=("$id") last+=("") outcome+=("") detail+=("{}")
done

# cell_view <status> <cell> <expected id> prints one JSON object: the view of the cell, read by the step ID.
cell_view() {
  jq -c --arg c "$2" --arg id "$3" '
    (.cells // [] | map(select(.name == $c))[0]) as $x
    | if $x == null then {cell: $c, present: false}
      else {cell: $c, present: true, valid: ($x.valid // false), validReason: ($x.validReason // ""), stepId: ($x.step.id // ""),
        current: ($id == "" or ($x.step.id // "") == $id), state: ($x.step.host.state // ""), detail: ($x.step.host.detail // ""),
        reason: ($x.step.host.reason // ""), expired: ((($x.step.expiresAt // "") != "") and (($x.step.expiresAt | sub("\\.[0-9]+Z$"; "Z") | fromdateiso8601? // 0) < now))} end' <<<"$1"
}

end=$((SECONDS + limit))
pending=1
while ((pending)); do
  status="$(mgmt_call status)" || json_fail portal "mise run mgmt -- status failed: ${status:-no output}. Run: CELL=management LINK_ONLY=mgmt-api mise run cell:link"
  pending=0
  for i in "${!cells[@]}"; do
    [[ -z "${outcome[$i]}" ]] || continue
    c="${cells[$i]}"
    view="$(cell_view "$status" "$c" "${expected[$i]}")"
    stepid="$(jq -r '.stepId // ""' <<<"$view")" state="$(jq -r '.state // ""' <<<"$view")" current="$(jq -r '.current // false' <<<"$view")"
    # A step that is not the one that was asked for is an older one, and its state says nothing about this request.
    [[ "$current" == true ]] || { state=""; stepid=""; }
    line="$c: step ${stepid:-none} ${state:-no host state}"
    if [[ "$line" != "${last[$i]}" ]]; then
      log "$line${stepid:+, log build/hostsvc/steps/$stepid.log}"
      last[$i]="$line"
    fi
    detail[$i]="$(jq -c --arg id "$stepid" --arg state "$state" '. + {stepId: $id, state: $state}' <<<"$view")"
    if [[ "$(jq -r '.valid // false' <<<"$view")" == true ]]; then
      outcome[$i]=valid
    elif [[ "$state" == failed || "$state" == failed_final || "$state" == refused ]]; then
      outcome[$i]="$state"
    elif [[ "$current" == true && "$(jq -r '.expired // false' <<<"$view")" == true ]]; then
      outcome[$i]=expired
    elif [[ "$(jq -r '.present // false' <<<"$view")" == false || "$(jq -r '.validReason // ""' <<<"$view")" == not_requested ]]; then
      outcome[$i]=not_requested
    else
      pending=1
    fi
  done
  if ((pending)); then
    if ((SECONDS >= end)); then
      for i in "${!cells[@]}"; do [[ -n "${outcome[$i]}" ]] || outcome[$i]=timeout; done
      break
    fi
    sleep "$poll"
  fi
done

# The hint of each final state is a command that the plane accepts in that state.
failed=0
summary='[]'
for i in "${!cells[@]}"; do
  c="${cells[$i]}"
  case "${outcome[$i]}" in
    valid) next="" ;;
    refused | failed | failed_final | expired) next="mise run portal -- retry --cell $c" ;;
    not_requested) next="mise run portal -- request --cell $c" ;;
    timeout) next="mise run portal -- wait --cell $c" ;;
  esac
  [[ "${outcome[$i]}" == valid ]] || failed=1
  [[ -z "$next" ]] || log "$c: ${outcome[$i]}. Run: $next"
  id="$(jq -r '.stepId // ""' <<<"${detail[$i]}")"
  summary="$(jq -c --arg c "$c" --arg o "${outcome[$i]}" --arg next "$next" --arg id "$id" --argjson d "${detail[$i]}" \
    '. + [{cell: $c, outcome: $o, stepId: $id, state: ($d.state // ""), detail: ($d.detail // ""), reason: ($d.reason // ""),
      log: (if $id == "" then "" else "build/hostsvc/steps/" + $id + ".log" end), next: $next}]' <<<"$summary")"
done
if [[ -n "$result" ]]; then
  jq -c --argjson cells "$summary" '. + {wait: {cells: $cells}}' <<<"$result"
else
  jq -nc --argjson cells "$summary" '{wait: {cells: $cells}}'
fi
exit "$failed"
