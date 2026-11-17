# shellcheck shell=bash disable=SC2034
# Read the step journal of the host service on this Mac. Source this file after scripts/lib.sh. harness:status and
# gate:m6:repair use it, so both find a stuck step by the same rules.
#
# The host service writes the journal times, the heartbeats and the step log headers with the clock of the Mac, so these
# functions compare them with the clock of the Mac (date +%s), never with the clock of a node.

# The stage timeouts in seconds. They are the timeouts of the stages in internal/hostsvc/actor.go.
STEP_TIMEOUT_creating=600
STEP_TIMEOUT_admitting=1800
STEP_TIMEOUT_bootstrapping=2700
# A running stage that is older than its timeout plus this time is stuck.
STEP_STAGE_GRACE=300
# A heartbeat older than this many seconds means that no stage runs.
STEP_HEARTBEAT_MAX=120

# steps_dir prints the directory of the journal. HOSTSVC_STEPS_DIR names another one, for the tests.
steps_dir() { printf '%s\n' "${HOSTSVC_STEPS_DIR:-$BUILD_ROOT/hostsvc/steps}"; }

# journal_states prints the state of each journal entry, one on each line. It prints nothing when the journal is absent, and it
# returns 1 when the journal does not parse.
journal_states() {
  local file
  file="$(steps_dir)/journal.json"
  [[ -f "$file" ]] || return 0
  jq -r '.entries[]?.status.state' "$file"
}

# stuck_steps <now> prints one line for each journal entry that runs a stage and looks stuck, as "<id> <cell> <state> <kind> <seconds>
# <limit>". now is the time of the Mac in epoch seconds. The kind is heartbeat (the heartbeat is older than 2 minutes, in seconds) or
# stage (the stage runs longer than its timeout plus 5 minutes, in seconds, with the limit in seconds). The actor writes a heartbeat only
# while a stage runs or a re-sign hold waits, so an entry that waits in another state is never stuck. The time that the stage started is
# in the last header line of the step log: "== <stage> attempt <n> CELL=<cluster> at <RFC 3339>". The function returns 1 when the
# journal does not parse. It never prints the content of a log line other than that time.
stuck_steps() {
  local now="$1" dir file rows id cell state hb log header at start limit var
  dir="$(steps_dir)"
  file="$dir/journal.json"
  [[ -f "$file" ]] || return 0
  rows="$(jq -r 'def ts: sub("\\.[0-9]+"; "") | if test("Z$") then fromdateiso8601
        else (capture("^(?<d>.*)(?<s>[+-])(?<h>[0-9]{2}):(?<m>[0-9]{2})$") | ((.d + "Z" | fromdateiso8601) - (if .s == "+" then 1 else -1 end) * ((.h | tonumber) * 3600 + (.m | tonumber) * 60))) end;
      .entries[]? | select(.status.state == "creating" or .status.state == "admitting" or .status.state == "bootstrapping")
      | [.status.id, .status.cell, .status.state, ((.heartbeatAt // "") | if . == "" then 0 else ts end)] | @tsv' "$file")" || return 1
  while IFS=$'\t' read -r id cell state hb; do
    [[ -n "$id" ]] || continue
    if ((hb > 1000000000 && now - hb > STEP_HEARTBEAT_MAX)); then
      printf '%s %s %s heartbeat %s %s\n' "$id" "$cell" "$state" "$((now - hb))" "$STEP_HEARTBEAT_MAX"
    fi
    log="$dir/$id.log"
    [[ -r "$log" ]] || continue
    header="$(grep '^== ' "$log" | tail -n 1)" || header=""
    [[ "$header" == *" at "* ]] || continue
    at="${header##* at }"
    start="$(jq -nr --arg t "$at" '$t | fromdateiso8601' 2>/dev/null)" || continue
    var="STEP_TIMEOUT_$state"
    limit=$((${!var} + STEP_STAGE_GRACE))
    if ((start > 1000000000 && now - start > limit)); then
      printf '%s %s %s stage %s %s\n' "$id" "$cell" "$state" "$((now - start))" "$limit"
    fi
  done <<<"$rows"
}
