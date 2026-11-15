#!/usr/bin/env bash
# Look at signed work: mise run ops -- trace <id> | close <id>.
#   trace  prints one JSON line with the operation that mgmtd holds (without its envelopes) and each row of the gateway queue
#          that carries the ID, as {id, op, queue: [{cell, ...row}]}. The cell comes from the operation. For an ID that
#          mgmtd does not hold, for example a forged one, op is null and the script reads the queue of each cell of the topology.
#          The refusals of mgmtd carry no cell, so the trace does not join them.
#   close  closes an open or expired operation with a refusal that mgmtd signs, and prints the answer of mgmtd.
# A failure prints one JSON error line on standard output and exits with status 1, like mgmt.sh and gw.sh. MGMT_SCRIPT and
# GW_SCRIPT name other scripts, for the tests.
export CELL=dev-cp
source "$(dirname "$0")/lib.sh"

mgmt="${MGMT_SCRIPT:-$ROOT/scripts/mgmt.sh}"
gw="${GW_SCRIPT:-$ROOT/scripts/gw.sh}"
usage="usage: mise run ops -- trace <id> | close <id>"

cmd="${1:-}"
id="${2:-}"
[[ "$cmd" == trace || "$cmd" == close ]] || json_fail ops "unknown command '$cmd'. $usage"
[[ -n "$id" && $# -eq 2 ]] || json_fail ops "$cmd needs one operation ID. $usage"
[[ "$id" =~ ^[0-9a-f]{32}$ ]] || json_fail ops "'$id' is no operation ID, which holds 32 lower-case hexadecimal digits"

# reason prints the error of a JSON error line, or the raw text.
reason() { jq -Rsr '(split("\n") | map(fromjson? | select(type == "object")) | .[0]) as $o | $o.error // .' <<<"$1"; }

if [[ "$cmd" == close ]]; then
  rc=0
  out="$("$mgmt" op close "$id")" || rc=$?
  ((rc == 0)) || json_fail ops "mise run mgmt -- op close failed: $(reason "$out")"
  printf '%s\n' "$out"
  exit 0
fi

rc=0
got="$("$mgmt" op get "$id" 2>/dev/null)" || rc=$?
cells=()
op=null
if ((rc == 0)); then
  jq -e 'type == "object" and .id != null' >/dev/null 2>&1 <<<"$got" || json_fail ops "mise run mgmt -- op get printed no operation: $got"
  op="$(jq -c 'del(.envelope, .envelopes)' <<<"$got")"
  cells=("$(jq -r .cell <<<"$got")")
elif [[ "$(jq -Rsr '(split("\n") | map(fromjson? | select(type == "object")) | .[0].reason) // ""' <<<"$got")" == operation_unknown ]]; then
  while IFS= read -r c; do cells+=("$c"); done < <(yq -r '.clusters[] | select(.components[] == "cell-identity") | .name' "$ROOT/harness/topology.yaml")
else
  json_fail ops "mise run mgmt -- op get failed: $(reason "$got")"
fi

rows='[]'
for c in "${cells[@]}"; do
  rc=0
  q="$("$gw" queue --cell "$c")" || rc=$?
  ((rc == 0)) || json_fail ops "mise run gw -- queue --cell $c failed: $(reason "$q")"
  rows="$(jq -c --arg id "$id" --arg c "$c" --argjson rows "$rows" '$rows + [(.items // [])[] | select(.opId == $id) | {cell: $c} + .]' <<<"$q")" \
    || json_fail ops "mise run gw -- queue --cell $c printed no queue: $q"
done
jq -nc --arg id "$id" --argjson op "$op" --argjson queue "$rows" '{id: $id, op: $op, queue: $queue}'
