#!/usr/bin/env bash
# Revoke a cell on this Mac while the environment is cut off from management: mise run revoke -- local|list|reapply|clean.
#
# A local revocation entry is a DSSE envelope that the operator key signs. It names the cell and the revision of the cell record that
# envd holds. The entry only narrows trust. envd reads the entries from ConfigMap envd-system/local-revocations in dev-cp, and mgmtd
# adopts each one when the environment reconnects. The Mac writes that ConfigMap with the field manager operator.
#
# local --cell <cell>  Read the revision of the record of the cell that envd holds from ConfigMap spire-system/cell-records in dev-cp.
#                      The read command pipes the seed into operatorctl sign, so no file, variable, argument or log line holds it.
#                      Apply the entry to ConfigMap envd-system/local-revocations, append it to build/operator/revocations.log,
#                      and print one JSON line with id, cell and record.
# list                 Print one JSON line for each key of ConfigMap envd-system/local-revocations: key, id, cell, record, issuedAt and
#                      the state that envd reports. held: envd holds the entry. pending: envd has not admitted it yet. stale: the
#                      record of the cell is newer than the entry. settled: the record is revoked, or the cell has no record. invalid:
#                      the key holds no readable entry.
# reapply              Write every entry of build/operator/revocations.log back to the ConfigMap. Use it after a lost dev-cp.
# clean                Delete the keys of the entries that are stale or settled. A key that is held, pending or invalid stays.
#
# Settings in .envrc.local, as in .envrc.local.example: POC_SECRET_READ_CMD for local. A failure prints one JSON error line.
export CELL=dev-cp
source "$(dirname "$0")/lib.sh"
source "$ROOT/components/lib/operator-key.sh"
cd "$ROOT"

log_file="$BUILD_ROOT/operator/revocations.log"
inputs_cm=local-revocations

usage() { awk 'NR > 1 && !/^#/ { exit } NR > 1 { sub(/^# ?/, ""); print }' "$0"; }

fail() { json_fail revoke "$@"; }

dev_cp() { kubectl --context kind-dev-cp "$@"; }

# read_records sets RECORDS to ConfigMap spire-system/cell-records of dev-cp, the store that envd writes.
read_records() {
  RECORDS="$(dev_cp -n spire-system get configmap cell-records -o json)" \
    || fail "could not read ConfigMap spire-system/cell-records in dev-cp. Run: mise run harness:status"
}

# read_inputs sets INPUTS to ConfigMap envd-system/local-revocations as JSON, or to null when it is absent.
read_inputs() {
  INPUTS="$(dev_cp -n envd-system get configmap "$inputs_cm" --ignore-not-found -o json)" \
    || fail "could not read ConfigMap envd-system/local-revocations in dev-cp. Run: mise run harness:status"
  [[ -n "$INPUTS" ]] || INPUTS=null
}

# put_inputs <patch JSON> merges the patch into the ConfigMap, and creates the ConfigMap first when it is absent. The field manager is
# operator.
put_inputs() {
  read_inputs
  if [[ "$INPUTS" == null ]]; then
    dev_cp -n envd-system create --field-manager=operator -f - >/dev/null <<<'{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"local-revocations","namespace":"envd-system"}}' \
      || fail "could not create ConfigMap envd-system/local-revocations in dev-cp. Run: mise run harness:status"
  fi
  dev_cp -n envd-system patch configmap "$inputs_cm" --type=merge --field-manager=operator -p "$1" >/dev/null \
    || fail "could not write ConfigMap envd-system/local-revocations in dev-cp. Run: mise run harness:status"
}

# entry_states prints one JSON line for each key of the inputs, with the state that envd reports. It decodes the payload with no
# signature check, because envd verifies each entry and the status checks do too.
entry_states() {
  read_inputs
  read_records
  jq -nc --argjson cm "$INPUTS" --argjson records "$RECORDS" '
    ($records.data // {}) as $d
    | (try ($d["local-revocations.json"] // "[]" | fromjson | map(.payload | @base64d | fromjson | .id)) catch []) as $held
    | def rec($cell): try ($d[$cell + ".dsse.json"] | fromjson | .payload | @base64d | fromjson) catch null;
      def older($a; $b): $a.epoch < $b.epoch or ($a.epoch == $b.epoch and $a.counter < $b.counter);
      ($cm.data // {}) | to_entries | sort_by(.key)[]
    | .key as $key
    | (try (.value | fromjson | .payload | @base64d | fromjson | {id, cell, record, issuedAt}) catch null) as $e
    | if $e == null or ($e.id | type) != "string" or ($e.cell | type) != "string" then {key: $key, state: "invalid"}
      else rec($e.cell) as $r
        | {key: $key} + $e + {state:
            (if $r == null or $r.revoked == true then "settled"
             elif older($e.record; $r) then "stale"
             elif ($held | index($e.id)) != null then "held"
             else "pending" end)}
      end'
}

cmd_local() {
  [[ "${1:-}" == --cell && -n "${2:-}" && $# == 2 ]] || fail "usage: revoke.sh local --cell <cell>"
  local cell="$2" name state rev envelope id
  [[ "$cell" =~ ^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$ ]] || fail "the cell name is not a DNS label"
  load_local_settings POC_SECRET_READ_CMD
  [[ -n "${POC_SECRET_READ_CMD:-}" ]] \
    || fail "POC_SECRET_READ_CMD is not set. Copy it from .envrc.local.example to .envrc.local and complete it. direnv loads .envrc.local after you run direnv allow"
  read_records
  state="$(jq -r --arg key "$cell.dsse.json" 'try (.data[$key] | fromjson | .payload | @base64d | fromjson
    | if .revoked == true then "revoked" else "\(.epoch).\(.counter)" end) catch "absent"' <<<"$RECORDS")" \
    || fail "ConfigMap spire-system/cell-records in dev-cp holds no readable record of $cell"
  case "$state" in
    absent) fail "ConfigMap spire-system/cell-records in dev-cp holds no record of $cell, so envd would refuse the entry as revocation_unknown_cell" ;;
    revoked) fail "the record of $cell that envd holds is revoked already, so an entry adds nothing" ;;
  esac
  rev="$state"
  name="$(operator_key_name)" \
    || fail "neither build/operator/key.env nor spec.name of operator-pub names the remote key. The owner creates the operator key once with: mise run operator:create-key"
  # The envelope is public data. Error text never quotes the output of the read command.
  envelope="$(operator_seed_pipe "$name" sign --env "$POC_ENV" --cell "$cell" --record "$rev")" \
    || fail "the read of the remote key $name through POC_SECRET_READ_CMD and operatorctl sign failed. Nothing was written"
  id="$(jq -er 'select(type == "object") | .payload | @base64d | fromjson | .id' <<<"$envelope" 2>/dev/null)" \
    || fail "operatorctl sign printed no envelope. Nothing was written"
  [[ "$id" =~ ^[0-9a-f]{16}$ ]] || fail "operatorctl sign printed an entry with no valid id. Nothing was written"
  put_inputs "$(jq -nc --arg key "$id.json" --arg env "$envelope" '{data: {($key): $env}}')"
  mkdir -p "$(dirname "$log_file")" && printf '%s\n' "$envelope" >>"$log_file" \
    || fail "the entry $id is in ConfigMap envd-system/local-revocations, but build/operator/revocations.log could not take it. Append it by hand"
  log "signed the entry $id for $cell at the record revision $rev"
  jq -nc --arg id "$id" --arg cell "$cell" --arg rev "$rev" '{id: $id, cell: $cell, record: {epoch: (($rev | split(".")[0]) | tonumber), counter: (($rev | split(".")[1]) | tonumber)}}'
}

cmd_list() {
  (($# == 0)) || fail "list takes no argument"
  entry_states
}

cmd_reapply() {
  (($# == 0)) || fail "reapply takes no argument"
  [[ -s "$log_file" ]] || fail "build/operator/revocations.log is absent or empty, so there is nothing to apply"
  local patch n
  patch="$(jq -Rsc 'split("\n") | map(select(length > 0))
    | map({key: ((fromjson | .payload | @base64d | fromjson | .id | select(test("^[0-9a-f]{16}$"))) + ".json"), value: .}) | from_entries | {data: .}' "$log_file" 2>/dev/null)" \
    || fail "a line of build/operator/revocations.log is no entry envelope. Nothing was written"
  n="$(jq '.data | length' <<<"$patch")"
  put_inputs "$patch"
  log "wrote $n entries of the log to ConfigMap envd-system/local-revocations"
  jq -nc --argjson n "$n" '{reapplied: $n}'
}

cmd_clean() {
  (($# == 0)) || fail "clean takes no argument"
  local states patch ids
  states="$(entry_states)"
  patch="$(jq -sc '[.[] | select(.state == "stale" or .state == "settled") | .key] | map({key: ., value: null}) | from_entries | {data: .}' <<<"$states")"
  ids="$(jq -sc '[.[] | select(.state == "stale" or .state == "settled") | .key | sub("\\.json$"; "")]' <<<"$states")"
  if [[ "$(jq '.data | length' <<<"$patch")" != 0 ]]; then put_inputs "$patch"; fi
  jq -nc --argjson removed "$ids" --argjson kept "$(jq -sc 'map(select(.state != "stale" and .state != "settled")) | length' <<<"$states")" '{removed: $removed, kept: $kept}'
}

case "${1:-}" in
  local) shift; cmd_local "$@" ;;
  list) shift; cmd_list "$@" ;;
  reapply) shift; cmd_reapply "$@" ;;
  clean) shift; cmd_clean "$@" ;;
  help | -h | --help) usage ;;
  *) usage >&2; exit 2 ;;
esac
