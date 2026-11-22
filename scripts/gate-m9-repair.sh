#!/usr/bin/env bash
# Repair what a slow tier of gate:m9 leaves behind when it stops early, for example after a sleep of the Mac, a go test timeout or Ctrl-C
# ("A failed overnight run" in the M9 plan). The script
#   1. heals every cut of the partition tool (scripts/partition.sh heal --all);
#   2. waits until dev-cp is connected: mgmtd received a status report of envd within 2 minutes, and envd applied the revision that mgmtd
#      signed (mise run mgmt -- status);
#   3. waits until envd holds no local revocation entry, because mgmtd adopts each one and the next revision settles it;
#   4. runs mise run revoke -- clean, which deletes the input entries that envd reports stale or settled;
#   5. runs mise run mgmt -- unrevoke --cell <c> for each cell in build/gate/m9-revoked (one cell on each line, which a test writes before it
#      revokes the cell), and removes the file;
#   6. runs scripts/gate-m2-repair.sh when the node of dev-cell-1 holds a trace of the API server key rotation test;
#   7. runs scripts/svid-ttl.sh restore, which removes build/gate/m9-svid-ttl and restarts dev-cp and each live cell, so that every agent,
#      and each un-revoked cell, gets new SVIDs;
#   8. deletes each namespace m9-<name> with the label cell.poc.internal/e2e=true in every existing cluster, and waits until none is left;
#   9. runs mise run harness:status until it passes, up to HARNESS_STATUS_WAIT seconds (default 600).
# Steps 1 and 4 call the scripts of the partition tool and of the revoke command only when they exist. It never touches an object without
# the label, and none with another prefix. It is safe to run again.
#
# Usage: gate-m9-repair.sh [--check]
#   --check lists each cut, the marker, a restore that did not settle (build/gate/m9-svid-ttl.restoring), a live agent_ttl of dev-cp that
#   differs from cells/dev-cp.env, the revoked test cells, the held and
#   input local revocation entries, the m9- namespaces and the API server test key, and exits 1 with the repair command. It changes nothing.
#   It exits 0 when it finds none.
# GATE_M9_WAIT bounds each wait in seconds (default 600), and GATE_M9_POLL sets the seconds between two reads (default 10).
export CELL=management
source "$(dirname "$0")/lib.sh"
source "$ROOT/components/lib/operator-key.sh"

check=0
case "${1:-}" in
  "") ;;
  --check) check=1 ;;
  *) die "usage: gate-m9-repair.sh [--check]" ;;
esac
((${#} <= 1)) || die "usage: gate-m9-repair.sh [--check]"
repair="mise run gate:m9:repair"
test_label="cell.poc.internal/e2e"
revoked="$BUILD_ROOT/gate/m9-revoked"
wait_seconds="${GATE_M9_WAIT:-600}"
poll="${GATE_M9_POLL:-10}"

existing="$(existing_clusters)" || die "could not list the clusters. Run: mise run harness:status"

# cuts prints one line for each rule of the partition tool, as node and tag.
cuts() {
  local out
  [[ -x "$ROOT/scripts/partition.sh" ]] || return 0
  out="$("$ROOT/scripts/partition.sh" list)" || { echo "the partition tool could not list its rules. Run: mise run partition -- list" >&2; return 1; }
  [[ -z "$out" ]] || jq -r '"\(.node) \(.tag)"' <<<"$out"
}

# held_cells prints the cells of the local revocation entries that envd holds, from key local-revocations.json of ConfigMap
# spire-system/cell-records in dev-cp, one on each line.
held_cells() {
  local records
  records="$(kubectl --context kind-dev-cp -n spire-system get configmap cell-records -o json)" || return 1
  jq -r '.data["local-revocations.json"] // "[]" | fromjson | if type != "array" then error("not an array") else . end
    | .[] | (try (.payload | @base64d | fromjson | .cell // "unknown") catch "unknown")' <<<"$records"
}

# input_entries prints the keys of ConfigMap envd-system/local-revocations in dev-cp, one on each line.
input_entries() {
  local cm
  cm="$(kubectl --context kind-dev-cp -n envd-system get configmap local-revocations --ignore-not-found -o json)" || return 1
  [[ -z "$cm" ]] || jq -r '.data // {} | keys[]' <<<"$cm"
}

# revoked_cells prints the cells of build/gate/m9-revoked. A line that is not a cluster name stops the script.
revoked_cells() {
  local line
  [[ -f "$revoked" ]] || return 0
  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ -n "$line" ]] || continue
    [[ "$line" =~ ^[a-z0-9][a-z0-9-]*$ ]] || die "build/gate/m9-revoked holds '$line', which is no cell name. Fix the file, then run: $repair"
    printf '%s\n' "$line"
  done <"$revoked"
}

# m9_namespaces <cluster> prints the namespaces m9-<name> with the test label in the cluster.
m9_namespaces() {
  local out
  out="$(kubectl --context "kind-$1" get namespaces -l "$test_label=true" -o name)" || return 1
  grep '^namespace/m9-' <<<"$out" | sed 's|^namespace/||' || true
}

# api_key_traces prints the traces of the API server key rotation test on the node of dev-cell-1, when dev-cell-1 is live.
api_key_traces() {
  local live
  live="$(live_cells)" || return 1
  grep -qx dev-cell-1 <<<"$live" || return 0
  keytest_leftover dev-cell-1
}

# traces prints one line for each trace of a stopped slow tier, with the step that the repair runs for it.
traces() {
  local line c ns live file out node tag cells
  out="$(cuts)" || exit 1
  while read -r node tag; do
    if [[ -n "$node" ]]; then echo "the node $node holds the cut $tag of the partition tool"; fi
  done <<<"$out"
  if [[ -e "$SVID_TTL_MARKER" ]]; then
    echo "the slow-tier marker build/gate/m9-svid-ttl holds $(tr -d '[:space:]' <"$SVID_TTL_MARKER"), so the SVID lifetime of dev-cp is not restored"
  elif [[ -e "$SVID_TTL_MARKER.restoring" ]]; then
    echo "build/gate/m9-svid-ttl.restoring exists, so a restore of the SVID lifetime of dev-cp did not settle"
  else
    live="$(svid_ttl_live)" || die "could not read agent_ttl of the SPIRE server config in dev-cp. Run: mise run harness:status"
    file="$(svid_ttl_file)"
    [[ "$live" == "$file" ]] || echo "the SPIRE server of dev-cp sets agent_ttl '$live', and cells/dev-cp.env sets SPIRE_SVID_TTL=$file"
  fi
  cells="$(revoked_cells)" || exit 1
  for c in $cells; do
    echo "build/gate/m9-revoked names $c, which a test revoked"
  done
  out="$(held_cells)" || die "could not read ConfigMap spire-system/cell-records in dev-cp, so the held entries are unknown. Run: mise run harness:status"
  [[ -z "$out" ]] || echo "envd holds local revocation entries for $(paste -sd' ' - <<<"$out")"
  out="$(input_entries)" || die "could not read ConfigMap envd-system/local-revocations in dev-cp. Run: mise run harness:status"
  for line in $out; do
    echo "ConfigMap envd-system/local-revocations in dev-cp holds the input entry $line"
  done
  for c in $existing; do
    out="$(m9_namespaces "$c")" || die "could not list the namespaces of $c"
    for ns in $out; do
      echo "$c holds the test namespace $ns"
    done
  done
  out="$(api_key_traces)" || die "could not check the node of dev-cell-1 for the API server test key: $out"
  [[ -z "$out" ]] || printf '%s\n' "$out"
}

if ((check)); then
  found="$(traces)"
  [[ -n "$found" ]] || exit 0
  printf '%s\n' "$found" >&2
  die "a slow tier of gate:m9 stopped early and left these traces. Run: $repair"
fi

# Every failure from here on leaves the repair unfinished, and a new run continues it.
die() { printf 'error: %s. Run: %s again\n' "$*" "$repair" >&2; exit 1; }

# wait_until <what> <command...> runs the command until it succeeds, up to wait_seconds.
wait_until() {
  local what="$1" waited=0
  shift
  log "waiting up to ${wait_seconds}s until $what"
  until "$@"; do
    ((waited < wait_seconds)) || return 1
    sleep "$poll"
    waited=$((waited + poll))
  done
}

# Step 1: heal every cut.
if [[ -x "$ROOT/scripts/partition.sh" ]]; then
  "$ROOT/scripts/partition.sh" heal --all >/dev/null || die "the partition tool could not heal every cut"
else
  log "scripts/partition.sh does not exist, so no cut of it can be in place"
fi

# Step 2: connected.
is_connected() { operator_connected 2>/dev/null; }
wait_until "dev-cp is connected to management" is_connected \
  || die "dev-cp is not connected after ${wait_seconds}s: $(operator_connected 2>&1 | sed 's/^error: //')"

# Step 3: mgmtd adopts each held entry, and the next revision settles it.
no_held() { local out; out="$(held_cells 2>/dev/null)" && [[ -z "$out" ]]; }
wait_until "envd holds no local revocation entry" no_held \
  || die "envd still holds local revocation entries for $(held_cells 2>/dev/null | paste -sd' ' -) after ${wait_seconds}s. Read the mirror with: mise run mgmt -- status. When mgmtd refuses an entry, the lifetime stays at the slow tier; restore it by hand with: mise run svid-ttl -- restore"

# Step 4: the input entries.
if [[ -x "$ROOT/scripts/revoke.sh" ]]; then
  mise run revoke -- clean || die "mise run revoke -- clean failed"
else
  inputs="$(input_entries)" || die "could not read ConfigMap envd-system/local-revocations in dev-cp"
  log "scripts/revoke.sh does not exist, so no input entry is cleaned${inputs:+. ConfigMap envd-system/local-revocations still holds: $(paste -sd' ' - <<<"$inputs")}"
fi

# Step 5: un-revoke each test cell. A cell that is not revoked is done.
cells="$(revoked_cells)" || exit 1
for c in $cells; do
  out="$(mise run mgmt -- unrevoke --cell "$c" 2>&1)" || [[ "$out" == *not_revoked* ]] || die "mise run mgmt -- unrevoke --cell $c failed: $out"
  log "un-revoked $c"
  left="$(grep -vx -- "$c" "$revoked" || true)"
  if [[ -n "$left" ]]; then printf '%s\n' "$left" >"$revoked"; else rm -f "$revoked"; fi
done

# Step 6: the API server of a key rotation test.
traces_m2="$(api_key_traces)" || die "could not check the node of dev-cell-1 for the API server test key: $traces_m2"
if [[ -n "$traces_m2" ]]; then
  log "the node of dev-cell-1 holds the API server test key: ${traces_m2//$'\n'/; }"
  "$ROOT/scripts/gate-m2-repair.sh" || die "scripts/gate-m2-repair.sh failed"
fi

# Step 7: the SVID lifetime, with a restart of dev-cp and of each live cell.
"$ROOT/scripts/svid-ttl.sh" restore >/dev/null || die "scripts/svid-ttl.sh restore failed"

# Step 8: the test namespaces.
for c in $existing; do
  namespaces="$(m9_namespaces "$c")" || die "could not list the namespaces of $c"
  for ns in $namespaces; do
    kubectl --context "kind-$c" delete namespace "$ns" --wait=false >/dev/null || die "could not delete the namespace $ns of $c"
  done
done
no_namespaces() {
  local c out
  for c in $existing; do
    out="$(m9_namespaces "$c" 2>/dev/null)" || return 1
    [[ -z "$out" ]] || return 1
  done
}
wait_until "no test namespace m9-* is left" no_namespaces || die "a test namespace m9-* is still there after ${wait_seconds}s"

# Step 9: harness:status, read again while telemetry retries clear after the restarts.
harness_status_settled || die "harness:status reports a bad value after the repair. Read its problems"
log "every trace of a slow tier of gate:m9 is repaired"
