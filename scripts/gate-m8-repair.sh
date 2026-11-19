#!/usr/bin/env bash
# Repair what a gate:m8 run can leave behind. The M8 tests change the signed bundle set of a cell or of dev-cp, and they run probe objects in
# the clusters with a bundle role (the cells and dev-cp). The script
#   1. deletes each namespace m8-<name> with the label cell.poc.internal/e2e=true and each Application m8-<name> with that label, in argocd,
#      and then waits until none is left, so a stuck object is an error and not a silent leftover;
#   2. runs mise run bundle -- repair --target <t> for each target whose bundle state is rolled_back with the detail rollback_unhealthy, because
#      such a cluster cannot read the store, and no new set would apply;
#   3. runs mise run bundle -- publish --target <t> --wait for each target that a test changed: a target in build/gate/m8-bundles, a target with the
#      Application apps-sample or the ConfigMap apps-demo/m8-marker, and a target in the state rolled_back. dev-cp goes first. It deletes the
#      ConfigMap apps-demo/m8-marker of a target after its publish, and removes build/gate/m8-bundles after every publish ended applied.
# The tests record a target in build/gate/m8-bundles before they sign a set for it. It never touches an object without the label, and none with
# another prefix. It is safe to run again.
#
# Usage: gate-m8-repair.sh [--check]
#   --check prints each trace of a run with the command that repairs it, and exits 1. It changes nothing. It exits 0 when it finds none.
# GATE_M8_WAIT sets the seconds to wait for the deletions (default 180), GATE_M8_OPEN_WAIT the seconds to wait for an open set of a target before its
# publish (default 2100, as long as the e2e helper m8WaitNoOpen), and GATE_M8_POLL the seconds between two reads (default 5).
# mgmtd refuses a new served set while one is open (bundle_open), so an interrupted run can leave a target that cannot take a publish for up to 30 minutes.
export CELL=dev-cp
source "$(dirname "$0")/lib.sh"

check=0
case "${1:-}" in
  "") ;;
  --check) check=1 ;;
  *) echo "usage: gate-m8-repair.sh [--check]" >&2; exit 1 ;;
esac
((${#} <= 1)) || { echo "usage: gate-m8-repair.sh [--check]" >&2; exit 1; }
repair="mise run gate:m8:repair"
test_label="cell.poc.internal/e2e"
recorded="$BUILD_ROOT/gate/m8-bundles"
marker_cm=m8-marker
wait_seconds="${GATE_M8_WAIT:-180}"
open_wait="${GATE_M8_OPEN_WAIT:-2100}"

existing="$(existing_clusters)" || die "could not list the clusters. Run: mise run harness:status"

# The targets are the existing clusters with a bundle role: dev-cp first, then each cell in topology order.
targets=()
for want in cp cell; do
  for cluster in $existing; do
    role="$(bundle_role_of "$cluster" 2>/dev/null)" || continue
    [[ "$role" != "$want" ]] || targets+=("$cluster")
  done
done

# state_of <target> prints state.json of ConfigMap bundle-state, and nothing when the ConfigMap is absent.
state_of() {
  local ns
  ns="$(bundle_state_ns "$(bundle_role_of "$1")")" || exit 1
  kubectl --context "kind-$1" -n "$ns" get configmap bundle-state --ignore-not-found -o 'jsonpath={.data.state\.json}' \
    || die "could not read ConfigMap bundle-state of $1"
}

# open_set <target> prints "<op ID> <expiry>" when the last signed set of the target is served, has no final result and has not expired, and nothing
# otherwise. A target that has no set yet gives nothing.
open_set() {
  local got err
  err="$(mktemp)"
  if ! got="$(mise run bundle -- get --target "$1" 2>"$err")"; then
    # Only the answer bundle_unknown means that the target has no set. Any other failure can hide an open set.
    if grep -q bundle_unknown "$err" || grep -q bundle_unknown <<<"$got"; then rm -f "$err"; return 0; fi
    echo "error: could not read the last set of $1: $(tail -n 1 "$err")" >&2
    rm -f "$err"
    return 1
  fi
  rm -f "$err"
  jq -r --argjson now "$(date +%s)" 'def ts: try (sub("\\.[0-9]+Z$"; "Z") | fromdateiso8601) catch 0;
    select(.served == true and (.result // null) == null and ((.expiresAt // "") | ts) > $now) | "\(.opId) \(.expiresAt)"' <<<"$got" 2>/dev/null || true
}

# probes prints "<cluster> <name>" for each probe of M8: a namespace, and application/<name> for an Application.
probes() {
  local cluster names name
  for cluster in "${targets[@]}"; do
    names="$(kubectl --context "kind-$cluster" get namespaces -o json | jq -r --arg l "$test_label" '.items[]
      | select(.metadata.labels[$l] == "true" and (.metadata.name | startswith("m8-"))) | .metadata.name')" \
      || die "could not list the namespaces of $cluster"
    for name in $names; do printf '%s %s\n' "$cluster" "$name"; done
    names="$(kubectl --context "kind-$cluster" -n argocd get applications -o json | jq -r --arg l "$test_label" '.items[]
      | select(.metadata.labels[$l] == "true" and (.metadata.name | startswith("m8-"))) | .metadata.name')" \
      || die "could not list the Applications of $cluster"
    for name in $names; do printf '%s application/%s\n' "$cluster" "$name"; done
  done
}

# Each target gets a reason line "<target> <kind> <text>" for a sign that a test changed it, where kind is recorded, apps-sample, marker,
# rolled_back or rollback_unhealthy. A target with more than one sign has more than one line.
signs() {
  local target state apps open
  for target in "${targets[@]}"; do
    if grep -qx -- "$target" "$recorded" 2>/dev/null; then
      printf '%s recorded is listed in build/gate/m8-bundles, so a test changed its signed set and did not restore it\n' "$target"
    fi
    apps="$(kubectl --context "kind-$target" -n argocd get applications -o json | jq -r '.items[].metadata.name')" \
      || die "could not list the Applications of $target"
    if grep -qx apps-sample <<<"$apps"; then
      printf '%s apps-sample holds the Application apps-sample\n' "$target"
    fi
    if [[ -n "$(kubectl --context "kind-$target" -n apps-demo get configmap "$marker_cm" --ignore-not-found -o name)" ]]; then
      printf '%s marker holds the ConfigMap apps-demo/%s\n' "$target" "$marker_cm"
    fi
    open="$(open_set "$target")" || exit 1
    if [[ -n "$open" ]]; then
      printf '%s open holds the open set %s, which expires at %s and has no final result\n' "$target" "${open% *}" "${open#* }"
    fi
    state="$(state_of "$target")" || exit 1
    [[ -n "$state" ]] || continue
    if [[ "$(jq -r '.state // ""' <<<"$state")" == rolled_back ]]; then
      if [[ "$(jq -r '.result.detail // ""' <<<"$state")" == rollback_unhealthy ]]; then
        printf '%s rollback_unhealthy is in the state rolled_back with rollback_unhealthy, so it does not run the last good root\n' "$target"
      else
        printf '%s rolled_back is in the state rolled_back, so it runs the last good set and not the newest one\n' "$target"
      fi
    fi
  done
}

# unserved_expired prints the ID of each bundle.apply operation that expired and was never served (signed with --no-serve). A refusal test leaves one, and it
# blocks nothing: mgmtd refuses a new set only for a served one. A served operation that expires stays a finding of harness:status.
unserved_expired() {
  local ops
  ops="$(mise run mgmt -- op list 2>/dev/null)" || die "could not list the operations of mgmtd. Run: mise run mgmt -- op list"
  jq -r '.ops[]? | select(.state == "expired" and .kind == "bundle.apply" and .served == false) | .id' <<<"$ops" || die "mise run mgmt -- op list printed no operation list"
}

found="$(probes)" || exit 1
reasons="$(signs)" || exit 1
unserved="$(unserved_expired)" || exit 1
if [[ -z "$found$reasons" ]]; then
  if ((check)); then
    for id in $unserved; do echo "info: the operation $id expired and was never served. It is no failure. $repair closes it"; done
  else
    for id in $unserved; do
      log "closing the expired operation $id, which was never served"
      mise run mgmt -- op close "$id" >/dev/null || die "could not close the operation $id. Run: mise run mgmt -- op close $id"
    done
  fi
  exit 0
fi

if ((check)); then
  while read -r cluster name; do
    [[ -n "$cluster" ]] || continue
    case "$name" in
      application/*) echo "$cluster holds the test Application ${name#application/}. Run: $repair" ;;
      *) echo "$cluster holds the test namespace $name. Run: $repair" ;;
    esac
  done <<<"$found"
  while read -r cluster kind text; do
    [[ -n "$cluster" ]] || continue
    echo "$cluster $text. Run: $repair"
  done <<<"$reasons"
  for id in $unserved; do echo "info: the operation $id expired and was never served. It is no failure. $repair closes it"; done
  exit 1
fi

# 1. The probes.
while read -r cluster name; do
  [[ -n "$cluster" ]] || continue
  case "$name" in
    application/*)
      log "deleting Application ${name#application/} in $cluster"
      kubectl --context "kind-$cluster" -n argocd delete application "${name#application/}" --ignore-not-found --wait=true --timeout=120s >/dev/null \
        || die "could not delete the Application ${name#application/} in $cluster" ;;
    *)
      log "deleting namespace $name in $cluster"
      kubectl --context "kind-$cluster" delete namespace "$name" --ignore-not-found --wait=true --timeout=180s >/dev/null \
        || die "could not delete namespace $name in $cluster" ;;
  esac
done <<<"$found"
end=$((SECONDS + wait_seconds))
while :; do
  left="$(probes)" || exit 1
  [[ -n "$left" ]] || break
  ((SECONDS < end)) || die "after ${wait_seconds}s these namespaces and Applications (cluster, name) still exist: $(paste -sd, - <<<"$left"). Run: kubectl --context kind-<cluster> get <kind> <name> -o yaml, then $repair"
  sleep "${GATE_M8_POLL:-5}"
done

# 2. A target whose rollback did not finish cannot apply a new set, so it needs the repair first.
while read -r target kind text; do
  [[ "$kind" == rollback_unhealthy ]] || continue
  log "repairing $target, which is in the state rolled_back with rollback_unhealthy"
  mise run bundle -- repair --target "$target" >/dev/null || die "could not repair $target. Run: mise run bundle -- repair --target $target, and read its error"
done <<<"$reasons"

# 3. The hydrated set goes out again for each target that a test changed, dev-cp first (the order of targets).
for target in "${targets[@]}"; do
  grep -q "^$target " <<<"$reasons" || continue
  open_end=$((SECONDS + open_wait))
  while :; do
    open="$(open_set "$target")" || exit 1
    [[ -n "$open" ]] || break
    ((SECONDS < open_end)) || die "the set ${open% *} of $target is open until ${open#* }, and mgmtd refuses a new set until it ends. Wait, then run: $repair"
    log "waiting for the open set ${open% *} of $target (until ${open#* })"
    sleep "${GATE_M8_POLL:-5}"
  done
  log "publishing the hydrated set of $target again"
  if ! err="$(mise run bundle -- publish --target "$target" --wait 2>&1 >/dev/null)"; then
    if [[ "$err" == *bundle_open* ]]; then
      die "mgmtd refused the set of $target because a set is still open (bundle_open): ${err##*$'\n'}. Wait for it to end, then run: $repair"
    fi
    die "could not publish the hydrated set of $target: ${err##*$'\n'}. Run: CELL=$target mise run cell:hydrate, then mise run bundle -- publish --target $target --wait"
  fi
  if grep -q "^$target marker " <<<"$reasons"; then
    kubectl --context "kind-$target" -n apps-demo delete configmap "$marker_cm" --ignore-not-found >/dev/null \
      || die "could not delete the ConfigMap apps-demo/$marker_cm of $target"
  fi
done
rm -f "$recorded"
for id in $unserved; do
  log "closing the expired operation $id, which was never served"
  mise run mgmt -- op close "$id" >/dev/null || die "could not close the operation $id. Run: mise run mgmt -- op close $id"
done
