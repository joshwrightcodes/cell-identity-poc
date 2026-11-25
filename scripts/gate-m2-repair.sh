#!/usr/bin/env bash
# Repair what a gate:m2 run leaves behind when it stops before its cleanups, for example after Ctrl-C,
# a go test timeout or a closed terminal. The tests run the same steps in their cleanups. The script
# is safe to run again.
#
# Usage: gate-m2-repair.sh [--check]
#   --check prints each trace and exits 1, or exits 0 when it finds none.
#
# The repair:
#   1. dev-cp: when the root, the spire-server pin or a test entry shows a trace of the entries test (see bundle_traces), waits for
#      an open set to end and publishes the last hydrated set of dev-cp with mise run bundle -- publish --target dev-cp --wait.
#      With no trace and an Application that is not Synced and Healthy, it refreshes root. Then it waits for the Applications at
#      the digests of build/dev-cp/published.env, and until the SPIRE server holds no entry under /m2-test/;
#   2. dev-cell-1: puts back the manifest that the key rotation test saved, or removes the two test
#      flags, checks the manifest, deletes the test key, and waits until the API server publishes
#      and signs with one key;
#   3. makes sure that kube-controller-manager, which keeps a token for each controller in memory, and kube-scheduler
#      run a container that started after the API server container (read from the container runtime, not from the mirror pods)
#      and hold a live Lease;
#   4. replaces each pod with a projected token from another key, one at a time, in this order: kindnet and kube-proxy, istio-cni-node, istiod,
#      then the other pods. It then waits for every workload;
#   5. runs the key check of mgmtd for dev-cell-1, and repeats it after 61 s while the answer is rate_limited, up to
#      three checks. The record of the cell must then list the key IDs that the API server publishes. A mgmtd
#      that does not answer skips this step.
# Each wait has a bound, and the log names it.
export CELL=dev-cell-1
source "$(dirname "$0")/lib.sh"

node="$CELL_NAME-control-plane"
cp="$SPIRE_SERVER_CLUSTER"
on_node() { docker exec "$node" "$@"; }
kcp() { kubectl --context "kind-$cp" "$@"; }

# wait_until <seconds> <what> <command...> logs the wait with its bound, and fails after the bound.
wait_until() {
  local bound="$1" what="$2" end
  shift 2
  end=$((SECONDS + bound))
  log "waiting up to ${bound}s until $what"
  until "$@" >/dev/null 2>&1; do
    ((SECONDS < end)) || die "$what: not true after ${bound}s"
    sleep 3
  done
}

# api_kids prints the sorted key IDs that the API server publishes.
api_kids() { k get --raw /openid/v1/jwks | jq -r '[.keys[].kid] | sort | join(" ")'; }

b64url_json() {
  local s="${1//-/+}"
  s="${s//_//}"
  while ((${#s} % 4)); do s+="="; done
  base64 -d <<<"$s" 2>/dev/null
}

# signing_kid requests a short token for celld and prints the key ID of its header. The audience
# m2-kid-probe makes the token useless to any service.
signing_kid() {
  local head
  head="$(k -n cell-identity-system create token celld --duration 10m --audience m2-kid-probe | cut -d. -f1)" || return 1
  b64url_json "$head" | jq -r '.kid // ""'
}

# Only one repair runs at a time. A repair that a test cleanup started can outlast the go test
# timeout, and then a new gate or repair must not run beside it. The lock directory holds the
# process ID of the repair. GATE_M2_REPAIR_LOCK names another directory, for the tests.
lock="${GATE_M2_REPAIR_LOCK:-$BUILD_ROOT/gate-m2-repair.lock}"
lock_holder() {
  local pid
  pid="$(cat "$lock/pid" 2>/dev/null)" || return 1
  [[ "$pid" =~ ^[0-9]+$ ]] || return 1
  # The system can give the PID of an ended repair to another process. Only a repair counts.
  [[ "$(ps -p "$pid" -o command= 2>/dev/null)" == *gate-m2-repair* ]] && echo "$pid"
}
if holder="$(lock_holder)"; then
  die "a repair already runs as process $holder. Wait until it ends, or stop it with kill $holder. Then run the command again"
fi

# The repair works on dev-cell-1, which exists only through a signed step. A cell that is not live has nothing to repair.
if ! live="$(live_cells)"; then
  die "$live"
fi
if ! grep -qx -- "$CELL_NAME" <<<"$live"; then
  log "$CELL_NAME is not live (no cluster, or no node address), so there is nothing to repair there"
  exit 0
fi

if [[ "${1:-}" == "--check" ]]; then
  found=()
  # The node traces come first. The JWKS counts only on a node without traces, because the API
  # server may not answer while the node holds the test key.
  node_traces="$(keytest_leftover "$CELL_NAME")" || die "$node_traces"
  if [[ -n "$node_traces" ]]; then
    found+=("$node_traces")
  else
    kids="$(api_kids 2>/dev/null)" || die "cannot read the JWKS of $CELL_NAME"
    [[ "$kids" != *" "* ]] || found+=("the API server of $CELL_NAME publishes the keys $kids")
    record_trace="$(record_kids_trace "$CELL_NAME" "$kids")"
    [[ -z "$record_trace" ]] || found+=("$record_trace")
  fi
  cp_traces="$(bundle_traces "$cp")" || die "$cp_traces"
  [[ -z "$cp_traces" ]] || found+=("$cp_traces")
  if ((${#found[@]} > 0)); then
    printf '%s\n' "${found[@]}" >&2
    die "a gate:m2 run left $cp or $CELL_NAME changed. Run: mise run gate:m2:repair"
  fi
  exit 0
fi

# A lock that no live repair holds is left from a repair that ended without its cleanup.
mkdir -p "$(dirname "$lock")"
# A rename moves the stale lock aside in one step, so two repairs cannot both remove it.
if ! mkdir "$lock" 2>/dev/null; then
  stale="$lock.stale.$$"
  mv "$lock" "$stale" 2>/dev/null && rm -rf "$stale"
  mkdir "$lock" 2>/dev/null || die "could not take the lock $lock, which another repair took first"
fi
echo "$$" >"$lock/pid"
trap 'rm -rf "$lock"' EXIT

# Every failure from here on leaves the repair unfinished, and a new run continues it.
die() { printf 'error: %s. Run: mise run gate:m2:repair again\n' "$*" >&2; exit 1; }

# Step 1: the bundles and the test entry in dev-cp.
apps_at_published() { cp_apps_at_published "$cp"; }
no_test_entries() {
  local entries
  entries="$(kcp -n spire-system exec spire-server-0 -c spire-server -- \
    /opt/spire/bin/spire-server entry show -socketPath /run/spire/sockets/api.sock -output json)" || return 1
  jq -e --arg p "$BUNDLE_TEST_PATH" '[.entries[] | select(.spiffe_id.path | startswith($p))] | length == 0' <<<"$entries"
}
restore_bundles "$cp" || die "could not restore the bundles of $cp. Run: CELL=$cp mise run cell:hydrate, then mise run bundle -- publish --target $cp --wait"
wait_until 300 "the Applications of $cp are Synced and Healthy at the digests of build/$cp/published.env" apps_at_published
wait_until 120 "the SPIRE server of $cp holds no entry under $BUNDLE_TEST_PATH" no_test_entries
log "the bundles of $cp match build/$cp/published.env"

# Step 2: the API server of dev-cell-1.
identity="$(node_matches "$CELL_NAME")" || die "$identity"
changed=0
# touched is 1 when this run changes the manifest, and then the API server must restart after the time that the node shows now.
touched=0
changed_at="$(on_node date +%s)" || die "cannot read the time of the node $node"
if on_node test -e "$KEYTEST_SAVED"; then
  changed=1
  if ! on_node cmp -s "$KEYTEST_SAVED" "$KEYTEST_MANIFEST"; then
    touched=1
    on_node sh -c "umask 077 && cp '$KEYTEST_SAVED' /root/m2-test.tmp && mv /root/m2-test.tmp '$KEYTEST_MANIFEST'"
    log "restored $KEYTEST_MANIFEST from $KEYTEST_SAVED"
  fi
elif on_node grep -q 'm2-test-sa' "$KEYTEST_MANIFEST"; then
  changed=1
  touched=1
  on_node sh -c "umask 077 && sed -e '\\|--service-account-key-file=$KEYTEST_KEY.pub|d' \
    -e 's|--service-account-signing-key-file=$KEYTEST_KEY.key|--service-account-signing-key-file=/etc/kubernetes/pki/sa.key|' \
    '$KEYTEST_MANIFEST' > /root/m2-test.tmp && mv /root/m2-test.tmp '$KEYTEST_MANIFEST'"
  log "removed the test key flags from $KEYTEST_MANIFEST"
fi
# The API server needs the key files for as long as its manifest names them.
on_node grep -q 'm2-test-sa' "$KEYTEST_MANIFEST" && die "$KEYTEST_MANIFEST still names the test key, so the key stays"
on_node rm -f "$KEYTEST_KEY.key" "$KEYTEST_KEY.pub"

one_key() {
  local kids signing ready
  kids="$(api_kids)" && [[ -n "$kids" && "$kids" != *" "* ]] || return 1
  signing="$(signing_kid)" && [[ "$signing" == "$kids" ]] || return 1
  ready="$(k -n kube-system get pod "kube-apiserver-$node" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}')"
  [[ "$ready" == True ]]
}
wait_until 240 "the API server of $CELL_NAME publishes one key, signs with it and is Ready" one_key
kid="$(api_kids)"
log "the API server of $CELL_NAME publishes and signs with the key $kid"

# Step 3: kube-controller-manager and kube-scheduler. The reference is the start of the API server container, read from the container
# runtime on the node. The mirror pods are not read: just after a restart of the API server their status can still show the old
# containers. A component counts as current when the runtime shows a container that started after the API server, its Lease names the
# node and is alive, and, for a container that this step stopped, the Lease has a new holder (see control_plane_current in gate-traces.sh).
if ((changed)); then
  api_restarted() { local s; s="$(container_started kube-apiserver)" && { ((!touched)) || ((s >= changed_at)); }; }
  wait_until 240 "the runtime shows a kube-apiserver container that started after the manifest changed" api_restarted
  api_started="$(container_started kube-apiserver)" || die "cannot read the start of the kube-apiserver container from the runtime"
  # kubelet can delay a new container by its restart back-off, up to 5 minutes. New pods wait while kube-scheduler is in back-off,
  # so step 4 starts only when both components are current.
  settle_control_plane "$node" "$api_started" 330 || die "kube-controller-manager and kube-scheduler did not become current (see the lines above)"
  log "kube-controller-manager and kube-scheduler run a container that started after the API server and hold a live Lease"
fi

# Step 4: pods with a projected token from another key. Only the token header leaves the node.
stale=()
while read -r path head; do
  [[ -n "$head" ]] || continue
  file_kid="$(b64url_json "$head" | jq -r '.kid // ""' 2>/dev/null)"
  if [[ -n "$file_kid" && "$file_kid" != "$kid" ]]; then
    uid="${path#/var/lib/kubelet/pods/}"
    stale+=("${uid%%/*}")
  fi
done < <(on_node sh -c 'find /var/lib/kubelet/pods/*/volumes/kubernetes.io~projected -type f 2>/dev/null | while read -r f; do
  h="$(head -n 1 "$f" | grep -oE "^eyJ[^.]*\.[^.]*\." | cut -s -d. -f1)"
  [ -n "$h" ] && printf "%s %s\n" "$f" "$h"; done; true')

workload_ready() {
  k -n "$2" get "$1" "$3" -o json | jq -e '
    if .kind == "DaemonSet" then .status.numberReady == .status.desiredNumberScheduled and .status.updatedNumberScheduled == .status.desiredNumberScheduled
    else ((.status.readyReplicas // 0) == (.spec.replicas // 1)) and ((.status.updatedReplicas // 0) == (.spec.replicas // 1)) and ((.status.replicas // 0) == (.spec.replicas // 1)) end'
}

# replace_pod <namespace> <pod> <owner kind> <owner name>. A Deployment outside the harness and
# outside Argo CD gets a rollout restart. kubectl then owns the restart annotation, which
# cell:verify and Argo CD would report on their objects, so their pods are deleted instead.
restarted=()
replace_pod() {
  local ns="$1" pod="$2" kind="$3" owner="$4" deployment managed
  case "$kind" in
    ReplicaSet)
      deployment="$(k -n "$ns" get replicaset "$owner" -o jsonpath='{.metadata.ownerReferences[?(@.kind=="Deployment")].name}')"
      managed="$(k -n "$ns" get deployment "$deployment" -o json \
        | jq -r '(.metadata.labels["cell.poc.internal/harness"] // .metadata.annotations["argocd.argoproj.io/tracking-id"] // "") | length')"
      if [[ "$managed" == 0 ]]; then
        [[ " ${restarted[*]-} " == *" $ns/$deployment "* ]] && return 0
        restarted+=("$ns/$deployment")
        log "restarting deployment $ns/$deployment, whose pod $pod holds a token from another key"
        k -n "$ns" rollout restart deployment "$deployment" >/dev/null
        log "waiting up to 120s for the rollout of $ns/$deployment"
        k -n "$ns" rollout status deployment "$deployment" --timeout=120s >/dev/null \
          || log "the rollout of $ns/$deployment did not finish in 120s, and the wait for every workload decides"
        return 0
      fi
      kind=deployment owner="$deployment" ;;
    DaemonSet) kind=daemonset ;;
    StatefulSet) kind=statefulset ;;
    *) kind="" ;;
  esac
  log "deleting pod $ns/$pod, which holds a token from another key"
  log "waiting up to 60s until pod $ns/$pod is gone"
  k -n "$ns" delete pod "$pod" --wait=true --timeout=60s >/dev/null || die "pod $ns/$pod did not go within 60s"
  if [[ -n "$kind" ]]; then
    sleep 3
    wait_until 120 "$kind $ns/$owner is ready again" workload_ready "$kind" "$ns" "$owner"
  fi
}
if ((${#stale[@]} > 0)); then
  uids="$(printf '%s\n' "${stale[@]}" | jq -Rsc 'split("\n") | map(select(length > 0)) | unique')"
  # kindnet and kube-proxy come first, because kube-proxy routes the service address of the API server for every other pod. istio-cni-node, istiod and the other pods follow.
  while read -r ns pod kind owner; do
    replace_pod "$ns" "$pod" "$kind" "$owner" </dev/null
  done < <(k get pods -A -o json | repair_order_pods "$uids")
fi

all_ready() {
  local bad
  bad="$(k get deployments,statefulsets,daemonsets -A -o json | jq -r '.items[] | select(
    if .kind == "DaemonSet" then .status.numberReady != .status.desiredNumberScheduled or .status.updatedNumberScheduled != .status.desiredNumberScheduled
    else ((.status.readyReplicas // 0) != (.spec.replicas // 1)) or ((.status.updatedReplicas // 0) != (.spec.replicas // 1)) or ((.status.replicas // 0) != (.spec.replicas // 1)) end)
    | "\(.kind)/\(.metadata.namespace)/\(.metadata.name)"')" || return 1
  [[ -z "$bad" ]]
}
wait_until 180 "every workload of $CELL_NAME is ready" all_ready
on_node rm -f "$KEYTEST_SAVED"

# Step 5: the key check of the record of the cell.
mgmt() { (cd "$ROOT" && mise run mgmt -- "$@" 2>/dev/null); }
if mgmt status >/dev/null; then
  for attempt in 1 2 3; do
    out="$(mgmt keycheck --cell "$CELL_NAME")" || die "the key check of $CELL_NAME failed: ${out:-no output}"
    result="$(jq -r '.result // ""' <<<"$out")"
    log "key check $attempt of $CELL_NAME: ${result:-no result}"
    [[ "$result" == rate_limited ]] || break
    ((attempt < 3)) || break
    sleep 61
  done
  record_kids="$(mgmt status | jq -r --arg cell "$CELL_NAME" '[.cells[] | select(.name == $cell)][0].kids // [] | sort | join(" ")')"
  [[ "$record_kids" == "$(api_kids)" ]] || die "the record of $CELL_NAME lists the key IDs '$record_kids', and the API server publishes '$(api_kids)'. The key check answered '${result:-none}'"
  log "the record of $CELL_NAME lists the key IDs of the API server: $record_kids"
else
  log "mgmtd does not answer, so the key check of $CELL_NAME is skipped"
fi
log "$cp and $CELL_NAME are repaired. Run: CELL=$cp mise run cell:verify and CELL=$CELL_NAME mise run cell:verify"
