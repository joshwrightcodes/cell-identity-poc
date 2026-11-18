# Checks for what a gate:m2 run leaves behind when it stops before its cleanup. Source this file.
# Each check prints one line for each trace and nothing when it finds none. It returns 1 only when
# it cannot read what it checks. scripts/gate-m2-repair.sh removes the traces.

# The M2 key rotation test edits the API server of one cell on its node. These paths name what it
# leaves there.
KEYTEST_MANIFEST=/etc/kubernetes/manifests/kube-apiserver.yaml
KEYTEST_SAVED=/root/m2-test-kube-apiserver.yaml
KEYTEST_KEY=/etc/kubernetes/pki/m2-test-sa

# node_matches <cluster> fails unless the node container that docker reaches has the InternalIP of
# the cluster node. A docker client that talks to another daemon then edits nothing.
node_matches() {
  local node="$1-control-plane" docker_ip kube_ip
  docker_ip="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}' "$node" 2>/dev/null)" || {
    echo "docker reaches no container $node. DOCKER_HOST is '${DOCKER_HOST:-unset}'"; return 1; }
  kube_ip="$(kubectl --context "kind-$1" get node "$node" -o jsonpath='{.status.addresses[?(@.type=="InternalIP")].address}' 2>/dev/null)" || {
    echo "cannot read the node $node from the API server of $1"; return 1; }
  [[ -n "$kube_ip" && " $docker_ip " == *" $kube_ip "* ]] || {
    echo "the container $node has the addresses '${docker_ip% }', and the API server of $1 reports '$kube_ip'. DOCKER_HOST is '${DOCKER_HOST:-unset}'"; return 1; }
}

# keytest_leftover <cluster> prints each trace of the key rotation test on the node of the cluster.
keytest_leftover() {
  node_matches "$1" || return 1
  docker exec "$1-control-plane" sh -c "
    [ -e '$KEYTEST_SAVED' ] && echo 'the node holds the saved manifest $KEYTEST_SAVED'
    grep -q 'm2-test-sa' '$KEYTEST_MANIFEST' && echo '$KEYTEST_MANIFEST names the test key'
    for f in '$KEYTEST_KEY.key' '$KEYTEST_KEY.pub'; do [ -e \"\$f\" ] && echo \"the node holds \$f\"; done
    true"
}

# store_forward_start <cluster> starts a port-forward to the registry of the bundle store of the cluster on a
# free local port, and sets STORE_ADDR and STORE_PF_PID. store_forward_stop ends it. The registry listens on
# the loopback address of the pod (port 5001), behind the token proxy on port 5000, so the forward goes to the pod.
store_forward_start() {
  local out port="" i
  out="$(mktemp)"
  kubectl --context "kind-$1" -n cell-system port-forward --address 127.0.0.1 pod/bundle-store-0 :5001 >"$out" 2>&1 &
  STORE_PF_PID=$!
  for i in $(seq 1 60); do
    port="$(sed -n 's/^Forwarding from 127\.0\.0\.1:\([0-9]*\) -> 5001$/\1/p' "$out" | head -n 1)"
    [[ -n "$port" ]] && break
    sleep 0.5
  done
  rm -f "$out"
  if [[ -n "$port" ]]; then
    STORE_ADDR="127.0.0.1:$port"
    for i in $(seq 1 30); do
      curl -fsS "http://$STORE_ADDR/v2/" >/dev/null 2>&1 && return 0
      sleep 0.5
    done
  fi
  store_forward_stop
  return 1
}

store_forward_stop() {
  kill "${STORE_PF_PID:-}" 2>/dev/null || true
  wait "${STORE_PF_PID:-}" 2>/dev/null || true
}

# The entries test publishes test bundles of root and spire-server, and an entry under /m2-test/.
BUNDLE_TEST_NAMES=(root spire-server)
BUNDLE_TEST_PATH=/m2-test/

# published_digest <cluster> <bundle> prints the digest that the last cell:publish pushed.
published_digest() {
  sed -n "s/^$2=//p" "$BUILD_ROOT/$1/published.env" 2>/dev/null
}

# bundle_traces <cluster> prints each trace of the entries test in the cluster: a current tag or an
# Application revision that differs from build/<cluster>/published.env, and a test entry.
bundle_traces() {
  local cluster="$1" name want got apps entries
  [[ -f "$BUILD_ROOT/$cluster/published.env" ]] || { echo "no build/$cluster/published.env. Run: CELL=$cluster mise run cell:up"; return 1; }
  store_forward_start "$cluster" || { echo "cannot reach the bundle store of $cluster"; return 1; }
  for name in "${BUNDLE_TEST_NAMES[@]}"; do
    want="$(published_digest "$cluster" "$name")"
    got="$(oras resolve --plain-http "$STORE_ADDR/bundles/$name:current" 2>/dev/null)" || got="unreadable"
    [[ -n "$want" && "$got" == "$want" ]] || echo "$name:current in the bundle store of $cluster is $got, and build/$cluster/published.env has '${want:-nothing}'"
  done
  store_forward_stop
  apps="$(applications_json kubectl --context "kind-$cluster")" || {
    echo "cannot read the Applications of $cluster in argocd"; return 1; }
  jq -e '[.items[] | select(.metadata.name == "root" or .metadata.name == "spire-server")] | length == 2' >/dev/null <<<"$apps" || {
    echo "$cluster has no Application root or spire-server in argocd"; return 1; }
  jq -r --arg root "$(published_digest "$cluster" root)" --arg spire "$(published_digest "$cluster" spire-server)" '.items[]
    | select(.metadata.name == "root" or .metadata.name == "spire-server")
    | if .metadata.name == "root" then select(.status.sync.revision != $root)
        | "Application root in \(.metadata.namespace) synced \(.status.sync.revision), and published.env has \($root)"
      else select(.spec.source.targetRevision != $spire or .status.sync.revision != $spire)
        | "Application spire-server pins \(.spec.source.targetRevision) and synced \(.status.sync.revision), and published.env has \($spire)"
      end' <<<"$apps"
  entries="$(kubectl --context "kind-$cluster" -n spire-system exec spire-server-0 -c spire-server -- \
    /opt/spire/bin/spire-server entry show -socketPath /run/spire/sockets/api.sock -output json 2>/dev/null)" || {
    echo "cannot read the entries of the SPIRE server in $cluster"; return 1; }
  jq -r --arg p "$BUNDLE_TEST_PATH" '.entries[] | select(.spiffe_id.path | startswith($p))
    | "the SPIRE server holds the test entry spiffe://\(.spiffe_id.trust_domain)\(.spiffe_id.path)"' <<<"$entries"
}

# record_kids_trace <cell> <key IDs of the API server, sorted and joined by spaces> prints one line when mgmtd answers and the record
# of the cell lists other key IDs. A repair that stopped between its pod replacement and its key check leaves such a record. It
# prints nothing when mgmtd does not answer.
record_kids_trace() {
  local status record
  status="$(cd "$ROOT" && mise run mgmt -- status 2>/dev/null)" || return 0
  jq -e 'type == "object"' >/dev/null 2>&1 <<<"$status" || return 0
  record="$(jq -r --arg cell "$1" '[.cells[] | select(.name == $cell)][0].kids // [] | sort | join(" ")' <<<"$status")"
  [[ "$record" == "$2" ]] || echo "the record of $1 lists the key IDs '$record', and the API server publishes '$2'. Run: mise run mgmt -- keycheck --cell $1"
}

# repair_order_pods <stale pod UIDs as a JSON array> reads the output of `kubectl get pods -A -o json` on standard input and prints
# "<namespace> <pod> <owner kind> <owner name>" for each pod with one of the UIDs. Three ranks, in this order:
#   0. kindnet, kube-proxy and istio-cni-node: kindnet enforces NetworkPolicy, kube-proxy routes the service addresses that other pods
#      need to start, and no pod gets a sandbox while the token of istio-cni-node is signed by a key that the API server no longer verifies.
#   1. istiod (label app.kubernetes.io/name): it reviews tokens through the API server and issues the certificates of other pods. An
#      app pod that waits for a certificate from an istiod with a token of the old key never gets one, so istiod comes before every
#      app pod, whatever the namespace sorts like. The cells hold no SPIRE server, so no other issuer is in this rank.
#   2. every other pod, in list order.
repair_order_pods() {
  jq -r --argjson uids "$1" '[.items[] | select(.metadata.uid as $u | $uids | index($u))]
    | sort_by(if ((.metadata.ownerReferences[0].name // "") | IN("kindnet", "kube-proxy", "istio-cni-node")) then 0
        elif ((.metadata.labels["app.kubernetes.io/name"] // "") | IN("istiod")) then 1 else 2 end)
    | .[] | "\(.metadata.namespace) \(.metadata.name) \(.metadata.ownerReferences[0].kind // "none") \(.metadata.ownerReferences[0].name // "none")"'
}

# The checks of step 3 of gate-m2-repair.sh. They need the functions k (kubectl of the cell) and on_node (a command on the node). They never
# read the status of the mirror pods: just after a restart of the API server, a mirror pod can still show the old container, whose start
# counts as "after the API server". Each component counts as current when all of these hold:
#   - the container runtime shows a running container that started at or after the API server;
#   - its Lease names the node as holder, and its renew time is within the lease duration of the node time, so the holder is alive;
#   - when the repair stopped the old container, the Lease has a new holder or an acquire time at or after the stop. The old process
#     renewed its Lease against the new API server before the stop, so a renew time alone does not show the new container.
# The Lease shows that the holder won the election. It does not show every controller of the manager.

# container_started <name> prints the start time, in epoch seconds, of the running container of that name on the node, from the container
# runtime. It returns 1 when no such container runs, and 2 when the runtime call fails.
container_started() {
  local ids id
  ids="$(on_node crictl ps --name "^$1\$" --state running -q)" || return 2
  id="$(head -n 1 <<<"$ids")"
  [[ -n "$id" ]] || return 1
  on_node crictl inspect "$id" | jq -er '.status.startedAt | sub("\\.[0-9]+Z$"; "Z") | fromdateiso8601' || return 2
}

# lease_holder <lease> prints the holder identity of Lease kube-system/<lease>, or nothing.
lease_holder() {
  k -n kube-system get lease "$1" -o json | jq -r '.spec.holderIdentity // ""'
}

# lease_current <lease> <node> <now> [<holder before the stop> <stop time>] succeeds when the Lease has the node as holder, and its
# renew time is not older than the lease duration at <now>. With a holder before the stop, it also needs a new holder, or an acquire
# time at or after the stop time. All times are epoch seconds of the node clock.
lease_current() {
  k -n kube-system get lease "$1" -o json | jq -e --arg n "$2" --argjson now "$3" --arg old "${4:-}" --argjson stop "${5:-0}" '
    def ts: sub("\\.[0-9]+Z$"; "Z") | fromdateiso8601;
    ((.spec.holderIdentity // "") | startswith($n + "_"))
    and ((.spec.renewTime // "" | ts) + (.spec.leaseDurationSeconds // 15) >= $now)
    and ($old == "" or .spec.holderIdentity != $old or ((.spec.acquireTime // "" | ts) >= $stop))' >/dev/null 2>&1
}

# component_current <container and Lease name> <node> <API server start> <now> [<holder before the stop> <stop time>]
component_current() {
  local started
  started="$(container_started "$1")" && ((started >= $3)) && lease_current "$1" "$2" "$4" "${5:-}" "${6:-}"
}

# control_plane_current <node> <API server start> [<manager holder before the stop> <manager stop time> <scheduler holder before the stop>
# <scheduler stop time>] succeeds when kube-controller-manager and kube-scheduler are both current. The holder and stop time of a component
# that the repair did not stop are empty.
control_plane_current() {
  local now
  now="$(on_node date +%s)" || return 1
  component_current kube-controller-manager "$1" "$2" "$now" "${3:-}" "${4:-}" \
    && component_current kube-scheduler "$1" "$2" "$now" "${5:-}" "${6:-}"
}

# lease_summary <lease> prints the holder and the acquire time of Lease kube-system/<lease>.
lease_summary() {
  k -n kube-system get lease "$1" -o json | jq -r '"holder " + (.spec.holderIdentity // "none") + ", acquireTime " + (.spec.acquireTime // "none")'
}

# settle_control_plane <node> <API server start> <bound in seconds> is step 3 of gate-m2-repair.sh. It stops each container of
# kube-controller-manager and kube-scheduler that started before the API server, because such a container keeps the tokens of the old key
# in memory. It reads the Lease holder before each stop, and takes the stop time from the node clock. Then it waits, up to the bound, until
# control_plane_current holds with those values. The pause between two checks is $CONTROL_PLANE_POLL seconds (default 3). It logs the holder
# before the stop, the stop time, and the holder and acquire time of the Lease that let the wait pass. It returns 1 after a failed call or a timeout.
settle_control_plane() {
  local node="$1" api_started="$2" bound="$3" component rc started holder ids id stopped_at end
  local manager_holder="" manager_stop="" scheduler_holder="" scheduler_stop=""
  for component in kube-controller-manager kube-scheduler; do
    rc=0
    started="$(container_started "$component")" || rc=$?
    if ((rc == 2)); then
      log "the container runtime call failed on $node while it read the $component container"
      return 1
    fi
    ((rc == 0)) && ((started < api_started)) || continue
    holder="$(lease_holder "$component")" || { log "cannot read Lease $component"; return 1; }
    ids="$(on_node crictl ps --name "^$component\$" -q)" || { log "the container runtime call failed on $node while it listed $component"; return 1; }
    for id in $ids; do
      on_node crictl stop "$id" >/dev/null || { log "cannot stop the container $id of $component on $node"; return 1; }
    done
    stopped_at="$(on_node date +%s)" || { log "cannot read the time of the node $node"; return 1; }
    case "$component" in
      kube-controller-manager) manager_holder="$holder" manager_stop="$stopped_at" ;;
      kube-scheduler) scheduler_holder="$holder" scheduler_stop="$stopped_at" ;;
    esac
    log "stopped the $component container, which started before the API server. Lease holder before the stop '${holder:-none}', stop time $stopped_at (node clock)"
  done
  end=$((SECONDS + bound))
  log "waiting up to ${bound}s until kube-controller-manager and kube-scheduler run a container that started after the API server and hold a live Lease"
  until control_plane_current "$node" "$api_started" "$manager_holder" "$manager_stop" "$scheduler_holder" "$scheduler_stop" >/dev/null 2>&1; do
    ((SECONDS < end)) || { log "kube-controller-manager and kube-scheduler are not current after ${bound}s"; return 1; }
    sleep "${CONTROL_PLANE_POLL:-3}"
  done
  for component in kube-controller-manager kube-scheduler; do
    log "the Lease of $component let the wait pass: $(lease_summary "$component" 2>/dev/null || echo 'unreadable')"
  done
}
