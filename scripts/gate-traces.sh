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

# store_forward_start <cluster> starts a port-forward to the bundle store of the cluster on a free
# local port, and sets STORE_ADDR and STORE_PF_PID. store_forward_stop ends it.
store_forward_start() {
  local out port="" i
  out="$(mktemp)"
  kubectl --context "kind-$1" -n cell-system port-forward --address 127.0.0.1 svc/bundle-store :5000 >"$out" 2>&1 &
  STORE_PF_PID=$!
  for i in $(seq 1 60); do
    port="$(sed -n 's/^Forwarding from 127\.0\.0\.1:\([0-9]*\) -> 5000$/\1/p' "$out" | head -n 1)"
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
#   1. istiod and the SPIRE server (label app.kubernetes.io/name): they review tokens through the API server or issue the certificates
#      of other pods. An app pod that waits for a certificate from an issuer that still holds a token of the old key never gets
#      one, so the issuers come before every app pod, whatever the namespace sorts like.
#   2. every other pod, in list order.
repair_order_pods() {
  jq -r --argjson uids "$1" '[.items[] | select(.metadata.uid as $u | $uids | index($u))]
    | sort_by(if ((.metadata.ownerReferences[0].name // "") | IN("kindnet", "kube-proxy", "istio-cni-node")) then 0
        elif ((.metadata.labels["app.kubernetes.io/name"] // "") | IN("istiod", "spire-server")) then 1 else 2 end)
    | .[] | "\(.metadata.namespace) \(.metadata.name) \(.metadata.ownerReferences[0].kind // "none") \(.metadata.ownerReferences[0].name // "none")"'
}

# The checks of step 3 of gate-m2-repair.sh. They need the functions k (kubectl of the cell) and on_node (a command on the node), and
# they never read the status of the mirror pods: just after a restart of the API server, the mirror pod of a static pod can still show
# the old container, whose start counts as "after the API server".

# container_started <name> prints the start time, in epoch seconds, of the running container of that name on the node, from
# the container runtime. It fails when no such container runs.
container_started() {
  local id
  id="$(on_node crictl ps --name "^$1\$" --state running -q | head -n 1)" && [[ -n "$id" ]] || return 1
  on_node crictl inspect "$id" | jq -er '.status.startedAt | sub("\\.[0-9]+Z$"; "Z") | fromdateiso8601'
}

# lease_current <lease> <node> <epoch> succeeds when Lease kube-system/<lease> has the node as holder and shows an acquire or a renew
# time at or after the epoch. A held lease shows that the component runs its controllers, which a ready container does not show.
lease_current() {
  k -n kube-system get lease "$1" -o json | jq -e --arg n "$2" --argjson t "$3" 'def ts: sub("\\.[0-9]+Z$"; "Z") | fromdateiso8601;
    ((.spec.holderIdentity // "") | startswith($n + "_"))
    and (([.spec.acquireTime, .spec.renewTime] | map(select(. != null) | ts) | max) >= $t)' >/dev/null
}

# control_plane_current <node> <epoch of the API server start> succeeds when kube-controller-manager and kube-scheduler each hold their lease
# since the start of the API server.
control_plane_current() {
  lease_current kube-controller-manager "$1" "$2" && lease_current kube-scheduler "$1" "$2"
}
