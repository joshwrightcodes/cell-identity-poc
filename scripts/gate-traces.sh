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
# "<namespace> <pod> <owner kind> <owner name>" for each pod with one of the UIDs. The pods of kindnet and kube-proxy come first:
# kindnet enforces NetworkPolicy, and kube-proxy routes the service addresses that other pods need to start.
repair_order_pods() {
  jq -r --argjson uids "$1" '[.items[] | select(.metadata.uid as $u | $uids | index($u))]
    | sort_by(if ((.metadata.ownerReferences[0].name // "") | IN("kindnet", "kube-proxy")) then 0 else 1 end)
    | .[] | "\(.metadata.namespace) \(.metadata.name) \(.metadata.ownerReferences[0].kind // "none") \(.metadata.ownerReferences[0].name // "none")"'
}
