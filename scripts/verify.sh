#!/usr/bin/env bash
# Check each base cell rule against the running cluster. Prints PASS or FAIL per check and
# exits non-zero if any check fails.
source "$(dirname "$0")/lib.sh"
set +e

failures=0
check() {
  local name="$1"; shift
  local detail
  if detail="$("$@" 2>&1)"; then
    printf 'PASS  %s\n' "$name"
  else
    printf 'FAIL  %s\n' "$name"
    [[ -n "$detail" ]] && printf '      %s\n' "${detail//$'\n'/$'\n      '}"
    failures=$((failures + 1))
  fi
}

# curl_from <deployment> <curl args...>: run curl in the curl container of a demo workload.
curl_from() {
  local from="$1"; shift
  k -n apps-demo exec "deploy/$from" -c curl -- curl -sS --max-time 10 "$@"
}

http_code() {
  local from="$1" url="$2"
  curl_from "$from" -o /dev/null -w '%{http_code}' "$url" 2>/dev/null
}

expect_code() {
  local from="$1" url="$2" want="$3" got
  got="$(http_code "$from" "$url")"
  [[ "$got" == "$want" ]] || { echo "$from -> $url: got HTTP '${got:-none}', want $want"; return 1; }
}

expect_no_connection() {
  # curl prints 000 when it cannot connect. Any other output, including none from a failed
  # kubectl exec, is a failure.
  local from="$1" url="$2" got
  got="$(http_code "$from" "$url")"
  [[ "$got" == "000" ]] || { echo "$from -> $url: got '${got:-no output}', want no connection (000)"; return 1; }
}

expect_no_tcp() {
  # curl exits with 28 when the connect times out, which is what a NetworkPolicy drop gives. Exit 7
  # means that a host refused the connection, and other codes mean that a listener answered.
  local from="$1" url="$2" rc
  curl_from "$from" -o /dev/null "$url" >/dev/null 2>&1
  rc=$?
  [[ "$rc" == 28 ]] || { echo "$from -> $url: curl exit $rc, want 28 (connect timeout)"; return 1; }
}

has_proxy() {
  # Istio adds istio-proxy as a native sidecar (an init container) or as a regular container.
  k -n "$1" get pod -l "app=$2" -o json | jq -e '
    [.items[].spec | (.initContainers // []) + .containers | .[].name] | index("istio-proxy") != null' >/dev/null
}

check_apps_synced() {
  k -n argocd get applications -o json | jq -e --argjson n "$((${#COMPONENTS[@]} + 1))" '
    (.items | length) == $n and
    all(.items[]; .status.sync.status == "Synced" and .status.health.status == "Healthy")' >/dev/null \
    || { k -n argocd get applications; return 1; }
}

check_argocd_local_only() {
  local clusters
  clusters="$(k -n argocd get secrets -l argocd.argoproj.io/secret-type=cluster -o name)"
  [[ -z "$clusters" ]] || { echo "remote cluster secrets: $clusters"; return 1; }
  k -n argocd get applications -o json | jq -e --arg store "oci://$BUNDLE_STORE_HOST/bundles/" '
    all(.items[]; .spec.destination.server == "https://kubernetes.default.svc"
      and (.spec.source.repoURL | startswith($store)))' >/dev/null \
    || { echo "an Application has another destination or source"; return 1; }
}

# The base platform namespaces, and the namespace of each harness component of this cell.
platform_namespaces=(argocd cell-system observability-system)
for entry in ${HARNESS_COMPONENTS[@]+"${HARNESS_COMPONENTS[@]}"}; do
  platform_namespaces+=("${entry#*:}")
done

has_harness() {
  local entry
  for entry in ${HARNESS_COMPONENTS[@]+"${HARNESS_COMPONENTS[@]}"}; do
    [[ "${entry%%:*}" == "$1" ]] && return 0
  done
  return 1
}

check_platform_outside_mesh() {
  local ns
  for ns in "${platform_namespaces[@]}"; do
    k -n "$ns" get pods -o json | jq -e '
      [.items[].spec | (.initContainers // []) + .containers | .[].name] | index("istio-proxy") == null' >/dev/null \
      || { echo "$ns has a pod with istio-proxy"; return 1; }
  done
}

check_workloads_in_mesh() {
  local app
  for app in echo client intruder; do
    has_proxy apps-demo "$app" || { echo "$app has no istio-proxy"; return 1; }
  done
  ! has_proxy apps-demo plaintext || { echo "plaintext has istio-proxy"; return 1; }
}

check_trust_domain() {
  local want="spiffe://$CELL_MESH_TRUST_DOMAIN/ns/apps-demo/sa/echo" certs
  certs="$(k -n apps-demo exec deploy/echo -c istio-proxy -- pilot-agent request GET certs)"
  grep -qF "\"$want\"" <<<"$certs" || { echo "echo has no certificate for $want"; return 1; }
}

check_egress_through_gateway() {
  # Count upstream connections from the gateway to example.com. Istio trims most stats from
  # the stats endpoint, but /clusters keeps a cx_total counter for each upstream host.
  gateway_count() {
    k -n istio-egress exec deploy/istio-egressgateway -- pilot-agent request GET clusters \
      | awk -F'::' '$1 == "outbound|443||example.com" && $3 == "cx_total" { n += $4 } END { print n + 0 }'
  }
  local before after
  before="$(gateway_count)"
  expect_code client https://example.com/ 200 || return 1
  after="$(gateway_count)"
  ((after > before)) || { echo "egress gateway connections to example.com: $before before, $after after"; return 1; }
}

check_psa_rejects_privileged() {
  local out
  if out="$(k -n apps-demo run psa-probe --image=docker.io/curlimages/curl:8.23.0 --privileged \
    --dry-run=server -o name 2>&1)"; then
    echo "a privileged pod was admitted: $out"
    return 1
  fi
  grep -q "violates PodSecurity" <<<"$out" || { echo "$out"; return 1; }
}

node_ip() {
  local facts ip
  facts="$(cd "$ROOT" && mise run hostsvc -- facts --cluster "$1" 2>/dev/null)" || { echo "no host service facts for $1"; return 1; }
  ip="$(jq -r '.nodeIP // ""' <<<"$facts")"
  [[ -n "$ip" ]] || { echo "the host service reports no node address for $1"; return 1; }
  printf '%s\n' "$ip"
}

# The cell renders the address of the SPIRE server node into the agent config and the NetworkPolicy.
# Docker can give a rebuilt node a new address, so both must match the host service now.
check_spire_server_address() {
  local want conf addr cidrs
  want="$(node_ip "$SPIRE_SERVER_CLUSTER")" || { echo "$want"; return 1; }
  conf="$(k -n cell-identity-system get configmap spire-agent -o jsonpath='{.data.agent\.conf}')"
  addr="$(sed -n 's/^ *server_address = "\(.*\)"$/\1/p' <<<"$conf")"
  cidrs="$(k -n cell-identity-system get networkpolicy celld -o json \
    | jq -r '[.spec.egress[] | select(any(.ports[]; .port == 30081)) | .to[].ipBlock.cidr] | join(" ")')"
  if [[ "$addr" != "$want" || "$cidrs" != "$want/32" ]]; then
    echo "the $SPIRE_SERVER_CLUSTER node is $want, but the agent uses '$addr' and the NetworkPolicy allows '$cidrs'."
    echo "Run: CELL=$CELL_NAME mise run cell:up"
    return 1
  fi
}

# The SPIRE server renders the node address and the signed record of each agent cell. A rebuilt
# cell has a new service account key, and it can have a new node address.
check_agent_cells_current() {
  local cell ip facts want got cidrs traces want_cidrs=() stale=()
  for cell in $SPIRE_AGENT_CELLS; do
    ip="$(node_ip "$cell")" || { echo "$ip"; return 1; }
    want_cidrs+=("$ip/32")
    facts="$(cd "$ROOT" && mise run hostsvc -- facts --cluster "$cell" 2>/dev/null)"
    want="$(jq -cS '.jwks.keys | sort_by(.kid)' <<<"$facts")"
    got="$(k -n spire-system get configmap "cell-record-$cell" -o jsonpath='{.data.record\.dsse\.json}' \
      | jq -r .payload | base64 -d | jq -cS '.jwks.keys | sort_by(.kid)')"
    [[ -n "$want" && "$got" == "$want" ]] || stale+=("the record of $cell holds other service account keys than $cell")
  done
  cidrs="$(k -n spire-system get networkpolicy spire-server-agents -o json | jq -r '[.spec.ingress[0].from[].ipBlock.cidr] | sort | join(" ")')"
  # jq sorts both sides, so the comparison does not depend on the locale of sort.
  want="$(printf '%s\n' "${want_cidrs[@]}" | jq -Rrs 'split("\n") | map(select(length > 0)) | sort | join(" ")')"
  [[ "$cidrs" == "$want" ]] || stale+=("the NetworkPolicy admits '$cidrs', but the agent cell nodes are '$want'")
  if ((${#stale[@]} > 0)); then
    printf '%s\n' "${stale[@]}"
    # A new record signs the live keys. While the key rotation test has changed a cell, those keys
    # include the test key, so the node must be repaired first.
    for cell in $SPIRE_AGENT_CELLS; do
      traces="$(keytest_leftover "$cell" 2>/dev/null || true)"
      if [[ -n "$traces" ]]; then
        printf '%s\n' "$traces"
        echo "Run: mise run gate:m2:repair, and then CELL=$CELL_NAME mise run cell:verify again"
        return 1
      fi
    done
    echo "Run: CELL=$CELL_NAME mise run cell:up"
    return 1
  fi
}

# The last identity event of celld must be an SVID for this cell that has not expired. A watch
# error after the last SVID means that the agent withdrew it, for example because no entry
# matches any more. celld logs its SVID again after each watch error.
check_celld_svid() {
  local want="spiffe://dev.env.poc.internal/cell/$CELL_NAME/celld" line
  line="$(k -n cell-identity-system logs deploy/celld -c celld | jq -cR 'fromjson?
    | select(.msg == "x509 svid updated" or .msg == "x509 svid held"
      or .msg == "workload api watch failed" or .msg == "workload api update without an svid")' \
    | tail -n 1)"
  if [[ -n "$line" ]] && jq -e --arg want "$want" '(.msg == "x509 svid updated" or .msg == "x509 svid held")
      and .spiffe_id == $want and (.not_after | fromdateiso8601) > now' <<<"$line" >/dev/null; then
    return 0
  fi
  echo "the last identity event of celld is ${line:-missing}, want an SVID for $want with a not_after in the future."
  echo "Read the agent log: mise x -- kubectl --context kind-$CELL_NAME -n cell-identity-system logs deploy/celld -c spire-agent"
  echo "Check the entries on the server: CELL=$SPIRE_SERVER_CLUSTER mise run cell:verify runs the check 'The SPIRE server holds the node alias and celld entries'."
  echo "Then run: CELL=$CELL_NAME mise run cell:up"
  return 1
}

# kindnet applies NetworkPolicy to a new pod only a few seconds after the pod starts. Because of
# this, a probe pod runs netprobe serve, and each probe runs netprobe dial in it with kubectl exec.
# Probe pods carry only the label below, and no app label that a NetworkPolicy selects. They run
# as user 1002, which no registration entry selects, and they mount no ServiceAccount token.
probe_label=cell.poc.internal/verify-probe=true
probe_targets=()
cleanup_probe_pods() {
  local target
  for target in ${probe_targets[@]+"${probe_targets[@]}"}; do
    kubectl --context "kind-${target%%/*}" -n "${target#*/}" delete pod -l "$probe_label" --wait=false >/dev/null 2>&1 || true
  done
}
trap cleanup_probe_pods EXIT
probe_records="$BUILD/verify-probes.log"
# max_first_block is the longest time from Ready to the first blocked dial that a probe accepts.
max_first_block=10

# expect_dial_blocked <cluster> <namespace> <ip:port>: a probe pod in the namespace must not open a
# TCP connection to the address. Only a dial timeout counts as blocked, because a refused dial
# means that the packets reached the host. The first blocked dial must come within
# max_first_block seconds of Ready, and three more dials over about six seconds must also time
# out. The time to the first block goes to build/<cluster>/verify-probes.log.
expect_dial_blocked() {
  local cluster="$1" ns="$2" addr="$3" image name overrides out="" dialed="" result=1 ready_at dial_start first="" i
  local kc=(kubectl --context "kind-$cluster" -n "$ns")
  image="$(sed -n 's/^IMAGE_NETPROBE=//p' "$BUILD_ROOT/images.env" 2>/dev/null)"
  [[ -n "$image" ]] || { echo "build/images.env has no IMAGE_NETPROBE. Run mise run images."; return 1; }
  [[ "$addr" =~ ^[0-9.]+:[0-9]+$ ]] || { echo "probe address '$addr' is not <IP address>:<port>"; return 1; }
  name="verify-probe-$RANDOM$RANDOM"
  overrides="$(jq -cn --arg name "$name" --arg image "$image" '{metadata: {labels: {"cell.poc.internal/verify-probe": "true"}}, spec: {
    automountServiceAccountToken: false,
    securityContext: {runAsNonRoot: true, runAsUser: 1002, runAsGroup: 1002, seccompProfile: {type: "RuntimeDefault"}},
    containers: [{name: $name, image: $image, args: ["serve", "--addr", ":8080"],
      securityContext: {allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, capabilities: {drop: ["ALL"]}}}]}}')"
  "${kc[@]}" run "$name" --image="$image" --restart=Never --overrides="$overrides" >/dev/null 2>&1 \
    || { echo "could not start a probe pod in $cluster/$ns"; return 1; }
  # dial sets out to the netprobe output and dialed to its result.
  dial() {
    out="$("${kc[@]}" exec "$name" -- /ko-app/netprobe dial --addr "$addr" --timeout 2s 2>&1)"
    dialed="$(jq -r '.result // "error"' <<<"$out" 2>/dev/null || echo error)"
  }
  if "${kc[@]}" wait --for=condition=Ready "pod/$name" --timeout=120s >/dev/null 2>&1; then
    ready_at=$SECONDS
    # first is the time from Ready to the start of the first dial that timed out.
    while ((SECONDS - ready_at <= max_first_block)); do
      dial_start=$SECONDS
      dial
      if [[ "$dialed" == timeout ]]; then first=$((dial_start - ready_at)); break; fi
      sleep 1
    done
    if [[ -n "$first" ]] && ((first > max_first_block)); then
      echo "a probe pod in $cluster/$ns was first blocked ${first}s after Ready, over the limit of ${max_first_block}s"
    elif [[ -z "$first" ]]; then
      echo "a probe pod in $cluster/$ns still reached $addr ${max_first_block}s after Ready: $out"
    else
      result=0
      for i in 1 2 3; do
        sleep 2
        dial
        if [[ "$dialed" != timeout ]]; then
          echo "a probe pod in $cluster/$ns was blocked at ${first}s, then dial $i to $addr gave: $out"
          result=1
          break
        fi
      done
      printf '%s %s/%s -> %s first block %ss after Ready, steady state %s\n' "$(date -u +%FT%TZ)" "$cluster" "$ns" "$addr" \
        "$first" "$([[ $result == 0 ]] && echo held || echo broken)" >>"$probe_records"
    fi
  else
    echo "the probe pod $cluster/$ns/$name did not become Ready"
  fi
  "${kc[@]}" delete pod "$name" --wait=false >/dev/null 2>&1 || true
  return "$result"
}

# The harness applies its components without Argo CD, so cell:verify compares them with the bundle.
check_harness_drift() {
  local bundle="$BUNDLES/$1/manifests.yaml" out rc
  [[ -f "$bundle" ]] || { echo "no $bundle. Run: CELL=$CELL_NAME mise run cell:up"; return 1; }
  out="$(k diff --server-side --force-conflicts -f "$bundle" 2>&1)"
  rc=$?
  case "$rc" in
    0) return 0 ;;
    1) printf '%s\n' "$out" | head -n 40; echo "Run: CELL=$CELL_NAME mise run cell:up"; return 1 ;;
    *) echo "kubectl diff failed: $out"; return 1 ;;
  esac
}

# The harness apply does not prune, and kubectl diff sees only the fields of its own field manager.
# So for each kind in the bundle, the namespace must hold exactly the objects of the bundle, apart
# from objects that only system controllers write, for example kube-root-ca.crt. Each object of
# the bundle must have only the field manager kubectl, and kube-controller-manager for status.
check_harness_objects() {
  local comp="$1" ns="$2" bundle="$BUNDLES/$1/manifests.yaml" kind want got live bad problems=()
  for kind in $(yq -N -r 'select(.kind != null and .kind != "Namespace") | .kind' "$bundle" | sort -u); do
    want="$(KIND="$kind" yq -o=json -I=0 'select(.kind == strenv(KIND)) | .metadata.name' "$bundle" | jq -rs 'sort | join(" ")')"
    live="$(k -n "$ns" get "$kind" -o json --show-managed-fields)" || { echo "could not list $kind in $ns"; return 1; }
    got="$(jq -r --arg label "cell.poc.internal/harness" '[.items[]
      | select((.metadata.labels[$label] // "") != ""
        or any(.metadata.managedFields[]?; .manager != "kube-controller-manager" and .manager != "pilot-discovery"))
      | .metadata.name] | sort | join(" ")' <<<"$live")" || { echo "could not read the $kind objects in $ns"; return 1; }
    [[ "$got" == "$want" ]] || problems+=("$ns has the $kind objects '$got' that the harness or a person wrote, and the bundle $comp has '$want'")
    bad="$(jq -r --arg want " $want " '.items[] | .metadata.name as $name | select($want | contains(" " + $name + " "))
      | . as $o | $o.metadata.managedFields[]? | select((.manager == "kubectl" and .operation == "Apply")
        or (.manager == "kube-controller-manager" and .subresource == "status") | not)
      | "\($o.kind)/\($name) has the field manager \(.manager) (\(.operation) \(.subresource // "object"))"' <<<"$live")" \
      || { echo "could not read the field managers of $kind in $ns"; return 1; }
    [[ -z "$bad" ]] || problems+=("$bad")
  done
  live="$(k get namespace "$ns" -o json --show-managed-fields)" || { echo "no namespace $ns"; return 1; }
  bad="$(jq -r --arg ns "$ns" '.metadata.managedFields[]? | select(.manager == "kubectl" and .operation == "Apply" | not)
    | "Namespace/\($ns) has the field manager \(.manager)"' <<<"$live")" \
    || { echo "could not read the field managers of $ns"; return 1; }
  [[ -z "$bad" ]] || problems+=("$bad")
  if ((${#problems[@]} > 0)); then
    printf '%s\n' "${problems[@]}"
    echo "Delete each extra object, and each field that another manager added. Then run: CELL=$CELL_NAME mise run cell:up"
    return 1
  fi
}

# check_live_images <namespace> <kind/name> <command>: every local image of the workload must be the
# one that build/images.env records for it.
check_live_images() {
  local bad
  bad="$(live_image_mismatches "$CELL_NAME" "$1" "$2")" || { echo "could not read $2 in $1"; return 1; }
  if [[ -n "$bad" ]]; then
    printf '%s\n' "$bad"
    echo "Run: $3"
    return 1
  fi
}

# The M2 key rotation test changes the API server of a cell on its node. The node must hold no trace
# of it, and the API server must publish exactly the keys that the record of the cell holds.
check_keytest_clean() {
  local traces live record
  traces="$(keytest_leftover "$CELL_NAME")" || { echo "could not read the node $CELL_NAME-control-plane"; return 1; }
  live="$(k get --raw /openid/v1/jwks | jq -cS '.keys | sort_by(.kid)')" || { echo "could not read the JWKS of $CELL_NAME"; return 1; }
  record="$(kubectl --context "kind-$SPIRE_SERVER_CLUSTER" -n spire-system get configmap "cell-record-$CELL_NAME" -o jsonpath='{.data.record\.dsse\.json}' \
    | jq -r .payload | base64 -d | jq -cS '.jwks.keys | sort_by(.kid)')" || { echo "could not read the record of $CELL_NAME in $SPIRE_SERVER_CLUSTER"; return 1; }
  if [[ -n "$traces" ]]; then
    printf '%s\n' "$traces"
    echo "Run: mise run gate:m2:repair"
    return 1
  fi
  if [[ -z "$live" || "$live" != "$record" ]]; then
    echo "the API server of $CELL_NAME publishes other keys than its record in $SPIRE_SERVER_CLUSTER."
    echo "Run: CELL=$SPIRE_SERVER_CLUSTER mise run cell:up"
    return 1
  fi
}

# The server config must hold the SVID lifetimes that SPIRE_SVID_TTL in cells/$CELL.env sets.
check_svid_ttl() {
  local conf agent x509
  conf="$(k -n spire-system get configmap spire-server -o jsonpath='{.data.server\.conf}')" || { echo "could not read ConfigMap spire-server"; return 1; }
  agent="$(sed -n 's/^ *agent_ttl = "\(.*\)"$/\1/p' <<<"$conf")"
  x509="$(sed -n 's/^ *default_x509_svid_ttl = "\(.*\)"$/\1/p' <<<"$conf")"
  if [[ "$agent" != "$SPIRE_SVID_TTL" || "$x509" != "$SPIRE_SVID_TTL" ]]; then
    echo "the server sets agent_ttl '$agent' and default_x509_svid_ttl '$x509', and SPIRE_SVID_TTL is '$SPIRE_SVID_TTL'."
    echo "Run: CELL=$CELL_NAME mise run cell:up"
    return 1
  fi
}

# The SPIRE server must hold the node alias and the celld entry of each agent cell, with the
# parents and selectors that the render declares.
check_agent_entries() {
  local entries cell sa missing=()
  entries="$(k -n spire-system exec spire-server-0 -c spire-server -- \
    /opt/spire/bin/spire-server entry show -socketPath /run/spire/sockets/api.sock -output json)" \
    || { echo "could not read the entries from spire-server-0"; return 1; }
  sa="${SPIRE_AGENT_SUBJECT/\//:}"
  for cell in $SPIRE_AGENT_CELLS; do
    jq -e --arg cell "$cell" --arg sa "$sa" 'any(.entries[]; .spiffe_id.path == "/cell/\($cell)/nodes"
      and .parent_id.path == "/spire/server"
      and ([.selectors[] | "\(.type):\(.value)"] | sort) == (["cluster_jwt:cell:\($cell)", "cluster_jwt:sa:\($sa)"] | sort))' \
      <<<"$entries" >/dev/null || missing+=("no node alias entry spiffe://dev.env.poc.internal/cell/$cell/nodes with the selectors of $cell")
    jq -e --arg cell "$cell" 'any(.entries[]; .spiffe_id.path == "/cell/\($cell)/celld"
      and .parent_id.path == "/cell/\($cell)/nodes"
      and [.selectors[] | "\(.type):\(.value)"] == ["unix:uid:65532"])' \
      <<<"$entries" >/dev/null || missing+=("no celld entry spiffe://dev.env.poc.internal/cell/$cell/celld with selector unix:uid:65532")
  done
  if ((${#missing[@]} > 0)); then
    printf '%s\n' "${missing[@]}"
    echo "Run: CELL=$CELL_NAME mise run cell:up"
    return 1
  fi
}

check_traces_received() {
  local i
  for i in 1 2 3; do expect_code client http://echo/hostname 200 >/dev/null; done
  local end=$((SECONDS + 60))
  # Read the logs into a variable first. With pipefail, grep -q would close the pipe early
  # and turn a match into a failure.
  local logs
  until logs="$(k -n observability-system logs deploy/otel-collector --since=5m)" && grep -q 'echo.apps-demo' <<<"$logs"; do
    ((SECONDS < end)) || { echo "no span or access log for echo.apps-demo in the collector output"; return 1; }
    sleep 5
  done
}

log "checking cell $CELL_NAME"
k get --raw /readyz >/dev/null 2>&1 || die "cannot reach the API server of $CELL_NAME"
check "Argo CD reports every Application Synced and Healthy" check_apps_synced
check "Argo CD has no remote clusters and reads only the local store" check_argocd_local_only
check "$(IFS=,; echo "${platform_namespaces[*]}" | sed 's/,/, /g') run without mesh proxies" check_platform_outside_mesh
check "Demo workloads run with mesh proxies, except plaintext" check_workloads_in_mesh
check "Mesh certificates use the cell trust domain" check_trust_domain
check "client reaches echo over mesh mTLS" expect_code client http://echo/hostname 200
check "intruder is denied by AuthorizationPolicy" expect_code intruder http://echo/hostname 403
check "plaintext cannot reach echo, because mTLS is strict" expect_no_connection plaintext http://echo/hostname
check "client reaches the allowed host through the egress gateway" check_egress_through_gateway
check "client cannot reach a host that is not allowed" expect_no_connection client https://example.org/
check "plaintext cannot reach the internet, because of NetworkPolicy" expect_no_connection plaintext https://example.com/
check "client cannot reach the bundle store" expect_no_connection client "http://$BUNDLE_STORE_HOST/v2/"
check "plaintext cannot reach the bundle store" expect_no_connection plaintext "http://$BUNDLE_STORE_HOST/v2/"
check "Pod Security rejects a privileged pod in a workload namespace" check_psa_rejects_privileged
check "The collector receives telemetry for echo" check_traces_received

if has_harness cell-identity; then
  probe_targets+=("$CELL_NAME/cell-identity-system")
  spire_ip="$(node_ip "$SPIRE_SERVER_CLUSTER" 2>/dev/null || true)"
  collector_ip="$(k -n observability-system get service otel-collector -o jsonpath='{.spec.clusterIP}' 2>/dev/null || true)"
  check "The agent config and the NetworkPolicy use the current $SPIRE_SERVER_CLUSTER node address" check_spire_server_address
  check "celld holds a current X.509 SVID for spiffe://dev.env.poc.internal/cell/$CELL_NAME/celld" check_celld_svid
  check "The cell-identity objects match the bundle" check_harness_drift cell-identity
  check "cell-identity-system has exactly the objects of the bundle, with no other field manager" \
    check_harness_objects cell-identity cell-identity-system
  check "celld runs the images that build/images.env records" \
    check_live_images cell-identity-system deployment/celld "CELL=$CELL_NAME mise run cell:up"
  check "The node holds no trace of the M2 key rotation test, and the API server publishes the keys of the record" \
    check_keytest_clean
  check "A probe pod with no app label in cell-identity-system cannot open TCP to the SPIRE node port (steady state)" \
    expect_dial_blocked "$CELL_NAME" cell-identity-system "${spire_ip:-unknown}:30081"
  check "A probe pod with no app label in cell-identity-system cannot open TCP to the collector (steady state)" \
    expect_dial_blocked "$CELL_NAME" cell-identity-system "${collector_ip:-unknown}:4318"
  check "plaintext cannot reach the SPIRE node port, because of NetworkPolicy" \
    expect_no_tcp plaintext "http://${spire_ip:-unknown}:30081/"
fi
if [[ -n "${SPIRE_AGENT_CELLS:-}" ]]; then
  check "The SPIRE server holds the current node address and keys of $SPIRE_AGENT_CELLS" check_agent_cells_current
  check "The SPIRE server holds the node alias and celld entries of $SPIRE_AGENT_CELLS" check_agent_entries
  check "The SPIRE server sets the SVID lifetimes of SPIRE_SVID_TTL ($SPIRE_SVID_TTL)" check_svid_ttl
  check "The SPIRE server runs the plugin image that build/images.env records" \
    check_live_images spire-system statefulset/spire-server "CELL=$CELL_NAME mise run cell:up"
  # rogue is outside the admitted node addresses, so the server NetworkPolicy must drop it.
  probe_targets+=("rogue/default")
  own_ip="$(node_ip "$CELL_NAME" 2>/dev/null || true)"
  check "A probe pod in rogue cannot open TCP to the SPIRE node port of $CELL_NAME (steady state)" \
    expect_dial_blocked rogue default "${own_ip:-unknown}:30081"
fi

if ((failures > 0)); then
  log "$failures check(s) failed"
  exit 1
fi
log "all checks passed"
