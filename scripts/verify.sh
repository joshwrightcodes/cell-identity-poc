#!/usr/bin/env bash
# Check each base cell rule against the running cluster. Prints PASS or FAIL per check and
# exits non-zero if any check fails.
source "$(dirname "$0")/lib.sh"
source "$ROOT/components/lib/peer-root.sh"
source "$ROOT/components/lib/hostsvc-pin.sh"
source "$ROOT/components/lib/mgmt-key.sh"
source "$ROOT/scripts/verify-lib.sh"
set +e

# A cell exists only through a signed step. cell:verify of a cell with no cluster prints one line and passes, so harness:verify,
# which runs every cluster of the topology, does not fail while a cell is absent.
if grep -qx -- "$CELL_NAME" <<<"$(catalog_cells)"; then
  existing_clusters="$(kind_clusters)" || existing_clusters="unknown"
  if [[ "$existing_clusters" != unknown ]] && ! grep -qx -- "$CELL_NAME" <<<"$existing_clusters"; then
    log "skipped: cell $CELL_NAME has no cluster yet. A signed step creates it: mise run portal -- request --cell $CELL_NAME --wait"
    exit 0
  fi
fi

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
  apps_json | jq -e --argjson n "$((${#COMPONENTS[@]} + 1))" '
    (.items | length) == $n and
    all(.items[]; .status.sync.status == "Synced" and .status.health.status == "Healthy")' >/dev/null \
    || { k get applications -A; return 1; }
}

check_argocd_local_only() {
  local clusters
  clusters="$(k -n argocd get secrets -l argocd.argoproj.io/secret-type=cluster -o name)"
  [[ -z "$clusters" ]] || { echo "remote cluster secrets: $clusters"; return 1; }
  apps_json | jq -e --arg store "oci://$BUNDLE_STORE_HOST/bundles/" '
    all(.items[]; .spec.destination.server == "https://kubernetes.default.svc"
      and (.spec.source.repoURL | startswith($store)))' >/dev/null \
    || { echo "an Application has another destination or source"; return 1; }
}

# The base platform namespaces, and the namespace of each harness and link component of this cell.
platform_namespaces=(argocd cell-system observability-system)
for entry in ${HARNESS_COMPONENTS[@]+"${HARNESS_COMPONENTS[@]}"} ${LINK_COMPONENTS[@]+"${LINK_COMPONENTS[@]}"}; do
  [[ " ${platform_namespaces[*]} " == *" ${entry#*:} "* ]] || platform_namespaces+=("${entry#*:}")
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

# Every istio-proxy must hold a workload certificate with more than 1 hour left on the wall clock of the pod. The agent renews on the
# monotonic clock, which stops while the Mac sleeps, so a sidecar can serve an expired certificate. The liveness probe of the cert-liveness
# injection template restarts the container below 2 hours. This check reads only.
check_proxy_cert_life() {
  local ns pods name metrics left found=0 bad=""
  for ns in apps-demo istio-egress; do
    pods="$(k -n "$ns" get pods -o json)" || { echo "could not list the pods in $ns"; return 1; }
    while read -r name; do
      [[ -n "$name" ]] || continue
      found=$((found + 1))
      metrics="$(k -n "$ns" exec "$name" -c istio-proxy -- sh -c "curl -sf -m 3 -H 'X-Prometheus-Scrape-Timeout-Seconds: 2' localhost:15020/stats/prometheus")" \
        || { bad+="$ns/$name: could not read the metrics of istio-proxy"$'\n'; continue; }
      left="$(awk 'index($1, "istio_agent_cert_expiry_seconds{") == 1 && $1 ~ /resource_name="default"/ { print $2; exit }' <<<"$metrics")"
      if [[ -z "$left" ]]; then
        bad+="$ns/$name: no istio_agent_cert_expiry_seconds for the default certificate"$'\n'
      elif ! awk -v v="$left" 'BEGIN { exit !(v > 3600) }'; then
        bad+="$ns/$name: the certificate has ${left%.*} s left, want more than 3600"$'\n'
      fi
    done < <(jq -r '.items[] | select(.status.phase == "Running" and .metadata.deletionTimestamp == null)
      | select([(.spec.initContainers // [])[], .spec.containers[] | .name] | index("istio-proxy") != null) | .metadata.name' <<<"$pods")
  done
  ((found > 0)) || { echo "no running istio-proxy in apps-demo or istio-egress"; return 1; }
  if [[ -n "$bad" ]]; then
    printf '%s' "$bad"
    echo "The agent missed its renewal. The liveness probe of a sidecar restarts the container within about 2 minutes of VM run time."
    echo "The egress gateway has no probe. Its repair is a pod replacement, which is allowed only outside an environment island."
    return 1
  fi
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
  echo "Check the entries on the server: CELL=$SPIRE_SERVER_CLUSTER mise run cell:verify runs the check 'The SPIRE server holds the node alias and the role entry of each subject'."
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
# out. The time to the first block goes to build/<cluster>/verify-probes.log. A fourth argument "refused" makes a refused dial count
# as blocked too, for an address where nothing listens.
expect_dial_blocked() {
  local cluster="$1" ns="$2" addr="$3" also="${4:-}" image name overrides out="" dialed="" result=1 ready_at dial_start first="" i
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
      if [[ "$dialed" == timeout || ( -n "$also" && "$dialed" == "$also" ) ]]; then first=$((dial_start - ready_at)); break; fi
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
        if [[ "$dialed" != timeout && ( -z "$also" || "$dialed" != "$also" ) ]]; then
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
  [[ -f "$bundle" ]] || { echo "no $bundle. Run: $(fix_command "$1")"; return 1; }
  out="$(k diff --server-side --force-conflicts -f "$bundle" 2>&1)"
  rc=$?
  case "$rc" in
    0) return 0 ;;
    1) printf '%s\n' "$out" | head -n 40; echo "Run: $(fix_command "$1")"; return 1 ;;
    *) echo "kubectl diff failed: $out"; return 1 ;;
  esac
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

# The entries test of gate:m2 serves a signed set with an entry under /m2-test/. A run that
# stops before its cleanup leaves that set live, and Argo CD still reports Synced and Healthy.
check_no_gate_bundles() {
  local traces
  if ! traces="$(bundle_traces "$CELL_NAME")" || [[ -n "$traces" ]]; then
    printf '%s\n' "$traces"
    echo "Run: mise run gate:m2:repair"
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

# The secret store of each namespace in SECRET_STORE_NAMESPACES must be Ready, and each
# ExternalSecret that uses it must be Ready with a refresh within twice its refresh interval.
check_secret_store() {
  local ns problems=() list
  for ns in $SECRET_STORE_NAMESPACES; do
    k -n "$ns" get secretstore "$SECRET_STORE" -o json 2>/dev/null \
      | jq -e 'any(.status.conditions[]?; .type == "Ready" and .status == "True")' >/dev/null \
      || problems+=("SecretStore $ns/$SECRET_STORE is missing or not Ready")
    list="$(k -n "$ns" get externalsecrets.external-secrets.io -o json)" || { echo "could not list the ExternalSecrets in $ns"; return 1; }
    while read -r line; do
      [[ -n "$line" ]] && problems+=("$line")
    done < <(jq -r --arg ns "$ns" --arg store "$SECRET_STORE" '
      def seconds: capture("^(?<n>[0-9]+)(?<u>[smh])$") | (.n | tonumber) * ({"s": 1, "m": 60, "h": 3600}[.u]);
      .items[] | select(.spec.secretStoreRef.name == $store)
      | (.spec.refreshInterval // "1h" | seconds) as $every
      | ((.status.refreshTime // "1970-01-01T00:00:00Z") | fromdateiso8601) as $at
      | if any(.status.conditions[]?; .type == "Ready" and .status == "True") | not then
          "ExternalSecret \($ns)/\(.metadata.name) is not Ready: \([.status.conditions[]? | select(.type == "Ready") | .message] | join("; "))"
        elif now - $at > 2 * $every then
          "ExternalSecret \($ns)/\(.metadata.name) last refreshed at \(.status.refreshTime // "never"), more than twice its interval of \(.spec.refreshInterval // "1h") ago"
        else empty end' <<<"$list")
  done
  if ((${#problems[@]} > 0)); then
    printf '%s\n' "${problems[@]}"
    echo "Run: CELL=$CELL_NAME mise run secrets:connect"
    return 1
  fi
}

# The intermediate CA in Secret spire-upstream must stay valid for more than 7 days. The check reads
# only the certificate of the Secret.
check_intermediate_expiry() {
  local cert info left want got
  cert="$(k -n spire-system get secret spire-upstream -o jsonpath='{.data.intermediate-cert}' | base64 -d)" \
    || { echo "could not read the intermediate certificate from Secret spire-system/spire-upstream"; return 1; }
  info="$(cd "$ROOT" && printf '%s\n' "$cert" | mise run pki -- info 2>/dev/null)" || { echo "pkigen could not read the intermediate certificate: $info"; return 1; }
  left="$(jq -r '((.not_after | fromdateiso8601) - now) / 86400 | floor' <<<"$info")"
  if ((left <= 7)); then
    echo "the intermediate CA expires at $(jq -r .not_after <<<"$info"), in $left days."
    echo "Run: CELL=$CELL_NAME mise run pki:rotate-intermediate"
    return 1
  fi
  # The server reads the files only when it signs a CA, so its active CA can still chain to an
  # older intermediate than the Secret holds.
  want="$(jq -r .subject_key_id <<<"$info")"
  got="$(k -n spire-system exec spire-server-0 -c spire-server -- /opt/spire/bin/spire-server localauthority x509 show \
    -socketPath /run/spire/sockets/api.sock -output json | jq -r '.active.upstream_authority_subject_key_id // ""')" \
    || { echo "could not read the active X.509 authority of spire-server-0"; return 1; }
  if [[ "$got" != "$want" ]]; then
    echo "the active X.509 authority of the server has the upstream authority '$got', and Secret spire-upstream holds the intermediate $want."
    echo "Run: CELL=$CELL_NAME mise run cell:restart"
    return 1
  fi
}

# The operator must not list Secrets in every namespace, and no copy of the access token may lie
# outside the store namespaces.
check_operator_scope() {
  local can extra
  can="$(k auth can-i list secrets -A --as=system:serviceaccount:external-secrets:external-secrets 2>/dev/null)"
  [[ "$can" == no ]] || { echo "the External Secrets Operator can list Secrets in every namespace (can-i: '${can:-unknown}'). Run: CELL=$CELL_NAME mise run eso:migrate"; return 1; }
  extra="$(k get secrets -A --field-selector metadata.name=poc-secrets-token -o json \
    | jq -r --arg keep " $SECRET_STORE_NAMESPACES " '.items[] | .metadata.namespace as $ns
      | select(($keep | contains(" " + $ns + " ")) | not) | "\($ns)/\(.metadata.name)"')" || { echo "could not list the Secrets named poc-secrets-token"; return 1; }
  [[ -z "$extra" ]] || { echo "a copy of the access token lies outside $SECRET_STORE_NAMESPACES: $extra. Run: CELL=$CELL_NAME mise run eso:migrate"; return 1; }
}

# The rogue probe proves the policy only when the node port has a ready local endpoint, because the
# Service uses the local traffic policy and a port without one also times out.
check_server_endpoint() {
  k -n spire-system get endpointslices -l kubernetes.io/service-name=spire-server -o json \
    | jq -e --arg node "$CELL_NAME-control-plane" 'any(.items[].endpoints[]?; .nodeName == $node and .conditions.ready == true)' >/dev/null \
    || { echo "the spire-server Service has no ready endpoint on $CELL_NAME-control-plane. Read: mise x -- kubectl --context kind-$CELL_NAME -n spire-system describe pod spire-server-0"; return 1; }
}

# expect_rogue_blocked <ip:port> requires the ready local endpoint first, and then a blocked dial
# from rogue.
expect_rogue_blocked() {
  check_server_endpoint || return 1
  expect_dial_blocked rogue default "$1"
}

# expect_rogue_closed <ip:port> is the case of no live cell: Service spire-server has no node port, and a dial from rogue gets no connection.
expect_rogue_closed() {
  check_spire_node_port_closed || return 1
  expect_dial_blocked rogue default "$1" refused
}

# The SPIRE server must hold, for each agent cell of the catalog (SPIRE_AGENT_CELLS, live or not) and each subject of SPIRE_CELL_SUBJECTS, the node
# alias cell/<cell>/agents/<role> and the role entry under it, with the parents and selectors that
# the render declares.
check_agent_entries() {
  local entries cell subject sa role missing=()
  entries="$(k -n spire-system exec spire-server-0 -c spire-server -- \
    /opt/spire/bin/spire-server entry show -socketPath /run/spire/sockets/api.sock -output json)" \
    || { echo "could not read the entries from spire-server-0"; return 1; }
  for cell in $SPIRE_AGENT_CELLS; do
    for subject in $SPIRE_CELL_SUBJECTS; do
      sa="${subject%%=*}"
      sa="${sa/\//:}"
      role="${subject#*=}"
      jq -e --arg cell "$cell" --arg sa "$sa" --arg role "$role" 'any(.entries[]; .spiffe_id.path == "/cell/\($cell)/agents/\($role)"
        and .parent_id.path == "/spire/server"
        and ([.selectors[] | "\(.type):\(.value)"] | sort) == (["cluster_jwt:cell:\($cell)", "cluster_jwt:sa:\($sa)"] | sort))' \
        <<<"$entries" >/dev/null || missing+=("no node alias entry spiffe://$SPIRE_TRUST_DOMAIN/cell/$cell/agents/$role with the selectors of $cell and $sa")
      jq -e --arg cell "$cell" --arg role "$role" 'any(.entries[]; .spiffe_id.path == "/cell/\($cell)/\($role)"
        and .parent_id.path == "/cell/\($cell)/agents/\($role)"
        and [.selectors[] | "\(.type):\(.value)"] == ["unix:uid:65532"])' \
        <<<"$entries" >/dev/null || missing+=("no $role entry spiffe://$SPIRE_TRUST_DOMAIN/cell/$cell/$role under its alias with selector unix:uid:65532")
    done
  done
  if ((${#missing[@]} > 0)); then
    printf '%s\n' "${missing[@]}"
    echo "Run: CELL=$CELL_NAME mise run cell:up"
    return 1
  fi
}

# The SPIRE server must be Ready at its current revision, and healthy on its admin socket.
check_server_healthy() {
  local out
  k -n spire-system get statefulset spire-server -o json | jq -e '(.spec.replicas // 1) as $want
    | (.status.readyReplicas // 0) == $want and (.status.updatedReplicas // 0) == $want
      and .status.currentRevision == .status.updateRevision' >/dev/null \
    || { echo "statefulset/spire-server in spire-system is not Ready at its current revision. Read: mise x -- kubectl --context kind-$CELL_NAME -n spire-system describe pod spire-server-0"; return 1; }
  out="$(k -n spire-system exec spire-server-0 -c spire-server -- /opt/spire/bin/spire-server healthcheck -socketPath /run/spire/sockets/api.sock 2>&1)"
  [[ "$out" == "Server is healthy." ]] || { echo "spire-server healthcheck: ${out:-no output}"; return 1; }
}

# The SPIRE server must hold the node alias and the entry of each local workload in
# SPIRE_LOCAL_WORKLOADS, with the parents and selectors that the render declares.
check_local_entries() {
  local entries w path sub ns sa missing=()
  entries="$(k -n spire-system exec spire-server-0 -c spire-server -- \
    /opt/spire/bin/spire-server entry show -socketPath /run/spire/sockets/api.sock -output json)" \
    || { echo "could not read the entries from spire-server-0"; return 1; }
  for w in $SPIRE_LOCAL_WORKLOADS; do
    path="${w%%=*}" sub="${w#*=}"
    ns="${sub%%/*}" sa="${sub#*/}"
    jq -e --arg td "$SPIRE_TRUST_DOMAIN" --arg ns "$ns" --arg sa "$sa" --arg cluster "$CELL_NAME" 'any(.entries[];
      .spiffe_id.trust_domain == $td and .spiffe_id.path == "/agents/\($ns)/\($sa)" and .parent_id.path == "/spire/server"
      and ([.selectors[] | "\(.type):\(.value)"] | sort)
        == (["k8s_psat:cluster:\($cluster)", "k8s_psat:agent_ns:\($ns)", "k8s_psat:agent_sa:\($sa)"] | sort))' \
      <<<"$entries" >/dev/null || missing+=("no node alias entry spiffe://$SPIRE_TRUST_DOMAIN/agents/$ns/$sa with the k8s_psat selectors of $CELL_NAME")
    jq -e --arg td "$SPIRE_TRUST_DOMAIN" --arg path "/$path" --arg parent "/agents/$ns/$sa" 'any(.entries[];
      .spiffe_id.trust_domain == $td and .spiffe_id.path == $path and .parent_id.path == $parent
      and [.selectors[] | "\(.type):\(.value)"] == ["unix:uid:65532"])' \
      <<<"$entries" >/dev/null || missing+=("no entry spiffe://$SPIRE_TRUST_DOMAIN/$path under the alias of $sub with selector unix:uid:65532")
  done
  if ((${#missing[@]} > 0)); then
    printf '%s\n' "${missing[@]}"
    echo "Run: CELL=$CELL_NAME mise run cell:up"
    return 1
  fi
}

# The SPIRE server trusts only its own trust domain, so it holds no federated bundle.
check_no_federation() {
  local out
  out="$(k -n spire-system exec spire-server-0 -c spire-server -- \
    /opt/spire/bin/spire-server bundle list -socketPath /run/spire/sockets/api.sock -output json)" \
    || { echo "could not list the federated bundles of spire-server-0"; return 1; }
  jq -e '(.bundles // []) | length == 0' <<<"$out" >/dev/null || { echo "the server holds federated bundles: $(jq -c '[.bundles[].trust_domain]' <<<"$out")"; return 1; }
}

# A server with no upstream authority keeps its CA key in keys.json on its data volume, so a restart
# keeps the root. SPIRE prepares the next CA, a new self-signed root, at notAfter minus
# min(lifetime / 2, 30 days) (pkg/server/ca/manager/slot.go of v1.15.5). Every peer copy must hold
# that root before SPIRE activates it, so the check fails 7 days before that time.
check_ca_key_persists() {
  local conf pv path node state expires lifetime threshold left
  conf="$(k -n spire-system get configmap spire-server -o jsonpath='{.data.server\.conf}')" || { echo "could not read ConfigMap spire-server"; return 1; }
  grep -q '^ *KeyManager "disk" {$' <<<"$conf" || { echo "the server keeps its CA key in memory, so a restart makes a new root. Run: CELL=$CELL_NAME mise run cell:up"; return 1; }
  pv="$(k -n spire-system get pvc data-spire-server-0 -o jsonpath='{.spec.volumeName}')" || { echo "no PersistentVolumeClaim data-spire-server-0"; return 1; }
  path="$(k get pv "$pv" -o json | jq -r '.spec.hostPath.path // .spec.local.path // ""')"
  node="$CELL_NAME-control-plane"
  [[ -n "$path" ]] && docker exec "$node" test -s "$path/keys.json" \
    || { echo "the data volume $pv holds no keys.json at '$path' on $node"; return 1; }
  state="$(k -n spire-system exec spire-server-0 -c spire-server -- /opt/spire/bin/spire-server localauthority x509 show \
    -socketPath /run/spire/sockets/api.sock -output json)" || { echo "could not read the X.509 authorities of spire-server-0"; return 1; }
  expires="$(jq -r '.active.expires_at // 0 | tonumber' <<<"$state")"
  lifetime="$(seconds_of "${SPIRE_CA_TTL:-24h}")"
  threshold=$((expires - (lifetime / 2 < 2592000 ? lifetime / 2 : 2592000)))
  left=$(((threshold - $(date +%s)) / 86400))
  if ((expires == 0 || left < 7)); then
    echo "SPIRE prepares a new root in $left days, at $(jq -rn --argjson t "$threshold" '$t | todate'), and activates it later. Run: CELL=$CELL_NAME mise run mgmt:rotate-ca"
    return 1
  fi
}

# seconds_of <duration> prints a duration of the form <n>s, <n>m or <n>h in seconds.
seconds_of() {
  local n="${1%[smh]}"
  case "$1" in
    *s) echo "$n" ;;
    *m) echo $((n * 60)) ;;
    *h) echo $((n * 3600)) ;;
  esac
}

# The server ServiceAccount can review tokens and read pods and nodes. No Secret may hold a token
# that does not expire for an account in spire-system.
check_no_token_secrets() {
  local out
  out="$(k -n spire-system get secrets --field-selector type=kubernetes.io/service-account-token -o name)" \
    || { echo "could not list the Secrets in spire-system"; return 1; }
  [[ -z "$out" ]] || { echo "spire-system holds ServiceAccount token Secrets: ${out//$'\n'/ }. Delete them."; return 1; }
}

# A cluster with the operator but no secret store holds no store of either kind, no copy of the
# store token, and an operator that cannot list Secrets in every namespace.
check_no_secret_store() {
  local out problems=()
  out="$(k get secretstores.external-secrets.io -A -o name)" || { echo "could not list the SecretStores"; return 1; }
  [[ -z "$out" ]] || problems+=("SecretStores: ${out//$'\n'/ }")
  if out="$(k get clustersecretstores.external-secrets.io -o name 2>&1)"; then
    [[ -z "$out" ]] || problems+=("ClusterSecretStores: ${out//$'\n'/ }")
  elif [[ "$out" != *"the server doesn't have a resource type"* ]]; then
    echo "could not list the ClusterSecretStores: $out"
    return 1
  fi
  out="$(k get secrets -A --field-selector metadata.name=poc-secrets-token -o name)" || { echo "could not list the Secrets named poc-secrets-token"; return 1; }
  [[ -z "$out" ]] || problems+=("copies of the store token: ${out//$'\n'/ }")
  out="$(k auth can-i list secrets -A --as=system:serviceaccount:external-secrets:external-secrets 2>/dev/null)"
  [[ "$out" == no ]] || problems+=("the operator can list Secrets in every namespace (can-i: '${out:-unknown}')")
  # The positive control shows that the account name is right, so the "no" above is not a typo.
  out="$(k auth can-i get secrets -n "$EXTERNAL_SECRETS_NAMESPACE" --as=system:serviceaccount:external-secrets:external-secrets 2>/dev/null)"
  [[ "$out" == yes ]] || problems+=("the operator cannot read Secrets in $EXTERNAL_SECRETS_NAMESPACE (can-i: '${out:-unknown}'), so the account name of the check is wrong")
  if ((${#problems[@]} > 0)); then
    printf '%s\n' "${problems[@]}"
    echo "$CELL_NAME has no secret store. Delete each object above, then run: CELL=$CELL_NAME mise run cell:up"
    return 1
  fi
}

# check_traces_in_store asks Tempo through Grafana in management for a trace of echo with the cluster
# name of this cluster. No collector prints what it receives, so the logs of the collector show no
# span. The signals of every cluster but management reach Grafana through the collector, the uplink,
# the relay and the gateway, so this check fails while any of them is down. The password stays in
# memory, and lgtm_curl puts it on the standard input of curl.
check_traces_in_store() {
  local LGTM_CLUSTER=management
  local pw query body out code end=$((SECONDS + 240)) i name="${COLLECTOR_CLUSTER:-$CELL_NAME}"
  pw="$(CELL=management "$ROOT/scripts/obs-password.sh")" || { echo "could not read the Grafana admin password: $pw"; return 1; }
  query="{ resource.k8s.cluster.name = \"$name\" && resource.service.name =~ \"echo.*\" }"
  body="$(jq -nc --arg q "$query" '{queries: [{refId: "A", datasource: {type: "tempo", uid: "tempo"}, queryType: "traceql", query: $q,
    limit: 5, tableType: "traces"}], from: "now-30m", to: "now"}')"
  grafana_login_ok || return 1
  until out="$(lgtm_curl "admin:$pw" POST /api/ds/query "$body" 2>&1)" && code="$(tail -n 1 <<<"$out")" && [[ "$code" == 200 ]] \
      && [[ "$(sed '$d' <<<"$out" | jq -r '[.results.A.frames[]?.data.values[0][]?] | length' 2>/dev/null)" -gt 0 ]]; do
    for i in 1 2 3; do expect_code client http://echo/hostname 200 >/dev/null; done
    ((SECONDS < end)) || {
      echo "Tempo in management holds no trace of echo.apps-demo with k8s.cluster.name $name. The last answer: HTTP ${code:-none}."
      echo "The collector, the uplink, the relay or the gateway can be down. Read each hop: mise run obs:uplink-status $name"
      return 1
    }
    sleep 5
  done
}

# lgtm must run as user 10001, Grafana must refuse an anonymous read of the data sources, and the pod
# must not read the Kubernetes API token that the account would give it.
check_lgtm_hardened() {
  local uid code
  uid="$(k -n observability-system exec lgtm-0 -c lgtm -- id -u 2>&1)" || { echo "could not run id in lgtm-0: $uid"; return 1; }
  [[ "$uid" == 10001 ]] || { echo "lgtm-0 runs as user '$uid', want 10001"; return 1; }
  code="$(k -n observability-system exec lgtm-0 -c lgtm -- curl -sS -o /dev/null -w '%{http_code}' --max-time 10 http://127.0.0.1:3000/api/datasources 2>&1)" \
    || { echo "could not call Grafana in lgtm-0: $code"; return 1; }
  [[ "$code" == 401 ]] || { echo "an anonymous read of /api/datasources answers HTTP '$code', want 401. Run: CELL=$CELL_NAME mise run cell:up"; return 1; }
  code="$(k -n observability-system exec lgtm-0 -c lgtm -- curl -sS -o /dev/null -w '%{http_code}' --max-time 10 -u admin:admin http://127.0.0.1:3000/api/user 2>&1)" \
    || { echo "could not call Grafana in lgtm-0: $code"; return 1; }
  [[ "$code" == 401 ]] || { echo "the default login admin:admin answers HTTP '$code', want 401, so Grafana did not read the generated password"; return 1; }
  k -n observability-system exec lgtm-0 -c lgtm -- test ! -e /var/run/secrets/kubernetes.io/serviceaccount/token \
    || { echo "lgtm-0 holds a service account token"; return 1; }
}

# grafana_login_ok prints nothing and succeeds when Grafana accepts the password of Secret grafana-admin.
# Otherwise it names the fix, so a 401 does not look like a failure of the store.
grafana_login_ok() {
  local pw out code fix lgtm="${LGTM_CLUSTER:-$CELL_NAME}"
  fix="CELL=$lgtm mise run obs:rotate-password, or, when it fails, the restore command that it prints (CELL=$lgtm scripts/obs-rotate-password.sh --restore-command)"
  pw="$(CELL="$lgtm" "$ROOT/scripts/obs-password.sh")" || { echo "could not read the Grafana admin password: $pw"; return 1; }
  out="$(lgtm_curl "admin:$pw" GET /api/user 2>&1)" || { echo "could not call Grafana in lgtm-0: $out"; return 1; }
  code="$(tail -n 1 <<<"$out")"
  [[ "$code" == 200 ]] && return 0
  if [[ "$code" == 401 ]]; then
    echo "Grafana refuses the password of Secret grafana-admin (HTTP 401), so the Secret and the Grafana database differ, or Grafana blocks the user for 5 minutes after 5 failed logins (wait, then run again). Fix for a difference: $fix"
  else
    echo "GET /api/user in Grafana answers HTTP '$code'"
  fi
  return 1
}

# The four data sources of the image must pass their health check.
check_grafana_datasources() {
  local pw uid out code
  grafana_login_ok || return 1
  pw="$("$ROOT/scripts/obs-password.sh")"
  for uid in prometheus loki tempo pyroscope; do
    out="$(lgtm_curl "admin:$pw" GET "/api/datasources/uid/$uid/health" 2>&1)" || { echo "could not call Grafana: $out"; return 1; }
    code="$(tail -n 1 <<<"$out")"
    [[ "$code" == 200 && "$(sed '$d' <<<"$out" | jq -r .status 2>/dev/null)" == OK ]] || { echo "data source $uid: HTTP $code: $(sed '$d' <<<"$out" | head -c 200)"; return 1; }
  done
}

# The gateway counts each failed forward to the store. Nothing may have failed in the last 5 minutes. A
# store that the gateway cannot reach, or a policy that drifted on flow N10, shows here first.
check_gateway_store_path() {
  local pw out code n
  grafana_login_ok || return 1
  pw="$("$ROOT/scripts/obs-password.sh")"
  out="$(lgtm_curl "admin:$pw" GET '/api/datasources/proxy/uid/prometheus/api/v1/query?query=sum(increase(cellproxy_gateway_upstream_failures_total%7Bk8s_cluster_name%3D%22management%22%7D%5B5m%5D))' 2>&1)" \
    || { echo "could not query Prometheus: $out"; return 1; }
  code="$(tail -n 1 <<<"$out")"
  [[ "$code" == 200 ]] || { echo "the Prometheus query answers HTTP '$code'"; return 1; }
  n="$(sed '$d' <<<"$out" | jq -r '.data.result[0].value[1] // "0"')"
  awk -v n="$n" 'BEGIN { exit !(n + 0 < 0.5) }' || { echo "the gateway failed $n forwards to the store in the last 5 minutes. Read: kubectl --context kind-$CELL_NAME -n observability-system logs deploy/telemetry-gateway -c cell-proxy"; return 1; }
}

# The data volume has no size limit of its own: local-path ignores the 10Gi request, and the files lie on the
# disk of the VM. Retention keeps each component at 48 hours, so 8 GiB means that a bound failed.
LGTM_DISK_LIMIT_KB=$((8 * 1024 * 1024))
check_lgtm_disk() {
  local kb
  kb="$(k -n observability-system exec lgtm-0 -c lgtm -- du -sk /data 2>/dev/null | awk '{print $1}')" || { echo "could not run du in lgtm-0"; return 1; }
  [[ "$kb" =~ ^[0-9]+$ ]] || { echo "du in lgtm-0 printed '$kb'"; return 1; }
  ((kb < LGTM_DISK_LIMIT_KB)) || { echo "/data of lgtm-0 holds $((kb / 1024)) MiB, over the limit of $((LGTM_DISK_LIMIT_KB / 1024)) MiB. Check the retention settings in components/observability-store"; return 1; }
}

check_grafana_secret_synced() {
  k -n observability-system get externalsecret grafana-admin -o json | jq -e 'any(.status.conditions[]?; .type == "Ready" and .status == "True")' >/dev/null \
    || { echo "ExternalSecret grafana-admin is not Ready. Run: CELL=$CELL_NAME mise run cell:up"; return 1; }
}

check_traces_received() {
  check_traces_in_store
}

# The collector is a StatefulSet with one Ready replica and its queue volume. A Deployment of the same
# name is a leftover of an older bundle: Argo CD prunes it, and a collector from it would run beside
# the new one with the old config.
check_collector_workload() {
  local sts pvc phase size
  sts="$(k -n observability-system get statefulset otel-collector -o json 2>&1)" || { echo "no StatefulSet otel-collector in observability-system: $sts. Run: CELL=$CELL_NAME mise run cell:up"; return 1; }
  jq -e '.spec.replicas == 1 and .status.readyReplicas == 1 and .status.updatedReplicas == 1' >/dev/null <<<"$sts" \
    || { echo "StatefulSet otel-collector has $(jq -r '[.spec.replicas, .status.readyReplicas // 0, .status.updatedReplicas // 0] | "replicas \(.[0]), ready \(.[1]), updated \(.[2])"' <<<"$sts"), want one Ready replica at its update revision"; return 1; }
  if k -n observability-system get deployment otel-collector >/dev/null 2>&1; then
    echo "Deployment otel-collector still exists, an object of the old bundle. Wait for Argo CD to prune it, or run: kubectl --context kind-$CELL_NAME -n observability-system delete deployment otel-collector"
    return 1
  fi
  pvc="$(k -n observability-system get pvc queue-otel-collector-0 -o json 2>&1)" || { echo "no PVC queue-otel-collector-0: $pvc"; return 1; }
  phase="$(jq -r .status.phase <<<"$pvc")" size="$(jq -r '.status.capacity.storage // ""' <<<"$pvc")"
  want_size="$(yq -N 'select(.kind == "StatefulSet" and .metadata.name == "otel-collector") | .spec.volumeClaimTemplates[0].spec.resources.requests.storage' "$BUNDLES/observability-system/manifests.yaml")"
  [[ -n "$want_size" && "$want_size" != null ]] || { echo "the bundle observability-system holds no claim template of otel-collector. Run: CELL=$CELL_NAME mise run cell:hydrate"; return 1; }
  [[ "$phase" == Bound && "$size" == "$want_size" ]] || { echo "PVC queue-otel-collector-0 is $phase with capacity '$size', and the bundle asks for $want_size"; return 1; }
}

# The uplink copies the node address of its upstream cluster into the cell-proxy argument and its
# NetworkPolicy. A cell dials the relay of SPIRE_SERVER_CLUSTER on 30444, and dev-cp dials the gateway
# of RELAY_TARGET on the target port of RELAY_TELEMETRY_ROUTES. Docker can give a rebuilt node a new address.
uplink_upstream() {
  case "$COLLECTOR_PLANE" in
    cell) echo "$SPIRE_SERVER_CLUSTER 30444 mgmt-root" ;;
    environment) echo "$RELAY_TARGET ${RELAY_TELEMETRY_ROUTES##*=} peer-root" ;;
    *) return 1 ;;
  esac
}

check_uplink_env_address() {
  local cluster port cm want got
  read -r cluster port cm <<<"$(uplink_upstream)" || { echo "COLLECTOR_PLANE '$COLLECTOR_PLANE' has no uplink"; return 1; }
  want="$(node_ip "$cluster")" || { echo "$want"; return 1; }
  got="$(k -n observability-system get deployment otel-uplink -o json \
    | jq -r '[.spec.template.spec.containers[] | select(.name == "cell-proxy") | .args[] | select(startswith("--upstream="))] | join(" ")')" \
    || { echo "could not read deployment/otel-uplink"; return 1; }
  if [[ "$got" != "--upstream=$want:$port" ]]; then
    echo "the $cluster node is $want, but the uplink has '$got', want --upstream=$want:$port."
    echo "Run: CELL=$CELL_NAME mise run cell:up"
    return 1
  fi
  got="$(k -n observability-system get networkpolicy otel-uplink -o json \
    | jq -r '[.spec.egress[].to[]?.ipBlock.cidr // empty] | join(" ")')" || { echo "could not read the NetworkPolicy otel-uplink"; return 1; }
  [[ " $got " == *" $want/32 "* ]] || { echo "the NetworkPolicy otel-uplink admits egress to '$got', want $want/32. Run: CELL=$CELL_NAME mise run cell:up"; return 1; }
}

check_uplink_peer_root() {
  local cluster port cm live got
  read -r cluster port cm <<<"$(uplink_upstream)" || { echo "COLLECTOR_PLANE '$COLLECTOR_PLANE' has no uplink"; return 1; }
  live="$(kubectl --context kind-management -n spire-system exec spire-server-0 -c spire-server -- \
    /opt/spire/bin/spire-server bundle show -socketPath /run/spire/sockets/api.sock -format pem 2>/dev/null | pem_lines)" \
    || { echo "could not read the trust bundle of management"; return 1; }
  got="$(k -n observability-system get configmap "$cm" -o jsonpath='{.data.root\.crt}' | pem_lines)"
  if [[ -z "$live" || "$got" != "$live" ]]; then
    echo "ConfigMap observability-system/$cm holds other roots than the live bundle of management."
    echo "Run: CELL=$CELL_NAME mise run cell:up"
    return 1
  fi
  peer_root_pods_current observability-system otel-uplink "$cm" "CELL=$CELL_NAME mise run cell:up" || return 1
}

# The mesh-view tunnel of a cell copies the node address of SPIRE_SERVER_CLUSTER into its
# cell-proxy argument and its NetworkPolicy, and the roots of management into ConfigMap mgmt-root.
check_mesh_view_env_address() {
  local want got
  want="$(node_ip "$SPIRE_SERVER_CLUSTER")" || { echo "$want"; return 1; }
  got="$(k -n mesh-view-system get deployment mesh-view -o json \
    | jq -r '[.spec.template.spec.containers[] | select(.name == "cell-proxy") | .args[] | select(startswith("--upstream="))] | join(" ")')" \
    || { echo "could not read deployment/mesh-view"; return 1; }
  if [[ "$got" != "--upstream=$want:30445" ]]; then
    echo "the $SPIRE_SERVER_CLUSTER node is $want, but the tunnel has '$got', want --upstream=$want:30445."
    echo "Run: CELL=$CELL_NAME mise run cell:up"
    return 1
  fi
  got="$(k -n mesh-view-system get networkpolicy mesh-view -o json \
    | jq -r '[.spec.egress[].to[]?.ipBlock.cidr // empty] | join(" ")')" || { echo "could not read the NetworkPolicy mesh-view"; return 1; }
  [[ " $got " == *" $want/32 "* ]] || { echo "the NetworkPolicy mesh-view admits egress to '$got', want $want/32. Run: CELL=$CELL_NAME mise run cell:up"; return 1; }
}

check_mesh_view_peer_root() {
  local live got
  live="$(kubectl --context kind-management -n spire-system exec spire-server-0 -c spire-server -- \
    /opt/spire/bin/spire-server bundle show -socketPath /run/spire/sockets/api.sock -format pem 2>/dev/null | pem_lines)" \
    || { echo "could not read the trust bundle of management"; return 1; }
  got="$(k -n mesh-view-system get configmap mgmt-root -o jsonpath='{.data.root\.crt}' | pem_lines)"
  if [[ -z "$live" || "$got" != "$live" ]]; then
    echo "ConfigMap mesh-view-system/mgmt-root holds other roots than the live bundle of management."
    echo "Run: CELL=$CELL_NAME mise run cell:up"
    return 1
  fi
  peer_root_pods_current mesh-view-system mesh-view mgmt-root "CELL=$CELL_NAME mise run cell:up" || return 1
}

# A gate test drops the packets between the relay and the hub with firewall rules on the dev-cp node. A run
# that stopped hard can leave them, and they cut the mesh tunnel of every cell.
check_no_blackhole() {
  local found
  found="$(blackhole_present "$CELL_NAME-control-plane")" || { echo "the node of $CELL_NAME does not answer"; return 1; }
  [[ -z "$found" ]] || { echo "the node of $CELL_NAME holds the firewall rules: ${found//-D /}"; echo "Run: mise run gate:m3:repair"; return 1; }
}

# The partition tool cuts the traffic between two nodes with firewall rules in both address families. A run that stopped
# early can leave them, and they cut a cell from its control plane, or an environment from management.
check_no_partition() {
  local found
  found="$(partition_rules "$CELL_NAME-control-plane")" || { echo "the node of $CELL_NAME does not answer"; return 1; }
  [[ -z "$found" ]] || { echo "the node of $CELL_NAME holds the cut rules: ${found//$'\n'/; }"; echo "Run: mise run partition -- heal --all"; return 1; }
}

log "checking cell $CELL_NAME"
k get --raw /readyz >/dev/null 2>&1 || die "cannot reach the API server of $CELL_NAME"
check "Argo CD reports every Application Synced and Healthy" check_apps_synced
check "No Application is outside argocd, except the mirrors of the central view" check_apps_namespace
check "AppProject default in argocd allows nothing, and the projects of the role are the only others" check_argocd_projects
check "argocd holds no admin password" check_no_admin_credentials
check "argocd holds only the allowed Secrets, and the agent can list them but not get or change them" check_argocd_secrets
check "Argo CD has no remote clusters and reads only the local store" check_argocd_local_only
check "$(IFS=,; echo "${platform_namespaces[*]}" | sed 's/,/, /g') run without mesh proxies" check_platform_outside_mesh
check "Demo workloads run with mesh proxies, except plaintext" check_workloads_in_mesh
check "Mesh certificates use the cell trust domain" check_trust_domain
check "Every istio-proxy certificate has more than 1 hour left" check_proxy_cert_life
check "client reaches echo over mesh mTLS" expect_code client http://echo/hostname 200
check "intruder is denied by AuthorizationPolicy" expect_code intruder http://echo/hostname 403
check "plaintext cannot reach echo, because mTLS is strict" expect_no_connection plaintext http://echo/hostname
check "client reaches the allowed host through the egress gateway" check_egress_through_gateway
check "client cannot reach a host that is not allowed" expect_no_connection client https://example.org/
check "plaintext cannot reach the internet, because of NetworkPolicy" expect_no_connection plaintext https://example.com/
check "client cannot reach the bundle store" expect_no_connection client "http://$BUNDLE_STORE_SERVICE/v2/"
check "plaintext cannot reach the bundle store" expect_no_connection plaintext "http://$BUNDLE_STORE_SERVICE/v2/"
check "Pod Security rejects a privileged pod in a workload namespace" check_psa_rejects_privileged
if [[ -n "${COLLECTOR_STORE:-}" ]]; then
  check "lgtm runs as user 10001, and Grafana answers 401 to an anonymous read" check_lgtm_hardened
  check "ExternalSecret grafana-admin is Ready" check_grafana_secret_synced
  check "No Secret in observability-system carries the annotation last-applied-configuration" check_no_last_applied_secret
  check "Grafana accepts the password of Secret grafana-admin, and its four data sources are healthy" check_grafana_datasources
  check "The gateway forwarded to the store with no failure in the last 5 minutes" check_gateway_store_path
  check "/data of lgtm-0 holds less than 8 GiB" check_lgtm_disk
fi
check "The collector is a StatefulSet with a Ready replica and the queue volume of the bundle, and no Deployment of the old bundle remains" check_collector_workload
check "Tempo in management holds a trace of echo from ${COLLECTOR_CLUSTER:-$CELL_NAME}, so its collector and uplink reach the store" check_traces_received

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
  check "cell-ops-system has exactly the objects of the bundle, besides the records that celld wrote" \
    check_harness_objects cell-identity cell-ops-system
  check "celld pins the live signing key of mgmtd, or the staged key during a rotation" check_op_key_pinned
  check "The node holds no trace of the M2 key rotation test, and the API server publishes the keys of the record" \
    check_keytest_clean
  check "A probe pod with no app label in cell-identity-system cannot open TCP to the SPIRE node port (steady state)" \
    expect_dial_blocked "$CELL_NAME" cell-identity-system "${spire_ip:-unknown}:30081"
  check "A probe pod with no app label in cell-identity-system cannot open TCP to the collector (steady state)" \
    expect_dial_blocked "$CELL_NAME" cell-identity-system "${collector_ip:-unknown}:4318"
  check "plaintext cannot reach the SPIRE node port, because of NetworkPolicy" \
    expect_no_tcp plaintext "http://${spire_ip:-unknown}:30081/"
  for port in 30450 30451; do
    check "A probe pod with no app label in cell-identity-system cannot open TCP to the gateway node port $port (steady state)" \
      expect_dial_blocked "$CELL_NAME" cell-identity-system "${spire_ip:-unknown}:$port"
  done
fi
# The agent copies the node address of SPIRE_SERVER_CLUSTER into the cell-proxy upstream and the
# NetworkPolicy. A rebuilt control plane can get a new address.
check_agent_env_address() {
  local want args cidrs
  want="$(node_ip "$SPIRE_SERVER_CLUSTER")" || { echo "$want"; return 1; }
  args="$(k -n argocd get deployment argocd-agent -o json | jq -r '.spec.template.spec.containers[] | select(.name == "cell-proxy") | .args[]')" \
    || { echo "could not read deployment/argocd-agent in argocd"; return 1; }
  cidrs="$(k -n argocd get networkpolicy argocd-agent -o json \
    | jq -r '[.spec.egress[] | select(any(.ports[]; .port == 30443)) | .to[].ipBlock.cidr] | join(" ")')"
  if ! grep -qxF -- "--upstream=$want:30443" <<<"$args" || [[ "$cidrs" != "$want/32" ]]; then
    echo "the $SPIRE_SERVER_CLUSTER node is $want, but cell-proxy dials '$(grep -- '--upstream=' <<<"$args")' and the NetworkPolicy allows '$cidrs'."
    echo "Run: CELL=$CELL_NAME mise run cell:up"
    return 1
  fi
}

# ConfigMap mgmt-root must hold the live roots of the management plane, or cell-proxy refuses the
# principal after a new management root.
check_agent_mgmt_root() {
  local live got
  live="$(kubectl --context kind-management -n spire-system exec spire-server-0 -c spire-server -- \
    /opt/spire/bin/spire-server bundle show -socketPath /run/spire/sockets/api.sock -format pem 2>/dev/null | pem_lines)" \
    || { echo "could not read the trust bundle of management"; return 1; }
  got="$(k -n argocd get configmap mgmt-root -o jsonpath='{.data.root\.crt}' | pem_lines)"
  if [[ -z "$live" || "$got" != "$live" ]]; then
    echo "ConfigMap argocd/mgmt-root holds other roots than the live bundle of management."
    echo "Run: CELL=$CELL_NAME mise run cell:up"
    return 1
  fi
  peer_root_pods_current argocd argocd-agent mgmt-root "CELL=$CELL_NAME mise run cell:up" || return 1
}

# The agent answers 200 on /healthz only while its stream to the principal is up.
check_agent_connected() {
  local code
  code="$(k -n argocd exec deploy/argocd-agent -c argocd-agent -- wget -q -S -O /dev/null http://127.0.0.1:8002/healthz 2>&1 | sed -n 's/^ *HTTP\/[0-9.]* \([0-9]*\).*/\1/p' | tail -n 1)"
  [[ "$code" == 200 ]] && return 0
  echo "the agent answers HTTP '${code:-none}' on /healthz, so it holds no stream to the principal."
  echo "Read the cell-proxy log: mise x -- kubectl --context kind-$CELL_NAME -n argocd logs deploy/argocd-agent -c cell-proxy"
  echo "A pod that cannot attest: read the SPIRE sidecar log, and look for the guard: mise x -- kubectl --context kind-$CELL_NAME -n argocd logs deploy/argocd-agent -c spire-agent | grep argocd-agent-read-only"
  echo "If management has no principal yet, run: CELL=management mise run cell:link"
  echo "If the relay holds old node addresses, run: CELL=$SPIRE_SERVER_CLUSTER mise run cell:verify, and then the command that it prints"
  return 1
}

# A pod that runs as the ServiceAccount of a cell subject can attest as that subject. In a namespace
# that a harness component shares with a bundle, such a pod must belong to the harness component,
# as check_plane_pods requires in a plane. In a namespace that the component owns,
# check_harness_objects already compares every workload with the bundle. The subjects come from
# SPIRE_CELL_SUBJECTS of SPIRE_SERVER_CLUSTER.
check_cell_subject_pods() {
  local subjects s ns entry comp accounts=""
  subjects="$(set -a; source "$ROOT/cells/$SPIRE_SERVER_CLUSTER.env"; echo "$SPIRE_CELL_SUBJECTS")"
  [[ -n "$subjects" ]] || { echo "cells/$SPIRE_SERVER_CLUSTER.env names no SPIRE_CELL_SUBJECTS"; return 1; }
  for s in $subjects; do
    ns="${s%%/*}"
    for entry in ${HARNESS_COMPONENTS[@]+"${HARNESS_COMPONENTS[@]}"}; do
      comp="${entry%%:*}"
      [[ "${entry#*:}" == "$ns" ]] || continue
      NS="$ns" yq -e 'select(.kind == "Namespace" and .metadata.name == strenv(NS))' "$BUNDLES/$comp/manifests.yaml" >/dev/null 2>&1 \
        || accounts+="${s#*=}=${s%%=*} "
    done
  done
  [[ -n "$accounts" ]] || return 0
  SPIRE_LOCAL_WORKLOADS="$accounts" check_plane_pods
}

if [[ -n "${SPIRE_SERVER_CLUSTER:-}" ]]; then
  check "Every pod that runs as a ServiceAccount of SPIRE_CELL_SUBJECTS in a shared namespace belongs to its harness component" check_cell_subject_pods
fi

if has_harness otel-uplink; then
  check "The otel-uplink objects match the bundle" check_harness_drift otel-uplink
  check "observability-system has exactly the otel-uplink objects of the bundle, with no other field manager" check_harness_objects otel-uplink observability-system
  check "The uplink runs the images that build/images.env records" \
    check_live_images observability-system deployment/otel-uplink "CELL=$CELL_NAME mise run cell:up"
  check "The uplink and its NetworkPolicy use the current node address of its upstream cluster" check_uplink_env_address
  check "The peer root ConfigMap of the uplink holds the live roots of management" check_uplink_peer_root
fi

if [[ -n "${RELAY_TARGET:-}" ]]; then
  check "The node of $CELL_NAME holds no firewall rule of a gate test between the relay and the hub" check_no_blackhole
fi

check "The node of $CELL_NAME holds no cut rule of the partition tool, in iptables or ip6tables" check_no_partition

if has_harness mesh-view; then
  check "The mesh-view objects match the bundle" check_harness_drift mesh-view
  check "mesh-view-system has exactly the mesh-view objects of the bundle, with no other field manager" check_harness_objects mesh-view mesh-view-system
  check "The mesh-view tunnel runs the images that build/images.env records" \
    check_live_images mesh-view-system deployment/mesh-view "CELL=$CELL_NAME mise run cell:up"
  check "The mesh-view tunnel and its NetworkPolicy use the current node address of $SPIRE_SERVER_CLUSTER" check_mesh_view_env_address
  check "The peer root ConfigMap of the mesh-view tunnel holds the live roots of management" check_mesh_view_peer_root
fi

if has_harness argocd-agent; then
  agent_bundle="$BUNDLES/argocd-agent/manifests.yaml"
  check "The argocd-agent objects match the bundle" check_harness_drift argocd-agent
  for ns in $(yq -N 'select(.metadata.namespace != null) | .metadata.namespace' "$agent_bundle" 2>/dev/null | sort -u); do
    check "$ns has exactly the argocd-agent objects of the bundle, with no other field manager" check_harness_objects argocd-agent "$ns"
  done
  check "The Argo CD Agent runs the images that build/images.env records" \
    check_live_images argocd deployment/argocd-agent "CELL=$CELL_NAME mise run cell:up"
  check "cell-proxy of the agent and its NetworkPolicy use the current $SPIRE_SERVER_CLUSTER node address" check_agent_env_address
  check "ConfigMap mgmt-root holds the live roots of management" check_agent_mgmt_root
  check "The ServiceAccount argocd-agent is not managed by Argo CD, so the view cannot reach its token subresource" check_agent_unmanaged
  check "No object of a gate run is left, and no binding grants the agent more than the render" check_agent_grants
  check "The Argo CD Agent holds a stream to the principal" check_agent_connected
fi
if has_harness envd; then
  check "The envd objects match the bundle" check_harness_drift envd
  check "envd-system has exactly the envd objects of the bundle, with no other field manager" check_harness_objects envd envd-system
  check "spire-system has exactly the envd objects of the bundle with the label envd, with no other field manager" check_harness_objects envd spire-system
  check "envd runs the images that build/images.env records" \
    check_live_images envd-system deployment/envd "CELL=$CELL_NAME mise run cell:up"
  check "envd and its NetworkPolicy use the current node address of $RELAY_TARGET" check_envd_mgmt_address
  check "The peer root ConfigMap of envd holds the live roots of $RELAY_TARGET" check_envd_peer_root
  check "ConfigMap cell-records holds the spec revision that mgmtd signed last" check_envd_applied
  check "The SPIRE server and envd pin the key that mgmtd signs with" check_spec_key_pinned
  check "ConfigMap spire-system/attest-hints exists, and the SPIRE server config sets hint_configmap to it" check_attest_hints_exists
  check "Every operator key pin of dev-cp and management holds the keys of operator-pub" check_operator_pins
  check "ConfigMap envd-system/local-revocations holds only entries that verify against the operator keys of envd" check_overlay_inputs
  check "The container agent-ban in spire-server-0 is Ready and has not restarted" check_agent_ban
fi
if has_harness cell-controller; then
  check "The cell-controller objects match the bundle" check_harness_drift cell-controller
  check "cell-controller-system has exactly the cell-controller objects of the bundle, with no other field manager" check_harness_objects cell-controller cell-controller-system
  check "The cell controller runs the images that build/images.env records" \
    check_live_images cell-controller-system deployment/cell-controller "CELL=$CELL_NAME mise run cell:up"
  check "ConfigMap hostsvc-pin of the cell controller equals the certificate that the host service presents" check_cell_controller_pin
  check "The cell controller pins the key that mgmtd signs with, and the staged key" check_cell_controller_key
  check "ConfigMap cell-steps holds the spec revision that mgmtd signed last" check_cell_steps_current
  check "The cell controller and its NetworkPolicy use the address that the node resolves for the host service" check_cell_controller_address
fi
if has_harness cell-gateway; then
  gateway_ip="$(node_ip "$CELL_NAME" 2>/dev/null || true)"
  check "The cell-gateway objects match the bundle" check_harness_drift cell-gateway
  check "gateway-system has exactly the cell-gateway objects of the bundle, with no other field manager" check_harness_objects cell-gateway gateway-system
  check "The cell gateway runs the images that build/images.env records" \
    check_live_images gateway-system statefulset/cell-gateway "CELL=$CELL_NAME mise run cell:up"
  check "The cell gateway holds no store error, and envd synced with it in the last 2 minutes" check_gateway_synced
  check "The cell gateway and its NetworkPolicy use the current node address of each cell" check_gateway_cells
  check "The cell gateway holds the record revision of each cell in ConfigMap cell-records" check_gateway_records
  check "The cell gateway holds an open stream for each cell of the topology" check_celld_streams
  check "The cell gateway pins the key that mgmtd signs with" check_gateway_spec_key
  for port in 30450 30451; do
    check "A probe pod in rogue cannot open TCP to the gateway node port $port of $CELL_NAME (steady state)" \
      expect_dial_blocked rogue default "${gateway_ip:-unknown}:$port"
  done
fi
if [[ -n "${SPIRE_AGENT_CELLS:-}" ]]; then
  check "The SPIRE server holds the current node address and keys of each live cell of $SPIRE_AGENT_CELLS" check_agent_cells_current
  check "The SPIRE server holds the node alias and the role entry of each subject of $SPIRE_AGENT_CELLS" check_agent_entries
  check "The bundle store and the SPIRE server hold no test bundle or test entry of gate:m2" check_no_gate_bundles
  check "The SPIRE server runs the plugin image that build/images.env records" \
    check_live_images spire-system statefulset/spire-server "CELL=$CELL_NAME mise run cell:up"
  check "The intermediate CA in Secret spire-upstream is valid for more than 7 days, and the active CA of the server chains to it" check_intermediate_expiry
  # rogue is outside the admitted node addresses, so the server NetworkPolicy must drop it.
  probe_targets+=("rogue/default")
  own_ip="$(node_ip "$CELL_NAME" 2>/dev/null || true)"
  live_now="$(live_cells)" || live_now="?"
  if [[ -z "$live_now" ]]; then
    # With no live cell the render has no node port, so nothing listens and a dial is refused.
    check "The SPIRE server of $CELL_NAME has no node port 30081 with no live cell, and a probe pod in rogue cannot open TCP to it (steady state)" \
      expect_rogue_closed "${own_ip:-unknown}:30081"
  else
    check "The SPIRE node port of $CELL_NAME has a ready local endpoint, and a probe pod in rogue cannot open TCP to it (steady state)" \
      expect_rogue_blocked "${own_ip:-unknown}:30081"
  fi
fi
if [[ -n "${SPIRE_AGENT_CELLS:-}${SPIRE_LOCAL_WORKLOADS:-}" ]]; then
  check "The SPIRE server is Ready and healthy" check_server_healthy
  check "The SPIRE server sets the SVID lifetimes of SPIRE_SVID_TTL ($SPIRE_SVID_TTL)" check_svid_ttl
  check "The SPIRE server of $SPIRE_TRUST_DOMAIN holds no federated bundle" check_no_federation
fi
if [[ -n "${SPIRE_AGENT_CELLS:-}${SPIRE_LOCAL_WORKLOADS:-}" && -z "${SPIRE_UPSTREAM:-}" ]]; then
  check "The SPIRE server keeps its CA key on its data volume, and the next root is more than 7 days away" check_ca_key_persists
fi
if [[ -n "${SPIRE_AGENT_CELLS:-}" && -n "${RELAY_TARGET:-}" ]] && has_harness cell-gateway; then
  check "The SPIRE server, relay and gateway admit lists, and the --cell-node arguments, equal the node addresses of the live cells" check_admit_lists
fi
if [[ -n "${RELAY_TARGET:-}" ]]; then
  check "The relay routes and admit lists use the current node addresses of $RELAY_TARGET and each live cell of $SPIRE_AGENT_CELLS" check_relay_current
  relay_ip="$(node_ip "$CELL_NAME" 2>/dev/null || true)"
  for route in $RELAY_VIEW_ROUTES $RELAY_TELEMETRY_ROUTES; do
    check "A probe pod in rogue cannot open TCP to the relay node port ${route%%:*} of $CELL_NAME (steady state)" \
      expect_dial_blocked rogue default "${relay_ip:-unknown}:${route%%:*}"
  done
fi
if [[ -n "${SPIRE_LOCAL_WORKLOADS:-}" ]]; then
  check "The SPIRE server holds the node alias and the entry of each local workload in SPIRE_LOCAL_WORKLOADS" check_local_entries
  check "Every pod that runs as a ServiceAccount of SPIRE_LOCAL_WORKLOADS belongs to its harness or link component" check_plane_pods
  check "spire-system holds no ServiceAccount token Secret" check_no_token_secrets
  # Only the local plane workloads reach the server pod, and no pod reaches the metrics port.
  probe_targets+=("$CELL_NAME/default")
  server_pod_ip="$(k -n spire-system get pod spire-server-0 -o jsonpath='{.status.podIP}' 2>/dev/null || true)"
  check "A probe pod in default of $CELL_NAME cannot open TCP to the SPIRE server API on its pod address (steady state)" \
    expect_dial_blocked "$CELL_NAME" default "${server_pod_ip:-unknown}:8081"
  check "A probe pod in default of $CELL_NAME cannot open TCP to the SPIRE server metrics port (steady state)" \
    expect_dial_blocked "$CELL_NAME" default "${server_pod_ip:-unknown}:9988"
fi
if [[ -n "${EXTERNAL_SECRETS_NAMESPACE:-}" && -z "${SECRET_STORE_NAMESPACES:-}" ]]; then
  check "$CELL_NAME has no SecretStore, no ClusterSecretStore and no store token, and the operator cannot list Secrets in every namespace" check_no_secret_store
fi
if [[ -n "${SECRET_STORE_NAMESPACES:-}" ]]; then
  check "SecretStore $SECRET_STORE is Ready, and each ExternalSecret that uses it is Ready and refreshed in time" check_secret_store
  check "The External Secrets Operator cannot list Secrets in every namespace, and no token copy lies outside $SECRET_STORE_NAMESPACES" check_operator_scope
fi

# The central view copies the node address and the trust bundle of VIEW_CONTROL_PLANE. A rebuilt
# control plane can have new ones, so both must match the live values.
check_view_env_address() {
  local want got
  want="$(node_ip "$VIEW_CONTROL_PLANE")" || { echo "$want"; return 1; }
  got="$(k -n central-view-system get networkpolicy argocd-agent-principal -o json \
    | jq -r '[.spec.ingress[] | select(any(.ports[]; .port == 8444)) | .from[].ipBlock.cidr] | join(" ")')" \
    || { echo "could not read NetworkPolicy central-view-system/argocd-agent-principal"; return 1; }
  if [[ "$got" != "$want/32" ]]; then
    echo "the $VIEW_CONTROL_PLANE node is $want, but the view listener admits '$got'."
    echo "Run: CELL=$CELL_NAME mise run cell:link"
    return 1
  fi
}

check_view_peer_root() {
  local live got
  live="$(kubectl --context "kind-$VIEW_CONTROL_PLANE" -n spire-system exec spire-server-0 -c spire-server -- \
    /opt/spire/bin/spire-server bundle show -socketPath /run/spire/sockets/api.sock -format pem 2>/dev/null | pem_lines)" \
    || { echo "could not read the trust bundle of $VIEW_CONTROL_PLANE"; return 1; }
  got="$(k -n central-view-system get configmap peer-root -o jsonpath='{.data.root\.crt}' | pem_lines)"
  if [[ -z "$live" || "$got" != "$live" ]]; then
    echo "ConfigMap central-view-system/peer-root holds other roots than the live bundle of $VIEW_CONTROL_PLANE."
    echo "Run: CELL=$CELL_NAME mise run cell:link"
    return 1
  fi
  peer_root_pods_current central-view-system argocd-agent-principal peer-root "CELL=$CELL_NAME mise run cell:link" || return 1
}

# The Secrets of central-view-system must be exactly the view keys and argocd-redis. An extra
# cluster Secret would add a cluster that argocd-server shows and calls.
check_view_secrets() {
  local want got
  want="$(printf '%s\n' argocd-agent-ca argocd-agent-resource-proxy-tls argocd-agent-jwt argocd-secret argocd-redis \
    $(for c in $VIEW_CELLS; do echo "cluster-$POC_ENV-$c"; done) | sort | paste -sd' ' -)"
  got="$(k -n central-view-system get secrets -o name | sed 's|^secret/||' | sort | paste -sd' ' -)" \
    || { echo "could not list the Secrets of central-view-system"; return 1; }
  if [[ "$got" != "$want" ]]; then
    echo "central-view-system holds the Secrets '$got', and the view needs '$want'."
    echo "Delete each extra Secret. For a missing one, run: CELL=$CELL_NAME mise run cell:link"
    return 1
  fi
}

# The view certificates live 180 days. The check fails 30 days before the resource proxy
# certificate expires, and every view certificate has the same lifetime.
check_view_cert_expiry() {
  local cert info left
  cert="$(k -n central-view-system get secret argocd-agent-resource-proxy-tls -o jsonpath='{.data.tls\.crt}' | base64 -d)" \
    || { echo "could not read Secret central-view-system/argocd-agent-resource-proxy-tls"; return 1; }
  info="$(cd "$ROOT" && printf '%s\n' "$cert" | mise run pki -- info 2>/dev/null)" || { echo "pkigen could not read the certificate: $info"; return 1; }
  left="$(jq -r '((.not_after | fromdateiso8601) - now) / 86400 | floor' <<<"$info")"
  if ((left < 30)); then
    echo "the view certificates expire at $(jq -r .not_after <<<"$info"), in $left days."
    echo "Run: mise run view:rotate-keys"
    return 1
  fi
}

# The principal and argocd-server read the view keys from the API at start, and they mount no copy.
# A run of link.sh that stopped after viewkeys made new keys leaves both on the old ones. The main
# container of each pod must have started after the newest view key Secret. viewkeys deletes and
# creates a Secret to change it, so its creation time is the time of its content.
check_view_pods_current() {
  local ns=central-view-system secrets newest name started pod at late=()
  # Only the creation times are read, so no Secret data enters this shell.
  secrets="$(k -n "$ns" get secrets argocd-agent-ca argocd-agent-resource-proxy-tls argocd-agent-jwt argocd-secret \
    -o jsonpath='{range .items[*]}{.metadata.creationTimestamp}{"\n"}{end}')" \
    || { echo "could not read the view key Secrets of $ns. Run: CELL=management mise run cell:link"; return 1; }
  newest="$(sort <<<"$secrets" | tail -n 1)"
  [[ -n "$newest" ]] || { echo "the view key Secrets of $ns have no creation time. Run: CELL=management mise run cell:link"; return 1; }
  for name in argocd-agent-principal argocd-server; do
    started="$(k -n "$ns" get pods -l "app.kubernetes.io/name=$name" -o json \
      | jq -r --arg name "$name" '.items[] | .metadata.name as $pod | .status.containerStatuses[]? | select(.name == $name)
        | "\($pod) \(.state.running.startedAt // "")"')" || { echo "could not read the pods of $name in $ns. Run: CELL=management mise run cell:link"; return 1; }
    [[ -n "$started" ]] || { echo "$name has no pod in $ns. Run: CELL=management mise run cell:link"; return 1; }
    while read -r pod at; do
      if [[ -z "$at" || "$at" < "$newest" ]]; then
        late+=("$pod started at ${at:-no time}")
      fi
    done <<<"$started"
  done
  if ((${#late[@]} > 0)); then
    for pod in "${late[@]}"; do
      printf '%s, before the newest view key at %s.\n' "$pod" "$newest"
    done
    echo "The pod reads the keys only at start, so it may hold old certificates."
    echo "Run: mise run view:rotate-keys"
    return 1
  fi
}

# The telemetry gateway copies the node address and the trust bundle of VIEW_CONTROL_PLANE, like the
# central view does.
check_gateway_env_address() {
  local want got
  want="$(node_ip "$VIEW_CONTROL_PLANE")" || { echo "$want"; return 1; }
  got="$(k -n observability-system get networkpolicy telemetry-gateway -o json \
    | jq -r '[.spec.ingress[] | select(any(.ports[]; .port == 8444)) | .from[].ipBlock.cidr] | join(" ")')" \
    || { echo "could not read NetworkPolicy observability-system/telemetry-gateway"; return 1; }
  if [[ "$got" != "$want/32" ]]; then
    echo "the $VIEW_CONTROL_PLANE node is $want, but the gateway listener admits '$got'."
    echo "Run: CELL=$CELL_NAME mise run cell:link"
    return 1
  fi
}

check_gateway_peer_root() {
  local live got
  live="$(kubectl --context "kind-$VIEW_CONTROL_PLANE" -n spire-system exec spire-server-0 -c spire-server -- \
    /opt/spire/bin/spire-server bundle show -socketPath /run/spire/sockets/api.sock -format pem 2>/dev/null | pem_lines)" \
    || { echo "could not read the trust bundle of $VIEW_CONTROL_PLANE"; return 1; }
  got="$(k -n observability-system get configmap peer-root -o jsonpath='{.data.root\.crt}' | pem_lines)"
  if [[ -z "$live" || "$got" != "$live" ]]; then
    echo "ConfigMap observability-system/peer-root holds other roots than the live bundle of $VIEW_CONTROL_PLANE."
    echo "Run: CELL=$CELL_NAME mise run cell:link"
    return 1
  fi
  peer_root_pods_current observability-system telemetry-gateway peer-root "CELL=$CELL_NAME mise run cell:link" || return 1
}

# The hub copies the node address and the trust bundle of VIEW_CONTROL_PLANE, like the gateway does. It
# also holds one tunnel for each cell of MESH_VIEW_CELLS, and Kiali needs them all.
check_hub_env_address() {
  local want got
  want="$(node_ip "$VIEW_CONTROL_PLANE")" || { echo "$want"; return 1; }
  got="$(k -n mesh-view-system get networkpolicy mesh-view-hub -o json \
    | jq -r '[.spec.ingress[] | select(any(.ports[]; .port == 8444)) | .from[].ipBlock.cidr] | join(" ")')" \
    || { echo "could not read NetworkPolicy mesh-view-system/mesh-view-hub"; return 1; }
  if [[ "$got" != "$want/32" ]]; then
    echo "the $VIEW_CONTROL_PLANE node is $want, but the hub listener admits '$got'."
    echo "Run: CELL=$CELL_NAME mise run cell:link"
    return 1
  fi
}

check_hub_peer_root() {
  local live got
  live="$(kubectl --context "kind-$VIEW_CONTROL_PLANE" -n spire-system exec spire-server-0 -c spire-server -- \
    /opt/spire/bin/spire-server bundle show -socketPath /run/spire/sockets/api.sock -format pem 2>/dev/null | pem_lines)" \
    || { echo "could not read the trust bundle of $VIEW_CONTROL_PLANE"; return 1; }
  got="$(k -n mesh-view-system get configmap peer-root -o jsonpath='{.data.root\.crt}' | pem_lines)"
  if [[ -z "$live" || "$got" != "$live" ]]; then
    echo "ConfigMap mesh-view-system/peer-root holds other roots than the live bundle of $VIEW_CONTROL_PLANE."
    echo "Run: CELL=$CELL_NAME mise run cell:link"
    return 1
  fi
  peer_root_pods_current mesh-view-system mesh-view-hub peer-root "CELL=$CELL_NAME mise run cell:link" || return 1
}

# hub_tunnel_gaps prints each live cell of MESH_VIEW_CELLS whose tunnel is not up, by the state that the hub serves. A cell with
# no cluster has no tunnel.
hub_tunnel_gaps() {
  local entry cell live
  live="$(live_cells)" || return 1
  for entry in $MESH_VIEW_CELLS; do
    cell="${entry%%=*}"
    grep -qx -- "$cell" <<<"$live" || continue
    hub_cell_state "$cell" || echo "$cell"
  done
}

# check_hub_tunnels succeeds when the last tunnel line of the hub for each cell of MESH_VIEW_CELLS is
# tunnel_up. A tunnel ends when the SVID of the cell expires and starts again within seconds, so the
# check waits up to 30 seconds for a cell that is between two tunnels.
check_hub_tunnels() {
  local end=$((SECONDS + 30)) down
  until down="$(hub_tunnel_gaps)" && [[ -z "$down" ]]; do
    if ((SECONDS >= end)); then
      echo "the hub has no tunnel from: $(paste -sd' ' - <<<"$down")."
      echo "Run: CELL=<cell> mise run cell:up for each of them, and read the state: mise run mesh:status"
      echo "If every cell is down at once, a test may have left its firewall rule: mise run gate:m3:repair"
      return 1
    fi
    sleep 3
  done
}

# The bundle store of every cluster, and the signed bundle sets of a cluster with the role cell or cp.
check "The bundle store proxy admits the one writer of the role of $CELL_NAME, and the repo server reads through its token client" check_store_proxy
case "$(bundle_role)" in
  cell | cp)
    check "The root in the bundle state of $CELL_NAME is signed by mgmtd (cosign, offline)" check_signed_root
    check "The guards that keep Argo CD away from the harness equal the render of the role" check_bundle_guard
    check "Each harness plane policy of the role exists with the harness label" check_plane_policies
    check "The allow-list digest that the applier reports equals the annotation of each AppProject" check_allow_list_version
    ;;
esac

# Link components: the objects of each namespace that the bundle holds, the cluster-scoped objects,
# and the images of each workload. cell:link renders them again from the live facts.
for entry in ${LINK_COMPONENTS[@]+"${LINK_COMPONENTS[@]}"}; do
  comp="${entry%%:*}"
  bundle="$BUNDLES/$comp/manifests.yaml"
  check "The $comp objects match the bundle" check_harness_drift "$comp"
  for ns in $(yq -N 'select(.metadata.namespace != null) | .metadata.namespace' "$bundle" 2>/dev/null | sort -u); do
    check "$ns has exactly the $comp objects of the bundle, with no other field manager" check_harness_objects "$comp" "$ns"
  done
  if [[ "$comp" == mgmt-api ]]; then
    check "ConfigMap hostsvc-pin equals the certificate that the host service presents" check_mgmt_hostsvc_pin
    check "The host service trusts the live root of $CELL_NAME" check_mgmt_hostsvc_root
    check "The host service serves the live dev root and the keys of mgmtd, and knows the signed spec revision" check_hostsvc_roots
    check "The host service address in the policy and in mgmtd is the one that the node resolves" check_mgmt_hostsvc_address
    check "The API port admits the current $VIEW_CONTROL_PLANE node address" check_mgmt_env_address
    check "ConfigMap peer-root holds the live roots of $VIEW_CONTROL_PLANE" check_mgmt_peer_root
    check "ConfigMap mgmt-signing-pub equals the key that mgmtd signs with" mgmt_signing_pub
  fi
  if [[ "$comp" == central-view ]]; then
    check "The view listener admits the current $VIEW_CONTROL_PLANE node address" check_view_env_address
    check "ConfigMap peer-root holds the live roots of $VIEW_CONTROL_PLANE" check_view_peer_root
    check "central-view-system holds only the Secrets of the view" check_view_secrets
    check "The view certificates are valid for 30 days or more" check_view_cert_expiry
    check "The principal and argocd-server started after the newest view key" check_view_pods_current
    check "ConfigMap cell-registry of central-view-system is the registry that mgmtd published" check_registry_published central-view-system
  fi
  if [[ "$comp" == telemetry-gateway ]]; then
    check "The gateway listener admits the current $VIEW_CONTROL_PLANE node address" check_gateway_env_address
    check "ConfigMap peer-root of observability-system holds the live roots of $VIEW_CONTROL_PLANE" check_gateway_peer_root
    check "ConfigMap cell-registry of observability-system is the registry that mgmtd published" check_registry_published observability-system
  fi
  if [[ "$comp" == mesh-view-hub ]]; then
    check "The hub listener admits the current $VIEW_CONTROL_PLANE node address" check_hub_env_address
    check "ConfigMap peer-root of mesh-view-system holds the live roots of $VIEW_CONTROL_PLANE" check_hub_peer_root
    check "ConfigMap cell-registry of mesh-view-system is the registry that mgmtd published" check_registry_published mesh-view-system
    check "The hub holds a tunnel from each live cell of MESH_VIEW_CELLS" check_hub_tunnels
  fi
  for workload in $(yq -o=json -I=0 'select(.kind == "Deployment" or .kind == "StatefulSet" or .kind == "Job")' "$bundle" 2>/dev/null \
      | jq -r 'select(any(.spec.template.spec | ((.initContainers // []) + .containers)[]; .image | startswith("localhost:5001/")))
        | .metadata.namespace + "|" + (.kind | ascii_downcase) + "/" + .metadata.name'); do
    check "${workload#*|} runs the images that build/images.env records" \
      check_live_images "${workload%%|*}" "${workload#*|}" "CELL=$CELL_NAME mise run cell:link"
  done
done

if ((failures > 0)); then
  log "$failures check(s) failed"
  exit 1
fi
log "all checks passed"
