# Helpers of cell:verify that scripts/verify.sh sources, so the tests can source them too. Each check
# function prints the reason and the repair command on standard output, and fails.
# check_mgmt_* need scripts/lib.sh and the helpers of components/lib/hostsvc-pin.sh, peer-root.sh and mgmt-key.sh.

# pem_lines prints each PEM certificate on standard input as one line, sorted.
pem_lines() {
  awk '/-----BEGIN CERTIFICATE-----/ { b = "" } { b = b $0 } /-----END CERTIFICATE-----/ { print b }' | sort
}

# peer_root_pods_current <namespace> <app> <ConfigMap> <fix command> succeeds when every running pod of the
# workload carries the digest of the ConfigMap in its annotation poc.internal/peer-root-sha256. The process reads
# the roots once at start, so a ConfigMap that is right does not show that the pod trusts the same roots.
peer_root_pods_current() {
  local ns="$1" app="$2" cm="$3" fix="$4" raw want pods bad
  raw="$(k -n "$ns" get configmap "$cm" -o jsonpath='{.data.root\.crt}')" || { echo "could not read ConfigMap $ns/$cm"; return 1; }
  want="$(printf '%s' "$raw" | shasum -a 256 | cut -d' ' -f1)"
  pods="$(k -n "$ns" get pods -l "app.kubernetes.io/name=$app" -o json)" || { echo "could not read the pods of $app in $ns"; return 1; }
  bad="$(jq -r --arg want "$want" '[.items[] | select(.metadata.deletionTimestamp == null) | .metadata.name as $n
      | ((.metadata.annotations["poc.internal/peer-root-sha256"] // "") | if . == "" then "none" else . end) as $got | select($got != $want) | "\($n) carries the root digest \($got)"] | .[]' <<<"$pods")"
  if [[ -z "$(jq -r '[.items[] | select(.metadata.deletionTimestamp == null)] | length | select(. > 0)' <<<"$pods")" ]]; then
    echo "$app has no running pod in $ns."
    echo "Run: $fix"
    return 1
  fi
  if [[ -n "$bad" ]]; then
    echo "$bad"
    echo "ConfigMap $ns/$cm has the digest $want, and a pod reads the roots only at start."
    echo "Run: $fix"
    return 1
  fi
}

node_ip() {
  local facts ip
  facts="$(cd "$ROOT" && mise run hostsvc -- facts --cluster "$1" 2>/dev/null)" || { echo "no host service facts for $1"; return 1; }
  ip="$(jq -r '.nodeIP // ""' <<<"$facts")"
  [[ -n "$ip" ]] || { echo "the host service reports no node address for $1"; return 1; }
  printf '%s\n' "$ip"
}

# The host service serves the live dev root, trusts the keys that mgmtd holds, and knows the spec that mgmtd signed last. The
# served dev_root_sha256 must equal the DER SHA-256 of the live dev root of dev-cp (while dev-cp exists), the served keys must
# equal the SHA-256 of the key that `mise run mgmt -- pubkey` prints and of stagedKey of `mise run mgmt -- status`, and
# spec_revision must equal the signed revision. A mismatch prints mise run hostsvc:serve -- sync, and a mgmtd that does not
# answer prints the link of mgmt-api.
check_hostsvc_roots() {
  local serve status mgmt pub staged live_dev want_keys flag problems=() link="CELL=management LINK_ONLY=mgmt-api mise run cell:link"
  serve="$(hostsvc_serve_script)"
  status="$("$serve" status)" || { echo "the host service status failed"; return 1; }
  [[ "$(jq -r '.running' <<<"$status")" == true ]] || { echo "the host service does not run."; echo "Run: mise run hostsvc:serve -- start"; return 1; }
  mgmt="$(cd "$ROOT" && mise run mgmt -- status 2>/dev/null)" || mgmt=""
  pub="$(cd "$ROOT" && mise run mgmt -- pubkey 2>/dev/null | jq -r '."spec.pub" // ""')" || pub=""
  if ! jq -e 'type == "object"' >/dev/null 2>&1 <<<"$mgmt" || [[ -z "$pub" ]]; then
    echo "mgmtd does not answer, so the keys and the spec revision of the host service are unchecked."
    echo "Run: $link"
    return 1
  fi
  if kind get clusters 2>/dev/null | grep -qx dev-cp; then
    live_dev="$(peer_root_pem dev-cp dev.env.poc.internal 2>/dev/null | pem_der_sha256)" || live_dev=""
    [[ -n "$live_dev" && "$(jq -r '.dev_root_sha256' <<<"$status")" == "$live_dev" ]] \
      || problems+=("the host service serves the dev root '$(jq -r '.dev_root_sha256' <<<"$status")', and the live root of dev-cp is '${live_dev:-unknown}'")
  fi
  flag=-d
  printf 'AA==' | base64 -d >/dev/null 2>&1 || flag=-D
  staged="$(jq -r '.stagedKey // ""' <<<"$mgmt")"
  want_keys="$({ printf '%s' "$pub" | base64 "$flag" | shasum -a 256 | cut -d' ' -f1; [[ -z "$staged" ]] || echo "$staged"; } | jq -Rcn '[inputs] | sort')"
  [[ "$(jq -cS '.keys | sort' <<<"$status")" == "$want_keys" ]] \
    || problems+=("the host service trusts the keys $(jq -c '.keys' <<<"$status"), and mgmtd holds $want_keys (the signing key and the staged key)")
  [[ "$(jq -cS '.spec_revision' <<<"$status")" == "$(jq -cS '.signed' <<<"$mgmt")" ]] \
    || problems+=("the host service knows the spec revision $(jq -c '.spec_revision' <<<"$status"), and mgmtd signed $(jq -c '.signed' <<<"$mgmt")")
  if ((${#problems[@]} > 0)); then
    printf '%s\n' "${problems[@]}"
    echo "Run: mise run hostsvc:serve -- sync. If mgmtd pushes no spec, run: $link"
    return 1
  fi
}

# mgmtd copies the certificate of the host service, the address of the host service, the node address of
# VIEW_CONTROL_PLANE and its root, and the host service copies the root of management. Each can fall behind
# a restart of the host service or a rebuild. A mismatch prints the command that brings it up to date.
check_mgmt_hostsvc_pin() {
  local live got status want
  live="$("$(hostsvc_serve_script)" pin 2>&1)" || { echo "$live"; echo "Run: $(dependents_of hostsvc)"; return 1; }
  got="$(k -n mgmt-system get configmap hostsvc-pin -o jsonpath='{.data.hostsvc\.crt}')" \
    || { echo "could not read ConfigMap mgmt-system/hostsvc-pin"; return 1; }
  if [[ "$(pem_lines <<<"$got")" != "$(pem_lines <<<"$live")" ]]; then
    echo "ConfigMap mgmt-system/hostsvc-pin holds another certificate than the host service presents."
    echo "Run: $(dependents_of hostsvc)"
    return 1
  fi
  status="$("$(hostsvc_serve_script)" status)" || return 1
  want="$(jq -r '.cert_sha256' <<<"$status")"
  got="$(k -n mgmt-system get pod mgmtd-0 -o jsonpath='{.metadata.annotations.poc\.internal/hostsvc-pin-sha256}')" \
    || { echo "could not read the pod mgmtd-0"; return 1; }
  if [[ "$got" != "$want" ]]; then
    echo "mgmtd-0 carries the pin digest '$got', and the host service presents $want."
    echo "Run: $(dependents_of hostsvc)"
    return 1
  fi
}

check_mgmt_hostsvc_root() {
  local status have live
  status="$("$(hostsvc_serve_script)" status)" || return 1
  have="$(jq -r '.root_sha256' <<<"$status")"
  live="$(peer_root_pem "$CELL_NAME" "$SPIRE_TRUST_DOMAIN" | pem_der_sha256)" || { echo "could not read the live root of $CELL_NAME"; return 1; }
  if [[ "$have" != "$live" ]]; then
    echo "the host service trusts the management root $have, and the live root is $live."
    echo "Run: $(dependents_of hostsvc)"
    return 1
  fi
}

check_mgmt_hostsvc_address() {
  local want got arg
  want="$(hostsvc_address "$CELL_NAME" 2>&1)" || { echo "$want"; return 1; }
  got="$(k -n mgmt-system get networkpolicy mgmtd -o json \
    | jq -r --argjson p "$HOSTSVC_PORT" '[.spec.egress[] | select(any(.ports[]; .port == $p)) | .to[].ipBlock.cidr] | join(" ")')" \
    || { echo "could not read NetworkPolicy mgmt-system/mgmtd"; return 1; }
  arg="$(k -n mgmt-system get statefulset mgmtd -o json | jq -r '.spec.template.spec.containers[] | select(.name == "mgmtd") | .args[] | select(startswith("--hostsvc-addr="))')"
  if [[ "$got" != "$want/32" || "$arg" != "--hostsvc-addr=$want:$HOSTSVC_PORT" ]]; then
    echo "host.docker.internal is $want in the node, but the policy admits '$got' and mgmtd runs '$arg'."
    echo "Run: $(fix_command mgmt-api)"
    return 1
  fi
}

check_mgmt_env_address() {
  local want got port
  if ! kind get clusters 2>/dev/null | grep -qx "$VIEW_CONTROL_PLANE"; then
    got="$(k -n mgmt-system get networkpolicy mgmtd -o json | jq -r '[.spec.ingress[] | select(any(.ports[]; .port == 8446)) | .from[].ipBlock.cidr] | join(" ")')"
    [[ -z "$got" ]] || { echo "$VIEW_CONTROL_PLANE does not exist, but the API port admits '$got'."; echo "Run: $(fix_command mgmt-api)"; return 1; }
    return 0
  fi
  want="$(node_ip "$VIEW_CONTROL_PLANE")" || { echo "$want"; return 1; }
  got="$(k -n mgmt-system get networkpolicy mgmtd -o json \
    | jq -r '[.spec.ingress[] | select(any(.ports[]; .port == 8446)) | .from[].ipBlock.cidr] | join(" ")')" \
    || { echo "could not read NetworkPolicy mgmt-system/mgmtd"; return 1; }
  if [[ "$got" != "$want/32" ]]; then
    echo "the $VIEW_CONTROL_PLANE node is $want, but port 8446 admits '$got'."
    echo "Run: $(fix_command mgmt-api)"
    return 1
  fi
}

check_mgmt_peer_root() {
  local live got
  live="$(peer_root_pem "$VIEW_CONTROL_PLANE" dev.env.poc.internal 2>&1)" || { echo "$live"; return 1; }
  got="$(k -n mgmt-system get configmap peer-root -o jsonpath='{.data.root\.crt}' 2>/dev/null | pem_lines)"
  if [[ -z "$got" || "$got" != "$(pem_lines <<<"$live")" ]]; then
    echo "ConfigMap mgmt-system/peer-root is absent or holds other roots than the live bundle of $VIEW_CONTROL_PLANE."
    echo "Run: $(fix_command mgmt-api)"
    return 1
  fi
  peer_root_pods_current mgmt-system mgmtd peer-root "$(fix_command mgmt-api)" || return 1
}


# missing_cell_hint <cell> prints the way out when a live cell cannot read its facts.
missing_cell_hint() {
  echo "Read the facts of the cell: mise run hostsvc -- facts --cluster $1, then run CELL=$1 mise run cell:up and CELL=$CELL_NAME mise run cell:up."
}

# record_jwks <cluster> <cell> prints the sorted keys that the signed record of the cell in ConfigMap
# spire-system/cell-records holds. It fails when the ConfigMap or the record is absent.
record_jwks() {
  local cm raw
  cm="$(kubectl --context "kind-$1" -n spire-system get configmap cell-records -o json 2>/dev/null)" || return 1
  raw="$(jq -er --arg key "$2.dsse.json" '.data[$key]' <<<"$cm")" || return 1
  jq -er .payload <<<"$raw" | base64 -d | jq -cS '.jwks.keys | sort_by(.kid)'
}

# The SPIRE server renders the node address of each live agent cell. envd writes the signed record of each bound cell
# into ConfigMap cell-records. A rebuilt cell has a new service account key, and it can have a new node address. A record
# that holds other keys than the cell publishes is a key check for the management plane. A live cell with no record has
# not bound yet: the check names it in one line and does not fail, because envd writes records only for bound cells. The
# rule of the agent node port is the one for port 8081, never the first rule, and it is absent while no cell is live.
check_agent_cells_current() {
  local cell ip facts want got cidrs traces want_cidrs=() stale=() keycheck=() live
  live="$(live_cells)" || { echo "$live"; return 1; }
  for cell in $live; do
    ip="$(node_ip "$cell")" || { echo "$ip."; missing_cell_hint "$cell"; return 1; }
    want_cidrs+=("$ip/32")
    if ! record_jwks "$CELL_NAME" "$cell" >/dev/null 2>&1; then
      echo "the record of $cell is not in ConfigMap cell-records yet, so $cell has not bound"
      continue
    fi
    facts="$(cd "$ROOT" && mise run hostsvc -- facts --cluster "$cell" 2>/dev/null)"
    want="$(jq -cS '.jwks.keys | sort_by(.kid)' <<<"$facts")"
    got="$(record_jwks "$CELL_NAME" "$cell")" || got=""
    if [[ -z "$want" || "$got" != "$want" ]]; then
      stale+=("the record of $cell in ConfigMap cell-records holds other service account keys than $cell publishes")
      keycheck+=("mise run mgmt -- keycheck --cell $cell")
    fi
  done
  json="$(k -n spire-system get networkpolicy plane-cells --ignore-not-found -o json)" || { echo "cannot read NetworkPolicy spire-system/plane-cells"; echo "Run: CELL=$CELL_NAME mise run cell:up"; return 1; }
  cidrs=""
  [[ -z "$json" ]] || cidrs="$(jq -r '[.spec.ingress[]? | select(any(.ports[]?; .port == 8081)) | .from[]?.ipBlock.cidr] | sort | join(" ")' <<<"$json")"
  # jq sorts both sides, so the comparison does not depend on the locale of sort.
  want="$(printf '%s\n' ${want_cidrs[@]+"${want_cidrs[@]}"} | jq -Rrs 'split("\n") | map(select(length > 0)) | sort | join(" ")')"
  [[ "$cidrs" == "$want" ]] || stale+=("the NetworkPolicy admits '$cidrs', but the agent cell nodes are '$want'")
  if ((${#stale[@]} > 0)); then
    printf '%s\n' "${stale[@]}"
    # While the key rotation test has changed a cell, its keys include the test key, so the node must be
    # repaired first. A node that cannot be read counts as one that needs the repair.
    for cell in $live; do
      if ! traces="$(keytest_leftover "$cell")" || [[ -n "$traces" ]]; then
        printf '%s\n' "$traces"
        echo "Run: mise run gate:m2:repair, and then CELL=$CELL_NAME mise run cell:verify again"
        return 1
      fi
    done
    if ((${#keycheck[@]} > 0)); then
      printf 'Run: %s\n' "${keycheck[@]}"
    else
      echo "Run: CELL=$CELL_NAME mise run cell:up"
    fi
    return 1
  fi
}

# check_admit_lists succeeds when every list that admits cells by node address equals the node addresses of the live cells, in
# both directions: the plane-cells policy of the SPIRE server (port 8081), the plane-cells policy of the relay (its route ports), the
# rules of N37 (8450) and N38 (8451) of the gateway, and the --cell-node arguments of the gateway. An address of a cell that has
# no cluster fails the check as well as a live cell that is missing. A policy rule is selected by its port, never by its index.
# While no cell is live, each cell rule is absent and each list is empty.
check_admit_lists() {
  local live cell ip want_cidrs=() want want_nodes=() problems=() got name json port
  live="$(live_cells)" || { echo "$live"; return 1; }
  for cell in $live; do
    ip="$(node_ip "$cell")" || { echo "$ip"; echo "Run: CELL=$CELL_NAME mise run cell:up"; return 1; }
    want_cidrs+=("$ip/32")
    want_nodes+=("--cell-node=$cell=$ip")
  done
  want="$(printf '%s\n' ${want_cidrs[@]+"${want_cidrs[@]}"} | jq -Rrs 'split("\n") | map(select(length > 0)) | sort | join(" ")')"
  list_of() { jq -r --argjson p "$2" '[.spec.ingress[]? | select(any(.ports[]?; .port == $p)) | .from[]?.ipBlock.cidr] | sort | join(" ")' <<<"$1"; }
  got=""
  if json="$(k -n spire-system get networkpolicy plane-cells --ignore-not-found -o json)"; then
    [[ -z "$json" ]] || got="$(list_of "$json" 8081)"
    [[ "$got" == "$want" ]] || problems+=("the SPIRE server admits '$got' on port 8081, and the live cells are '$want'")
  else
    problems+=("cannot read NetworkPolicy spire-system/plane-cells")
  fi
  got=""
  if json="$(k -n relay-system get networkpolicy plane-cells --ignore-not-found -o json)"; then
    [[ -z "$json" ]] || got="$(jq -r '[.spec.ingress[]? | .from[]?.ipBlock.cidr] | sort | join(" ")' <<<"$json")"
    [[ "$got" == "$want" ]] || problems+=("the relay plane policy plane-cells admits '$got' on its route ports, and the live cells are '$want'")
  else
    problems+=("cannot read NetworkPolicy relay-system/plane-cells")
  fi
  json="$(k -n gateway-system get networkpolicy cell-gateway -o json 2>/dev/null)" || { problems+=("cannot read NetworkPolicy gateway-system/cell-gateway"); json='{}'; }
  for port in 8450 8451; do
    got="$(list_of "$json" "$port")"
    [[ "$got" == "$want" ]] || problems+=("the gateway admits '$got' on port $port, and the live cells are '$want'")
  done
  got="$(k -n gateway-system get statefulset cell-gateway -o json 2>/dev/null \
    | jq -r '[.spec.template.spec.containers[] | select(.name == "cellgw") | .args[] | select(startswith("--cell-node="))] | sort | join(" ")')" \
    || got=""
  want="$(printf '%s\n' ${want_nodes[@]+"${want_nodes[@]}"} | jq -Rrs 'split("\n") | map(select(length > 0)) | sort | join(" ")')"
  [[ "$got" == "$want" ]] || problems+=("the gateway runs '$got', and the live cells need '$want'")
  if ((${#problems[@]} > 0)); then
    printf '%s\n' "${problems[@]}"
    echo "Run: CELL=dev-cp mise run cell:up"
    return 1
  fi
}

# The M2 key rotation test changes the API server of a cell on its node. The node must hold no trace
# of it, and the API server must publish exactly the keys that the record of the cell holds.
check_keytest_clean() {
  local traces live record
  # The node traces come first, because the API server may not answer while the node holds them.
  if ! traces="$(keytest_leftover "$CELL_NAME")" || [[ -n "$traces" ]]; then
    printf '%s\n' "$traces"
    echo "Run: mise run gate:m2:repair"
    return 1
  fi
  live="$(k get --raw /openid/v1/jwks | jq -cS '.keys | sort_by(.kid)')" || { echo "could not read the JWKS of $CELL_NAME"; return 1; }
  record="$(record_jwks "$SPIRE_SERVER_CLUSTER" "$CELL_NAME")" || { echo "could not read the record of $CELL_NAME in ConfigMap cell-records of $SPIRE_SERVER_CLUSTER"; return 1; }
  if [[ -z "$live" || "$live" != "$record" ]]; then
    echo "the API server of $CELL_NAME publishes other keys than its record in $SPIRE_SERVER_CLUSTER."
    echo "Run: mise run mgmt -- keycheck --cell $CELL_NAME"
    return 1
  fi
}

# configmap_applied_spec <namespace> <ConfigMap> [marker] succeeds when envd wrote the ConfigMap for the spec that mgmtd signed
# last: the annotations poc.internal/spec-epoch and poc.internal/spec-counter equal the signed revision, and, when a marker is
# named, the label poc.internal/made-by has that value.
configmap_applied_spec() {
  local ns="$1" name="$2" marker="${3:-}" status signed epoch cm counter stored_epoch made
  status="$(cd "$ROOT" && mise run mgmt -- status 2>/dev/null)" || { echo "mise run mgmt -- status failed: $status"; echo "Run: CELL=management LINK_ONLY=mgmt-api mise run cell:link"; return 1; }
  signed="$(jq -er '.signed.counter' <<<"$status")" && epoch="$(jq -er '.signed.epoch' <<<"$status")" \
    || { echo "mgmtd reports no signed revision: $status"; return 1; }
  cm="$(k -n "$ns" get configmap "$name" -o json 2>&1)" \
    || { echo "ConfigMap $ns/$name is absent: $cm"; echo "Read the log of envd: mise x -- kubectl --context kind-$CELL_NAME -n envd-system logs deploy/envd -c envd"; return 1; }
  counter="$(jq -r '.metadata.annotations["poc.internal/spec-counter"] // "none"' <<<"$cm")"
  stored_epoch="$(jq -r '.metadata.annotations["poc.internal/spec-epoch"] // "none"' <<<"$cm")"
  made="$(jq -r '.metadata.labels["poc.internal/made-by"] // "none"' <<<"$cm")"
  if [[ "$counter" != "$signed" || "$stored_epoch" != "$epoch" || -n "$marker" && "$made" != "$marker" ]]; then
    echo "$name holds the spec revision $stored_epoch/$counter${marker:+ and the marker '$made'}, and mgmtd signed $epoch/$signed${marker:+. envd writes it with the marker $marker}."
    echo "Read the status of envd: mise run mgmt -- status, and its log: mise x -- kubectl --context kind-$CELL_NAME -n envd-system logs deploy/envd -c envd"
    return 1
  fi
}

# envd writes the signed counter of the spec as the annotation poc.internal/spec-counter of ConfigMap
# cell-records. The counter must equal the one that mgmtd signed last.
check_envd_applied() { configmap_applied_spec spire-system cell-records; }

# The SPIRE server and envd pin the public key of mgmtd: record_public_keys in the server config, and
# ConfigMap mgmt-spec-key. Both must equal ConfigMap mgmt-signing-pub in management. With no live cell the render drops the
# cluster_jwt plugin, so the server config must hold no record_public_keys line and no cluster_jwt plugin, and only mgmt-spec-key
# must equal the live key.
check_spec_key_pinned() {
  local live conf pinned stored cells
  live="$(mgmt_signing_pub 2>&1)" || { echo "$live"; return 1; }
  conf="$(k -n spire-system get configmap spire-server -o jsonpath='{.data.server\.conf}')" || { echo "could not read ConfigMap spire-server"; return 1; }
  pinned="$(sed -n 's/^ *record_public_keys = \[\(.*\)\]$/\1/p' <<<"$conf" | tr -d ' "')"
  stored="$(k -n envd-system get configmap mgmt-spec-key -o jsonpath='{.data.spec\.pub}')" || { echo "could not read ConfigMap envd-system/mgmt-spec-key"; return 1; }
  cells="$(live_cells)" || { echo "$cells"; return 1; }
  if [[ -z "$cells" ]]; then
    if [[ -n "$pinned" ]] || grep -q 'NodeAttestor "cluster_jwt"' <<<"$conf" || [[ "$stored" != "$live" ]]; then
      echo "no cell is live, so the server config must hold no cluster_jwt plugin and no record_public_keys, and mgmt-spec-key must hold $live."
      echo "The server config pins '$pinned' (cluster_jwt plugin present: $(grep -q 'NodeAttestor "cluster_jwt"' <<<"$conf" && echo yes || echo no)), and mgmt-spec-key holds '$stored'."
      echo "Run: CELL=$CELL_NAME mise run cell:up"
      return 1
    fi
    return 0
  fi
  if [[ "$pinned" != "$live" || "$stored" != "$live" ]]; then
    echo "mgmt-signing-pub holds $live, the server config pins '$pinned', and mgmt-spec-key holds '$stored'."
    echo "Run: CELL=$CELL_NAME mise run cell:up"
    return 1
  fi
}

# check_attest_hints_exists succeeds when ConfigMap spire-system/attest-hints exists and the server config of the SPIRE server sets
# hint_configmap to it. envd creates the ConfigMap, and the cluster_jwt plugin only patches it, so a missing ConfigMap means that
# every hint of an unknown key ID is lost. With no live cell the render drops the plugin, and the server config must set no
# hint_configmap.
check_attest_hints_exists() {
  local conf set cells
  cells="$(live_cells)" || { echo "$cells"; return 1; }
  conf="$(k -n spire-system get configmap spire-server -o jsonpath='{.data.server\.conf}')" || { echo "could not read ConfigMap spire-server"; return 1; }
  set="$(sed -n 's/^ *hint_configmap = "\(.*\)"$/\1/p' <<<"$conf")"
  if [[ -z "$cells" ]]; then
    if [[ -n "$set" ]]; then
      echo "no cell is live, so the render drops the cluster_jwt plugin, and the server config sets hint_configmap '$set', want none."
      echo "Run: CELL=$CELL_NAME mise run cell:up"
      return 1
    fi
    return 0
  fi
  k -n spire-system get configmap attest-hints -o name >/dev/null 2>&1 \
    || { echo "ConfigMap spire-system/attest-hints is absent, so the SPIRE server cannot hint mgmtd on an unknown key ID."; echo "Run: CELL=$CELL_NAME mise run cell:up"; return 1; }
  if [[ "$set" != spire-system/attest-hints ]]; then
    echo "the server config sets hint_configmap '$set', want spire-system/attest-hints."
    echo "Run: CELL=$CELL_NAME mise run cell:up"
    return 1
  fi
}

# check_spire_node_port_closed succeeds when the Service of the SPIRE server has no node port 30081. With no live cell the render
# keeps only the ClusterIP Service of the workloads, so nothing listens on the node port, and the node answers a dial with a refusal.
check_spire_node_port_closed() {
  local ports
  ports="$(k -n spire-system get service spire-server -o json | jq -r '[.spec.ports[]? | .nodePort // empty] | join(" ")')" \
    || { echo "could not read Service spire-server"; return 1; }
  if [[ " $ports " == *" 30081 "* ]]; then
    echo "no cell is live, and Service spire-server still has the node port 30081."
    echo "Run: CELL=$CELL_NAME mise run cell:up"
    return 1
  fi
}

# envd copies the node address of RELAY_TARGET into its upstream argument, and the NetworkPolicy of
# flow N30 admits it. Docker can give a rebuilt node a new address.
check_envd_mgmt_address() {
  local want arg cidrs
  want="$(node_ip "$RELAY_TARGET")" || { echo "$want"; return 1; }
  arg="$(k -n envd-system get deployment envd -o json \
    | jq -r '[.spec.template.spec.containers[] | select(.name == "envd") | .args[] | select(startswith("--upstream="))] | join(" ")')" \
    || { echo "could not read deployment/envd"; return 1; }
  cidrs="$(k -n envd-system get networkpolicy envd -o json \
    | jq -r '[.spec.egress[] | select(any(.ports[]; .port == 31446)) | .to[].ipBlock.cidr] | join(" ")')" \
    || { echo "could not read NetworkPolicy envd-system/envd"; return 1; }
  if [[ "$arg" != "--upstream=$want:31446" || "$cidrs" != "$want/32" ]]; then
    echo "the $RELAY_TARGET node is $want, but envd runs '$arg' and the policy admits '$cidrs'."
    echo "Run: CELL=$CELL_NAME mise run cell:up"
    return 1
  fi
}

# ConfigMap envd-system/peer-root must hold the live roots of management, and the pod must carry their digest.
check_envd_peer_root() {
  local live got
  live="$(peer_root_pem "$RELAY_TARGET" mgmt.poc.internal 2>&1)" || { echo "$live"; return 1; }
  got="$(k -n envd-system get configmap peer-root -o jsonpath='{.data.root\.crt}' 2>/dev/null | pem_lines)"
  if [[ -z "$got" || "$got" != "$(pem_lines <<<"$live")" ]]; then
    echo "ConfigMap envd-system/peer-root is absent or holds other roots than the live bundle of $RELAY_TARGET."
    echo "Run: CELL=$CELL_NAME mise run cell:up"
    return 1
  fi
  peer_root_pods_current envd-system envd peer-root "CELL=$CELL_NAME mise run cell:up" || return 1
}

# check_op_key_pinned succeeds when each key in ConfigMap cell-identity-system/mgmt-op-key is the live signing key of
# mgmtd (`mgmt -- pubkey`) or the key that mgmtd has staged for the next rotation (the SHA-256 of its bytes equals
# `stagedKey` in `mgmt -- status`), when the live key is among them, and when each running celld pod carries the
# checksum of the ConfigMap. celld trusts an operation signed by any key in the mount, and loads the mount only at start.
check_op_key_pinned() {
  local fix="CELL=$CELL_NAME mise run cell:up" live status staged cm name value fp sum got pods bad problems=() found=0
  live="$(cd "$ROOT" && mise run mgmt -- pubkey 2>/dev/null | jq -r '."spec.pub" // ""')" || live=""
  [[ -n "$live" ]] || { echo "mise run mgmt -- pubkey gave no key."; echo "Run: CELL=management LINK_ONLY=mgmt-api mise run cell:link"; return 1; }
  status="$(cd "$ROOT" && mise run mgmt -- status 2>/dev/null)" || status='{}'
  staged="$(jq -r '.stagedKey // ""' <<<"$status" 2>/dev/null)" || staged=""
  cm="$(k -n cell-identity-system get configmap mgmt-op-key -o json 2>/dev/null)" \
    || { echo "ConfigMap cell-identity-system/mgmt-op-key is absent."; echo "Run: $fix"; return 1; }
  while IFS=$'\t' read -r name value; do
    [[ -n "$name" ]] || continue
    fp="$(printf '%s' "$value" | base64 -d 2>/dev/null | shasum -a 256 | cut -d' ' -f1)"
    if [[ "$value" == "$live" ]]; then
      found=1
    elif [[ -n "$staged" && "$fp" == "$staged" ]]; then
      :
    else
      problems+=("mgmt-op-key holds $name = $value, which is neither the live key of mgmtd nor its staged key")
    fi
  done < <(jq -r '((.data // {}) + ((.binaryData // {}) | map_values(@base64d))) | to_entries[] | select(.key | endswith(".pub")) | [.key, .value] | @tsv' <<<"$cm")
  ((found == 1)) || problems+=("mgmt-op-key holds no key that equals the live key $live")
  sum="$(jq -r '.metadata.annotations["poc.internal/op-key-sha256"] // ""' <<<"$cm")"
  pods="$(k -n cell-identity-system get pods -l app.kubernetes.io/name=celld -o json)" || { echo "could not read the pods of celld"; return 1; }
  bad="$(jq -r --arg want "$sum" '.items[] | select(.metadata.deletionTimestamp == null)
    | (.metadata.annotations["poc.internal/op-key-sha256"] // "none") as $got | select($got != $want) | "\(.metadata.name) carries the key checksum \($got)"' <<<"$pods")"
  [[ -z "$bad" ]] || problems+=("$bad, and mgmt-op-key has $sum, which celld reads only at start")
  if ((${#problems[@]} > 0)); then
    printf '%s\n' "${problems[@]}"
    echo "Run: $fix"
    return 1
  fi
}

# check_registry_published <namespace> checks ConfigMap cell-registry of the namespace, which mgmtd publishes. It must carry
# only the label poc.internal/made-by=mgmtd, hold the record of each cell that mgmtd serves as compact JSON and no other
# record, and hold the live signing key of mgmtd in signers.pub. mgmtd checks the object again every minute, and writes it
# at once after a bind, so the check reads it again for up to REGISTRY_PUBLISHED_WAIT seconds (default 20) before it fails.
# A mismatch names the status of mgmtd and its log.
check_registry_published() {
  local ns="$1" wait="${REGISTRY_PUBLISHED_WAIT:-20}" end problem="" served cm key cell held pub signers
  local next="Run: mise run mgmt -- status, and read the log of mgmtd-0: kubectl --context kind-management -n mgmt-system logs mgmtd-0 -c mgmtd"
  end=$((SECONDS + wait))
  while :; do
    problem=""
    if ! served="$(cd "$ROOT" && mise run mgmt -- records 2>/dev/null)" || ! jq -e 'type == "object"' >/dev/null 2>&1 <<<"$served"; then
      echo "mise run mgmt -- records failed: ${served:-no output}"; echo "$next"; return 1
    fi
    if ! pub="$(mgmt_signing_pub)"; then
      echo "could not read the signing key of mgmtd"; echo "$next"; return 1
    fi
    if ! cm="$(k -n "$ns" get configmap cell-registry -o json 2>&1)"; then
      problem="could not read ConfigMap $ns/cell-registry: $cm"
    elif [[ "$(jq -c '.metadata.labels // {}' <<<"$cm")" != '{"poc.internal/made-by":"mgmtd"}' ]]; then
      problem="ConfigMap $ns/cell-registry has the labels $(jq -c '.metadata.labels // {}' <<<"$cm"), and mgmtd publishes only poc.internal/made-by=mgmtd"
    else
      # The trailing newline belongs to the value, and a command substitution would drop it.
      signers="$(jq -j '.data["signers.pub"] // ""' <<<"$cm"; echo x)"; signers="${signers%x}"
      [[ "$signers" == "$pub"$'\n' ]] || problem="signers.pub of $ns/cell-registry is '${signers%$'\n'}', and mgmtd signs with $pub"
      for cell in $(jq -r 'keys[]' <<<"$served"); do
        key="$cell.dsse.json"
        held="$(jq -c --arg k "$key" '.data[$k] | fromjson' <<<"$cm" 2>/dev/null)" || held=""
        [[ -n "$held" && "$held" == "$(jq -c --arg c "$cell" '.[$c]' <<<"$served")" ]] || problem+="${problem:+; }$cell has another record than mgmtd serves, or none"
      done
      for key in $(jq -r '.data // {} | keys[] | select(endswith(".dsse.json"))' <<<"$cm"); do
        jq -e --arg c "${key%.dsse.json}" 'has($c)' >/dev/null <<<"$served" || problem+="${problem:+; }$ns/cell-registry holds the record ${key%.dsse.json}, which mgmtd does not serve"
      done
    fi
    [[ -n "$problem" ]] || return 0
    if ((SECONDS >= end)); then
      echo "$problem"; echo "$next"; return 1
    fi
    sleep 2
  done
}

# The gateway checks. check_gateway_* need scripts/gw.sh and the functions of scripts/lib.sh and of this file. A
# mismatch prints the command of dependents_of that brings the gateway up to date.

# gateway_status prints the status that cellgw ctl status answers, or the reason on standard output and fails.
gateway_status() {
  local out
  out="$("$ROOT/scripts/gw.sh" status 2>/dev/null)" || { echo "mise run gw -- status failed: $out"; echo "Run: $(dependents_of gateway-nodes)"; return 1; }
  jq -e 'type == "object" and has("epoch")' <<<"$out" >/dev/null 2>&1 \
    || { echo "mise run gw -- status is no gateway status: $out"; echo "Run: $(dependents_of gateway-nodes)"; return 1; }
  printf '%s\n' "$out"
}

# check_gateway_synced succeeds when the store of the gateway reports no error, and envd synced with it within 2 minutes.
# envd syncs at each round, every 10 seconds.
# GATEWAY_SYNC_MAX_AGE is the age in seconds above which the sync of envd counts as late (2 minutes). harness:status uses the same value.
GATEWAY_SYNC_MAX_AGE=120
check_gateway_synced() {
  local status err synced age now
  status="$(gateway_status)" || { echo "$status"; return 1; }
  now="$(node_now)" || { echo "cannot read the time of the node dev-cp-control-plane, so the age of the sync is unknown. Run: docker ps"; return 1; }
  err="$(jq -r '.storeError // ""' <<<"$status")"
  if [[ -n "$err" ]]; then
    echo "the store of the gateway reports '$err'."
    echo "Run: $(dependents_of gateway-store)"
    return 1
  fi
  synced="$(jq -r '.syncedAt // ""' <<<"$status")"
  age="$(jq -n --argjson now "$now" --arg t "$synced" '($now - ($t | sub("\\.[0-9]+Z$"; "Z") | fromdateiso8601? // 0))')"
  if [[ -z "$synced" ]] || ((${age%.*} > GATEWAY_SYNC_MAX_AGE)); then
    echo "envd synced with the gateway at '${synced:-never}', which is more than 2 minutes ago."
    echo "Read the log of envd: mise x -- kubectl --context kind-$CELL_NAME -n envd-system logs deploy/envd -c envd. Then run: $(dependents_of gateway-nodes)"
    return 1
  fi
}

# check_gateway_cells succeeds when the gateway runs a --cell-node argument for each live cell with its current node address,
# and for no other cell. check_admit_lists compares the ingress rules of flows N37 and N38. Docker can give a node a new address.
check_gateway_cells() {
  local live cell want arg args problems=()
  live="$(live_cells)" || { echo "$live"; return 1; }
  args="$(k -n gateway-system get statefulset cell-gateway -o json \
    | jq -r '[.spec.template.spec.containers[] | select(.name == "cellgw") | .args[] | select(startswith("--cell-node="))] | .[]')" \
    || { echo "could not read statefulset/cell-gateway"; return 1; }
  for cell in $live; do
    want="$(node_ip "$cell")" || { echo "$want"; return 1; }
    arg="$(grep -- "^--cell-node=$cell=" <<<"$args" || true)"
    [[ "$arg" == "--cell-node=$cell=$want" ]] || problems+=("the node of $cell is $want, but the gateway runs '${arg:-no --cell-node}'")
  done
  for arg in $args; do
    cell="${arg#--cell-node=}"
    cell="${cell%%=*}"
    grep -qx -- "$cell" <<<"$live" || problems+=("the gateway runs $arg, and $cell has no cluster")
  done
  if ((${#problems[@]} > 0)); then
    printf '%s\n' "${problems[@]}"
    echo "After a rebuilt cell, run: $(dependents_of gateway-nodes)"
    echo "After a restart of the VM, rebuild the harness: mise run harness:down, then mise run harness:up"
    return 1
  fi
}

# check_gateway_records succeeds when the revision that the gateway holds for each live cell that has a record equals the revision of the record in
# ConfigMap cell-records, which envd verified under the key of mgmtd.
check_gateway_records() {
  local status cm cell have want cells problems=()
  status="$(gateway_status)" || { echo "$status"; return 1; }
  cm="$(k -n spire-system get configmap cell-records -o json)" || { echo "could not read ConfigMap spire-system/cell-records"; return 1; }
  cells="$(live_cells)" || { echo "$cells"; return 1; }
  for cell in $cells; do
    if ! jq -e --arg c "$cell" '.data[$c + ".dsse.json"] != null' <<<"$cm" >/dev/null; then
      # envd writes a record only for a bound cell, so a live cell with no record has not bound yet.
      echo "cell-records holds no record of $cell yet, so $cell has not bound"
      continue
    fi
    want="$(jq -r --arg c "$cell" '.data[$c + ".dsse.json"] | fromjson | .payload' <<<"$cm" | base64 -d | jq -c '[.epoch, .counter]')" \
      || { echo "could not read the record of $cell in cell-records"; return 1; }
    have="$(jq -c --arg c "$cell" '.records[$c] // null | if . == null then null else [.epoch, .counter] end' <<<"$status")"
    [[ "$have" == "$want" ]] || problems+=("the gateway holds the record revision $have of $cell, and cell-records holds $want")
  done
  if ((${#problems[@]} > 0)); then
    printf '%s\n' "${problems[@]}"
    echo "Read the log of envd: mise x -- kubectl --context kind-$CELL_NAME -n envd-system logs deploy/envd -c envd. If the store of the gateway is lost or corrupt, run: $(dependents_of gateway-store)"
    return 1
  fi
}

# check_celld_streams succeeds when the gateway holds at least one open stream for each live cell. celld opens one stream when it starts, and again at each new SVID.
check_celld_streams() {
  local status cells cell n problems=()
  status="$(gateway_status)" || { echo "$status"; return 1; }
  cells="$(live_cells)" || { echo "$cells"; return 1; }
  for cell in $cells; do
    n="$(jq -r --arg c "$cell" '.streams[$c] // 0' <<<"$status")"
    ((n >= 1)) || problems+=("the gateway holds no stream of $cell. Run: CELL=$cell mise run cell:up")
  done
  if ((${#problems[@]} > 0)); then
    printf '%s\n' "${problems[@]}"
    return 1
  fi
}

# check_gateway_spec_key succeeds when the gateway pins the key that mgmtd signs with: ConfigMap mgmt-spec-key of
# gateway-system, and the pod template checksum that follows it.
check_gateway_spec_key() {
  local live stored sum got
  live="$(mgmt_signing_pub 2>&1)" || { echo "$live"; return 1; }
  stored="$(k -n gateway-system get configmap mgmt-spec-key -o jsonpath='{.data.spec\.pub}')" || { echo "could not read ConfigMap gateway-system/mgmt-spec-key"; return 1; }
  sum="$(printf '%s' "$live" | shasum -a 256 | cut -d' ' -f1)"
  got="$(k -n gateway-system get statefulset cell-gateway -o jsonpath='{.spec.template.metadata.annotations.poc\.internal/spec-key-sha256}')" \
    || { echo "could not read statefulset/cell-gateway"; return 1; }
  if [[ "$stored" != "$live" || "$got" != "$sum" ]]; then
    echo "mgmt-signing-pub holds $live, mgmt-spec-key of the gateway holds '$stored', and the pod template carries '$got'."
    echo "Run: $(dependents_of gateway-nodes)"
    return 1
  fi
}

# The cell controller copies the certificate of the host service and the address of the host service, and pins the keys of
# mgmtd. Each can fall behind a restart of the host service, a rebuild or a rotation, so a check reads the copy and the
# pod that uses it. A mismatch prints the render of the cell controller alone, which reads all four again.
cell_controller_fix="CELL=dev-cp HARNESS_ONLY=cell-controller mise run cell:up"

# check_cell_controller_pin succeeds when ConfigMap cell-controller-system/hostsvc-pin holds the certificate that the host
# service presents, and every running pod of the cell controller carries its SHA-256 in the annotation
# poc.internal/hostsvc-pin-sha256. The process reads the pin once at start.
check_cell_controller_pin() {
  local live got status want pods bad
  live="$("$(hostsvc_serve_script)" pin 2>&1)" || { echo "$live"; echo "Run: mise run hostsvc:serve -- start"; return 1; }
  got="$(k -n cell-controller-system get configmap hostsvc-pin -o jsonpath='{.data.hostsvc\.crt}')" \
    || { echo "could not read ConfigMap cell-controller-system/hostsvc-pin"; return 1; }
  if [[ "$(pem_lines <<<"$got")" != "$(pem_lines <<<"$live")" ]]; then
    echo "ConfigMap cell-controller-system/hostsvc-pin holds another certificate than the host service presents."
    echo "Run: $cell_controller_fix"
    return 1
  fi
  status="$("$(hostsvc_serve_script)" status)" || return 1
  want="$(jq -r '.cert_sha256' <<<"$status")"
  pods="$(k -n cell-controller-system get pods -l app.kubernetes.io/name=cell-controller -o json)" \
    || { echo "could not read the pods of cell-controller in cell-controller-system"; return 1; }
  if [[ "$(jq -r '[.items[] | select(.metadata.deletionTimestamp == null)] | length' <<<"$pods")" == 0 ]]; then
    echo "cell-controller has no running pod in cell-controller-system."
    echo "Run: $cell_controller_fix"
    return 1
  fi
  bad="$(jq -r --arg want "$want" '.items[] | select(.metadata.deletionTimestamp == null)
    | ((.metadata.annotations["poc.internal/hostsvc-pin-sha256"] // "none")) as $got | select($got != $want)
    | "\(.metadata.name) carries the pin digest \($got)"' <<<"$pods")"
  if [[ -n "$bad" ]]; then
    printf '%s\n' "$bad"
    echo "The host service presents $want, and a pod reads the pin only at start."
    echo "Run: $cell_controller_fix"
    return 1
  fi
}

# check_cell_controller_key succeeds when the cell controller pins the keys that mgmtd signs with: ConfigMap mgmt-spec-key holds
# spec.pub equal to the answer of `mise run mgmt -- pubkey` and, while mgmtd stages a key, next.pub equal to stagedKey, and holds
# no next.pub otherwise. The pod template checksum must follow both files. mgmt_signing_pub and mgmt_signing_next_pub make the two
# comparisons with mgmtd.
check_cell_controller_key() {
  local live next stored stored_next sum got
  live="$(mgmt_signing_pub 2>&1)" || { echo "$live"; return 1; }
  next="$(mgmt_signing_next_pub 2>&1)" || { echo "$next"; return 1; }
  stored="$(k -n cell-controller-system get configmap mgmt-spec-key -o jsonpath='{.data.spec\.pub}')" \
    || { echo "could not read ConfigMap cell-controller-system/mgmt-spec-key"; return 1; }
  stored_next="$(k -n cell-controller-system get configmap mgmt-spec-key -o jsonpath='{.data.next\.pub}')" \
    || { echo "could not read ConfigMap cell-controller-system/mgmt-spec-key"; return 1; }
  sum="$(printf '%s' "$live${next:+$'\n'$next}" | shasum -a 256 | cut -d' ' -f1)"
  got="$(k -n cell-controller-system get deployment cell-controller -o jsonpath='{.spec.template.metadata.annotations.poc\.internal/spec-key-sha256}')" \
    || { echo "could not read deployment/cell-controller"; return 1; }
  if [[ "$stored" != "$live" || "$stored_next" != "$next" || "$got" != "$sum" ]]; then
    echo "mgmtd signs with '$live' and stages '${next:-none}', mgmt-spec-key of the cell controller holds '$stored' and '${stored_next:-none}', and the pod template carries '$got'."
    echo "Run: $cell_controller_fix"
    return 1
  fi
}

# check_cell_steps_current succeeds when envd wrote ConfigMap cell-controller-system/cell-steps for the spec that mgmtd signed last,
# with the label poc.internal/made-by=envd. A test that patches the ConfigMap, as a compromised dev-cp could, makes this check fail until
# envd writes its next change.
check_cell_steps_current() { configmap_applied_spec cell-controller-system cell-steps envd; }

# check_cell_controller_address succeeds when the egress rule of flow N42 admits the one address that host.docker.internal has in the
# node container, on HOSTSVC_PORT only (a rule with another port beside it does not count), and the pod runs --hostsvc-addr with the same address. Docker can give the name another
# address after vm:up.
check_cell_controller_address() {
  local want got arg
  want="$(hostsvc_address "$CELL_NAME" 2>&1)" || { echo "$want"; return 1; }
  got="$(k -n cell-controller-system get networkpolicy cell-controller -o json \
    | jq -r --argjson p "$HOSTSVC_PORT" '[.spec.egress[] | select(any(.ports[]; .port == $p)) | select((.ports | length) == 1) | .to[].ipBlock.cidr] | join(" ")')" \
    || { echo "could not read NetworkPolicy cell-controller-system/cell-controller"; return 1; }
  arg="$(k -n cell-controller-system get deployment cell-controller -o json \
    | jq -r '.spec.template.spec.containers[] | select(.name == "cell-controller") | .args[] | select(startswith("--hostsvc-addr="))')" \
    || { echo "could not read deployment/cell-controller"; return 1; }
  if [[ "$got" != "$want/32" || "$arg" != "--hostsvc-addr=$want:$HOSTSVC_PORT" ]]; then
    echo "host.docker.internal is $want in the node, but the policy admits '$got' and the cell controller runs '$arg'."
    echo "Run: $cell_controller_fix"
    return 1
  fi
}

# The checks of the signed bundle sets. A cluster with the bundle role cell or cp runs all five, and a cluster with the role open (management) runs
# only check_store_proxy, because it has no writer and no set. They need scripts/lib.sh.

# bundle_allow_json prints the path of the allow-list data. BUNDLE_ALLOW_JSON names another file, for the tests.
bundle_allow_json() { printf '%s\n' "${BUNDLE_ALLOW_JSON:-$ROOT/internal/bundle/allow.json}"; }

# check_signed_root succeeds when cosign verifies, on this Mac and offline, that mgmtd signed the root that the bundle state of the cluster records
# (mise run bundle -- verify). A bootstrap state has no signed root.
check_signed_root() {
  local out reason
  if ! out="$(cd "$ROOT" && mise run bundle -- verify --target "$CELL_NAME" 2>&1)"; then
    reason="$(grep '^error:' <<<"$out" | tail -n 1 || true)"
    reason="${reason:-$(tail -n 1 <<<"$out")}"
    printf '%s\n' "$reason"
    # A new set fixes a bootstrap state or a missing state. A root that fails cosign says its own command (after a key rotation, bundle -- cosign), and a
    # mirror or mgmtd that does not answer needs the harness first: a publish needs both.
    if [[ "$reason" == *"bootstrap root"* || "$reason" == *"no bundle state"* || "$reason" == *"no root digest"* ]]; then
      echo "Run: mise run bundle -- publish --target $CELL_NAME --wait"
    elif [[ "$reason" != *"cosign"* ]]; then
      echo "Run: mise run harness:status"
    fi
    return 1
  fi
}

# check_bundle_guard succeeds when the admission policies that keep Argo CD away from the harness equal the render of components/lib/bundle-guard.sh
# for the role: bundles-spare-harness and its binding in a cell and in dev-cp, and bundles-app-limits and its binding in a cell.
check_bundle_guard() {
  local role docs names comp out rc doc kind name resource live problems
  role="$(bundle_role)" || return 1
  case "$role" in
    cell) names="bundles-spare-harness and bundles-app-limits" comp=cell-identity ;;
    cp) names="bundles-spare-harness" comp=envd ;;
    *) echo "$CELL_NAME has role $role, so it has no bundle guard"; return 1 ;;
  esac
  docs="$("$ROOT/components/lib/bundle-guard.sh" "$role" 2>&1)" || { echo "could not render the guards of role $role: $docs"; return 1; }
  # The harness apply puts the label of the component on each object, so the render needs it too, or the diff would remove it.
  docs="$(COMP="$comp" yq '.metadata.labels["cell.poc.internal/harness"] = strenv(COMP)' <<<"$docs")" || { echo "could not label the guards of role $role"; return 1; }
  rc=0
  out="$(k diff --server-side --force-conflicts -f - <<<"$docs" 2>&1)" || rc=$?
  case "$rc" in
    0) ;;
    1)
      printf '%s\n' "$out" | head -n 40
      echo "The guards $names of $CELL_NAME differ from the render of components/lib/bundle-guard.sh $role."
      echo "Run: CELL=$CELL_NAME mise run cell:up"
      return 1 ;;
    *) echo "kubectl diff failed: $out"; return 1 ;;
  esac
  # The diff shows a field of the render that differs, and not a field that another manager added. So read each live object too: its match conditions,
  # its validations and its rules must equal the render, and its binding may carry no selector, parameter or extra rule that narrows the guard.
  problems=()
  while IFS= read -r doc; do
    [[ -n "$doc" && "$doc" != --- ]] || continue
    kind="$(jq -r .kind <<<"$doc")" name="$(jq -r .metadata.name <<<"$doc")"
    case "$kind" in
      ValidatingAdmissionPolicy) resource=validatingadmissionpolicy ;;
      ValidatingAdmissionPolicyBinding) resource=validatingadmissionpolicybinding ;;
      *) continue ;;
    esac
    if ! live="$(k get "$resource" "$name" -o json 2>&1)"; then
      problems+=("cannot read $kind $name: $live")
      continue
    fi
    jq -e --argjson r "$doc" '
      def rules: [.spec.matchConstraints.resourceRules[]? | {apiGroups, operations, resources}];
      def checks: [.spec.validations[]? | {expression, message}];
      if .kind == "ValidatingAdmissionPolicy" then
        (.spec.matchConditions // []) == ($r.spec.matchConditions // []) and checks == ($r | checks) and rules == ($r | rules)
        and ((.spec.matchConstraints.namespaceSelector // {}) == {} and (.spec.matchConstraints.objectSelector // {}) == {} and (.spec.matchConstraints.excludeResourceRules // []) == [])
      else
        .spec.policyName == $r.spec.policyName and .spec.validationActions == $r.spec.validationActions and (.spec.paramRef // null) == null
        and ((.spec.matchResources // {}) | (.namespaceSelector // {}) == {} and (.objectSelector // {}) == {} and (.resourceRules // []) == [] and (.excludeResourceRules // []) == [])
      end' >/dev/null <<<"$live" || problems+=("$kind $name differs from the render, or narrows its match (a selector, a parameter, an extra condition or another rule)")
  done <<<"$("$ROOT/components/lib/bundle-guard.sh" "$role")"
  if ((${#problems[@]} > 0)); then
    printf '%s\n' "${problems[@]}"
    echo "Run: CELL=$CELL_NAME mise run cell:up"
    return 1
  fi
}

# check_store_proxy succeeds when the proxy in front of the bundle store admits the one writer of the role and the reader that Argo CD uses (the
# token client of the repo server), with the audience bundle-store. A cluster with no writer (role open) lists none.
check_store_proxy() {
  local role want sts repo problems
  role="$(bundle_role)" || return 1
  want="$(bundle_store_writer_of "$role")" || return 1
  sts="$(k -n cell-system get statefulset/bundle-store -o json)" || { echo "could not read statefulset/bundle-store in cell-system"; return 1; }
  problems="$(jq -r --arg want "${want:+--writer=$want}" --arg cluster "$CELL_NAME" '
    [.spec.template.spec.containers[] | select(.name == "store-proxy")] as $c
    | if ($c | length) != 1 then "statefulset/bundle-store has no container store-proxy"
      else ($c[0].args // []) as $a
        | ([$a[] | select(startswith("--writer="))]) as $w
        | (if ($a | index("--audience=bundle-store")) == null then "store-proxy lacks --audience=bundle-store" else empty end),
          (if ($a | index("--reader=system:serviceaccount:argocd:argocd-repo-server")) == null then "store-proxy lacks --reader=system:serviceaccount:argocd:argocd-repo-server" else empty end),
          (if $want == "" then (if ($w | length) > 0 then "\($cluster) has no bundle writer, but store-proxy admits \($w | join(" "))" else empty end)
           elif $w != [$want] then "store-proxy admits the writers \(if ($w | length) == 0 then "none" else $w | join(" ") end), want \($want)" else empty end)
      end' <<<"$sts")" || { echo "could not read the arguments of store-proxy"; return 1; }
  repo="$(k -n argocd get deployment/argocd-repo-server -o json)" || { echo "could not read deployment/argocd-repo-server in argocd"; return 1; }
  jq -e --arg up "--upstream=$BUNDLE_STORE_SERVICE" 'any(.spec.template.spec.containers[]; .name == "store-token" and ((.args // []) | index($up)) != null)' >/dev/null <<<"$repo" \
    || problems+="${problems:+$'\n'}deployment/argocd-repo-server has no container store-token with --upstream=$BUNDLE_STORE_SERVICE"
  if [[ -n "$problems" ]]; then
    printf '%s\n' "$problems"
    echo "Run: CELL=$CELL_NAME mise run cell:up"
    return 1
  fi
}

# check_plane_policies succeeds when each harness plane policy that the allow list names for the role exists with the label
# cell.poc.internal/harness. The apply engine spares these policies, so a missing one is not restored by a bundle.
check_plane_policies() {
  local role ns name json problems=()
  role="$(bundle_role)" || return 1
  while read -r ns name; do
    [[ -n "$name" ]] || continue
    if ! json="$(k -n "$ns" get networkpolicy "$name" -o json 2>/dev/null)"; then
      problems+=("NetworkPolicy $ns/$name is absent")
    elif ! jq -e '(.metadata.labels["cell.poc.internal/harness"] // "") != ""' >/dev/null <<<"$json"; then
      problems+=("NetworkPolicy $ns/$name has no label cell.poc.internal/harness")
    fi
  done < <(jq -r --arg role "$role" '.roles[$role].planePolicies[]? | "\(.namespace) \(.name)"' "$(bundle_allow_json)")
  if ((${#problems[@]} > 0)); then
    printf '%s\n' "${problems[@]}"
    echo "Run: CELL=$CELL_NAME mise run cell:up"
    return 1
  fi
}

# check_allow_list_version succeeds when the allow-list digest that the applier of the cluster reports to mgmtd (allowSHA256 of mise run mgmt -- status)
# equals the annotation poc.internal/allow-sha256 of each AppProject of the role, so the project limits and the engine read one list.
check_allow_list_version() {
  local role st reported name ann problems=()
  role="$(bundle_role)" || return 1
  st="$(CELL=management mise run mgmt -- status 2>/dev/null)" || { echo "could not read mise run mgmt -- status. Run: CELL=management LINK_ONLY=mgmt-api mise run cell:link"; return 1; }
  case "$role" in
    cell) reported="$(jq -r --arg c "$CELL_NAME" '[.cells[]? | select(.name == $c) | .bundleStatus.allowSHA256 // empty][0] // ""' <<<"$st")" ;;
    cp) reported="$(jq -r '.planeBundleStatus.allowSHA256 // ""' <<<"$st")" ;;
    *) echo "$CELL_NAME has role $role, so it has no allow list"; return 1 ;;
  esac || { echo "mise run mgmt -- status printed no JSON object"; return 1; }
  if [[ -z "$reported" ]]; then
    echo "mgmtd holds no allowSHA256 for $CELL_NAME, so its applier has not reported a bundle state."
    echo "Run: mise run bundle -- publish --target $CELL_NAME --wait"
    return 1
  fi
  for name in $(jq -r --arg role "$role" '.roles[$role].appProjects[]?' "$(bundle_allow_json)"); do
    ann="$(k -n argocd get appproject "$name" -o jsonpath='{.metadata.annotations.poc\.internal/allow-sha256}')" \
      || { echo "could not read AppProject $name in argocd"; return 1; }
    if [[ -z "$ann" ]]; then
      problems+=("AppProject $name has no annotation poc.internal/allow-sha256, and the applier of $CELL_NAME reports allowSHA256 $reported")
    elif [[ "$ann" != "$reported" ]]; then
      problems+=("AppProject $name carries allowSHA256 $ann, and the applier of $CELL_NAME reports allowSHA256 $reported")
    fi
  done
  if ((${#problems[@]} > 0)); then
    printf '%s\n' "${problems[@]}"
    echo "Run: mise run bundle -- publish --target $CELL_NAME --wait"
    echo "If the images of celld and envd are older than this checkout, run first: mise run images -- celld envd, then CELL=$CELL_NAME mise run cell:hydrate"
    return 1
  fi
}
