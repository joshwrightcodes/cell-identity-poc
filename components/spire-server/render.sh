#!/usr/bin/env bash
# Render the SPIRE server of one trust domain.
#
# Two attestation paths feed the server. Each loads only when its inputs are set.
#   - cluster_jwt, for the SPIRE agent sidecars in cells: SPIRE_AGENT_CELLS (the catalog of cells) and
#     SPIRE_CELL_SUBJECTS. The render keeps the cluster_jwt section while a cell of the catalog is live (live_cells in
#     components/lib/live-cells.sh), and checks the node of each live cell for traces of the M2 key rotation test. The harness
#     plane policy spire-system/plane-cells, which the envd render prints, admits the node addresses of the live cells on the
#     node port. With no live cell, the render drops the cluster_jwt section and keeps the entries. The plugin trusts only records that the
#     management plane signs: record_public_keys holds the public key of mgmtd, from ConfigMap
#     mgmt-signing-pub in management (components/lib/mgmt-key.sh). envd writes the signed records into
#     ConfigMap spire-system/cell-records, which the pod mounts as an optional volume, and the plugin
#     reloads them while the server runs. ConfigMap spire-entries gets two
#     ClusterStaticEntry manifests for each subject of each cell: a node alias
#     spiffe://<td>/cell/<cell>/agents/<role> that matches only the attested agents of that cell and
#     ServiceAccount, and the ID spiffe://<td>/cell/<cell>/<role> under that alias, for each cell of the
#     catalog, live or not. So the agent of one subject gets no entry of another subject. The plugin image is the one that
#     `mise run images` built on this Mac, pinned by the digest in build/images.env. The server
#     config carries the SHA-256 of the plugin binary from that image, so the server checks the
#     binary before it runs it.
#   - k8s_psat, for the plane workloads of this cluster: SPIRE_LOCAL_WORKLOADS, a list of
#     <spiffe path>=<namespace>/<service account>. Each workload gets a node alias
#     spiffe://<td>/agents/<namespace>/<service account> that matches only its own agent sidecars,
#     and its ID under that alias. The server gets an API token and a ClusterRole for TokenReview
#     and the pod and node reads. Each workload pod reaches the server API through the ClusterIP of
#     Service spire-server, and carries the label app.kubernetes.io/name=<service account>.
#   - Key hints: the cluster_jwt plugin patches ConfigMap spire-system/attest-hints on unknown_kid (hint_configmap in
#     server.conf). It reaches the API through the same token as k8s_psat, so the hint line and Role spire-server-hints
#     stay only when the cluster has both agent cells and local workloads.
# In a cluster with the bundle role cp (components/lib/bundle-role.sh), the ingress of every local workload to the server API
# is a harness plane policy that the envd render prints (spire-system/plane-envd and spire-system/plane-workloads), so the
# bundle has no workload policy. The workloads keep their aliases and entries.
# SPIRE_UPSTREAM=disk signs the server CA with the intermediate CA from Secret spire-upstream, and
# the CA keys stay in memory. Without it, the CA is a self-signed root, and its key lives on the
# data volume, so a restart keeps the root.
# Inputs come from cells/<cluster>.env: SPIRE_TRUST_DOMAIN, SPIRE_SVID_TTL, SPIRE_CA_TTL (default
# 24h), SPIRE_UPSTREAM, SPIRE_AGENT_CELLS, SPIRE_CELL_SUBJECTS and SPIRE_LOCAL_WORKLOADS. POC_ENV
# comes from cells/common.env, CELL_NAME names the cluster whose bundle role decides the workload policy, and the API server facts from build/<cluster>/facts.env. The
# external-secrets bundle holds Namespace spire-system when it is the namespace of the operator,
# EXTERNAL_SECRETS_NAMESPACE or SECRET_STORE_NAMESPACES. hydrate replaces @CELL_NAME@, the cluster
# name of the k8s_psat config.
set -euo pipefail
: "${SPIRE_TRUST_DOMAIN:?}" "${SPIRE_SVID_TTL:?}" "${POC_ENV:?}" "${CELL_NAME:?}"

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
namespace=spire-system
plugin_binary=/ko-app/cluster-jwt-server
# Every ko image runs as this user, the nonroot user of the distroless base image in .ko.yaml.
workload_uid=65532

die() { printf 'error: spire-server render: %s\n' "$*" >&2; exit 1; }

source "$root/scripts/ko-image.sh"
source "$root/scripts/gate-traces.sh"
source "$root/components/lib/addresses.sh"
source "$root/components/lib/mgmt-key.sh"
source "$root/components/lib/live-cells.sh"
source "$root/components/lib/bundle-role.sh"

# seconds <duration> prints a duration of the form <n>s, <n>m or <n>h in seconds.
seconds() {
  local n="${1%[smh]}"
  case "$1" in
    *s) echo "$n" ;;
    *m) echo $((n * 60)) ;;
    *h) echo $((n * 3600)) ;;
  esac
}

td="$SPIRE_TRUST_DOMAIN"
[[ "$td" =~ ^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$ ]] || die "SPIRE_TRUST_DOMAIN '$td' is not a trust domain name"
[[ "$POC_ENV" =~ ^[a-z0-9][a-z0-9-]{0,30}$ ]] || die "POC_ENV '$POC_ENV' is not a short DNS label"

# SPIRE_SVID_TTL sets agent_ttl and default_x509_svid_ttl. The M2 tests verified renewal at 1m, so
# that is the floor. SPIRE warns when an SVID lifetime exceeds ca_ttl / 6. The JWT SVID lifetime
# keeps its default of 5m, so the same rule needs ca_ttl of 30m or more.
[[ "$SPIRE_SVID_TTL" =~ ^[1-9][0-9]*[smh]$ ]] && (($(seconds "$SPIRE_SVID_TTL") >= 60)) \
  || die "SPIRE_SVID_TTL '$SPIRE_SVID_TTL' is not a lifetime of 1m or more, such as 1m or 1h"
ca_ttl="${SPIRE_CA_TTL:-24h}"
[[ "$ca_ttl" =~ ^[1-9][0-9]*[smh]$ ]] || die "SPIRE_CA_TTL '$ca_ttl' is not a lifetime of the form <n>s, <n>m or <n>h, such as 24h"
ca_seconds="$(seconds "$ca_ttl")"
(($(seconds "$SPIRE_SVID_TTL") * 6 <= ca_seconds)) || die "SPIRE_SVID_TTL $SPIRE_SVID_TTL is above ca_ttl / 6 for ca_ttl $ca_ttl"
((300 * 6 <= ca_seconds)) || die "ca_ttl $ca_ttl is below 30m, the floor for the default JWT SVID lifetime of 5m"

upstream="${SPIRE_UPSTREAM:-}"
[[ -z "$upstream" || "$upstream" == disk ]] || die "SPIRE_UPSTREAM '$upstream' is not disk, and not unset"
read -r -a cells <<<"${SPIRE_AGENT_CELLS:-}"
read -r -a subjects <<<"${SPIRE_CELL_SUBJECTS:-}"
read -r -a local_workloads <<<"${SPIRE_LOCAL_WORKLOADS:-}"
if (((${#cells[@]} > 0) != (${#subjects[@]} > 0))); then
  die "SPIRE_AGENT_CELLS and SPIRE_CELL_SUBJECTS must both be set or both be unset, got '${SPIRE_AGENT_CELLS:-}' and '${SPIRE_CELL_SUBJECTS:-}'"
fi
((${#cells[@]} > 0 || ${#local_workloads[@]} > 0)) || die "cells/<cluster>.env names no agent cell and no local workload, so no agent can attest"

# The config sections to keep, from server.conf.
sections=()
if [[ "$upstream" == disk ]]; then sections+=(keys_memory upstream_disk); else sections+=(keys_disk); fi

entries='{}'
mgmt_pub=""
plugin_image=""
checksum=""
live=()
if ((${#cells[@]} > 0)); then
  # Each subject is <namespace>/<service account>=<role>. A role and a ServiceAccount may appear once.
  seen_roles=" " seen_accounts=" "
  for subject in "${subjects[@]}"; do
    [[ "$subject" =~ ^[a-z0-9-]+/[a-z0-9-]+=[a-z0-9-]+$ ]] || die "SPIRE_CELL_SUBJECTS entry '$subject' is not <namespace>/<service account>=<role>"
    [[ ! "${subject#*=}" =~ ^agents(-|$) ]] || die "the role ${subject#*=} of SPIRE_CELL_SUBJECTS is the path of the node aliases, or names an alias entry"
    [[ "$seen_roles" != *" ${subject#*=} "* ]] || die "SPIRE_CELL_SUBJECTS names the role ${subject#*=} twice"
    [[ "$seen_accounts" != *" ${subject%%=*} "* ]] || die "SPIRE_CELL_SUBJECTS names the ServiceAccount ${subject%%=*} twice"
    seen_roles+="${subject#*=} " seen_accounts+="${subject%%=*} "
  done

  # The entries of every cell of the catalog stay, whether its cluster exists or not.
  for cell in "${cells[@]}"; do
    # The cluster_jwt plugin gives an attested agent the selectors cluster_jwt:cell:<cell> and
    # cluster_jwt:sa:<namespace>:<service account>. Each alias matches both, for one subject. The
    # role entry selects the uid of the ko images.
    for subject in "${subjects[@]}"; do
      subject_sa="${subject%%=*}" role="${subject#*=}"
      alias_id="spiffe://$td/cell/$cell/agents/$role"
      entries="$(jq -c --arg cell "$cell" --arg td "$td" --arg alias "$alias_id" --arg sa "${subject_sa/\//:}" --arg role "$role" --arg uid "$workload_uid" '
        . + {
          ($cell + "-agents-" + $role + ".yaml"): {apiVersion: "spire.spiffe.io/v1alpha1", kind: "ClusterStaticEntry",
            metadata: {name: ($cell + "-agents-" + $role)},
            spec: {spiffeID: $alias, parentID: ("spiffe://" + $td + "/spire/server"),
              selectors: ["cluster_jwt:cell:" + $cell, "cluster_jwt:sa:" + $sa]}},
          ($cell + "-" + $role + ".yaml"): {apiVersion: "spire.spiffe.io/v1alpha1", kind: "ClusterStaticEntry",
            metadata: {name: ($cell + "-" + $role)},
            spec: {spiffeID: ("spiffe://" + $td + "/cell/" + $cell + "/" + $role), parentID: $alias,
              selectors: ["unix:uid:" + $uid]}}
        }' <<<"$entries")"
    done
  done

  # Only a live cell attests, so the cluster_jwt section follows the live cells of the catalog.
  live_all="$(live_cells)" || die "could not list the live cells"
  for cell in $live_all; do
    [[ " ${cells[*]} " != *" $cell "* ]] || live+=("$cell")
  done
fi
if ((${#live[@]} > 0)); then
  sections+=(cluster_jwt)
  mgmt_pub="$(mgmt_signing_pub)" || exit 1

  # The plugin image and the checksum of the binary in it.
  plugin_image="$(ko_image cluster-jwt-server)" || die "no plugin image"
  checksum="$(ko_binary_sha256 "$plugin_image" "$plugin_binary")" || die "no plugin checksum"

  for cell in "${live[@]}"; do
    # While the M2 key rotation test has changed the cell, its API server publishes the test key, so
    # the render stops until the node is repaired.
    traces="$(keytest_leftover "$cell")" || die "cannot check the node of $cell for the M2 key rotation test: $traces. Run: mise run gate:m2:repair"
    [[ -z "$traces" ]] || die "the node of $cell holds traces of the M2 key rotation test: ${traces//$'\n'/; }. Run: mise run gate:m2:repair"
  done
fi

psat_accounts='[]'
workload_peers='[]'
api_peers='[]'
if ((${#local_workloads[@]} > 0)); then
  sections+=(k8s_psat)
  : "${API_SERVER_IPS:?}" "${API_SERVER_PORT:?}" "${API_SERVICE_IP:?}"
  seen=" "
  for w in "${local_workloads[@]}"; do
    [[ "$w" =~ ^([a-z0-9-]+(/[a-z0-9-]+)*)=([a-z0-9-]+)/([a-z0-9-]+)$ ]] \
      || die "SPIRE_LOCAL_WORKLOADS entry '$w' is not <spiffe path>=<namespace>/<service account>"
    path="${BASH_REMATCH[1]}" wns="${BASH_REMATCH[3]}" wsa="${BASH_REMATCH[4]}"
    case "$path" in
      spire | spire/* | cell | cell/* | agents | agents/*) die "the SPIFFE path $path of SPIRE_LOCAL_WORKLOADS is reserved for agents and cells" ;;
    esac
    [[ "$seen" != *" ${path//\//-} "* ]] || die "SPIRE_LOCAL_WORKLOADS names $path twice"
    seen+="${path//\//-} "
    # The k8s_psat plugin gives an agent the selectors k8s_psat:cluster:<cluster>,
    # k8s_psat:agent_ns:<namespace> and k8s_psat:agent_sa:<service account>, with others that the
    # alias does not need.
    alias_id="spiffe://$td/agents/$wns/$wsa"
    entries="$(jq -c --arg td "$td" --arg alias "$alias_id" --arg ns "$wns" --arg sa "$wsa" --arg path "$path" --arg uid "$workload_uid" '
      ("agents-" + $ns + "-" + $sa) as $alias_name | ("workload-" + ($path | gsub("/"; "-"))) as $entry_name |
      . + {
        ($alias_name + ".yaml"): {apiVersion: "spire.spiffe.io/v1alpha1", kind: "ClusterStaticEntry",
          metadata: {name: $alias_name},
          spec: {spiffeID: $alias, parentID: ("spiffe://" + $td + "/spire/server"),
            selectors: ["k8s_psat:cluster:@CELL_NAME@", "k8s_psat:agent_ns:" + $ns, "k8s_psat:agent_sa:" + $sa]}},
        ($entry_name + ".yaml"): {apiVersion: "spire.spiffe.io/v1alpha1", kind: "ClusterStaticEntry",
          metadata: {name: $entry_name},
          spec: {spiffeID: ("spiffe://" + $td + "/" + $path), parentID: $alias, selectors: ["unix:uid:" + $uid]}}
      }' <<<"$entries")"
    psat_accounts="$(jq -c --arg a "$wns:$wsa" '. + [$a] | unique' <<<"$psat_accounts")"
    workload_peers="$(jq -c --arg ns "$wns" --arg sa "$wsa" '. + [{
      namespaceSelector: {matchLabels: {"kubernetes.io/metadata.name": $ns}},
      podSelector: {matchLabels: {"app.kubernetes.io/name": $sa}}}] | unique' <<<"$workload_peers")"
  done
  ipv4='^([0-9]{1,3}\.){3}[0-9]{1,3}$'
  api_ips="$(ipv4_list API_SERVER_IPS)" || exit 1
  api_peers="$(for ip in $api_ips; do printf '{"ipBlock":{"cidr":"%s/32"}}\n' "$ip"; done | jq -cs .)"
  [[ "$API_SERVER_PORT" =~ ^[0-9]+$ ]] || die "API_SERVER_PORT '$API_SERVER_PORT' is not a port number"
  [[ "$API_SERVICE_IP" =~ $ipv4 ]] || die "API_SERVICE_IP '$API_SERVICE_IP' is not an IPv4 address"
fi

key_list="[]"
[[ -z "$mgmt_pub" ]] || key_list="[\"$mgmt_pub\"]"
account_list="$(jq -r 'map("\"" + . + "\"") | "[" + join(", ") + "]"' <<<"$psat_accounts")"
# Each section of server.conf starts with "# section: <name>" and ends with "# end: <name>". The
# render keeps the sections of this cluster without their marker lines.
server_conf="$(awk -v keep=" ${sections[*]} " '
    /^ *# section: / { drop = index(keep, " " $3 " ") == 0; next }
    /^ *# end: / { drop = 0; next }
    !drop' "$here/server.conf" | cat -s \
  | sed -e "s|@SPIRE_TRUST_DOMAIN@|$td|g" -e "s|@SPIRE_CA_TTL@|$ca_ttl|" -e "s|@SPIRE_PLUGIN_CHECKSUM@|$checksum|" \
    -e "s|@SPIRE_RECORD_PUBLIC_KEYS@|$key_list|" -e "s|@SPIRE_PSAT_ACCOUNTS@|$account_list|" \
    -e "s|@SPIRE_SVID_TTL@|$SPIRE_SVID_TTL|g" -e "s|@POC_ENV@|$POC_ENV|g")"
if ((${#live[@]} == 0 || ${#local_workloads[@]} == 0)); then
  server_conf="$(sed -e '/^ *hint_configmap = /d' <<<"$server_conf")"
fi
controller_conf="$(sed -e "s|@SPIRE_TRUST_DOMAIN@|$td|" "$here/controller-manager.yaml")"

# config_map <name> <key> <content> prints a ConfigMap with one literal block value.
config_map() {
  NAME="$1" KEY="$2" VALUE="$3" NS="$namespace" yq -n '
    .apiVersion = "v1" | .kind = "ConfigMap" | .metadata.name = strenv(NAME) | .metadata.namespace = strenv(NS)
    | .data[strenv(KEY)] = strenv(VALUE) | .data[strenv(KEY)] style="literal"'
}
config_maps="$(config_map spire-server server.conf "$server_conf"; echo "---"; config_map spire-controller-manager config.yaml "$controller_conf")"
config_checksum="$(printf '%s' "$config_maps" | sha256)"

# The objects, containers and volumes that this cluster does not need.
drop_objects=()
drop_volumes=()
pod='select(.kind == "StatefulSet" and .metadata.name == "spire-server") | .spec.template.spec'
service='select(.kind == "Service" and .metadata.name == "spire-server") | .spec'
edits=""
if ((${#live[@]} == 0)); then
  drop_volumes+=(plugins records)
  edits+=" | del($pod.initContainers) | ($service.type) = \"ClusterIP\" | del($service.externalTrafficPolicy) | del($service.ports[].nodePort)"
fi
if [[ "$upstream" != disk ]]; then
  drop_objects+=("ExternalSecret/spire-upstream")
  drop_volumes+=(upstream)
fi
if ((${#local_workloads[@]} == 0)); then
  drop_objects+=("ClusterRole/spire-server-psat" "ClusterRoleBinding/spire-server-psat" "NetworkPolicy/spire-server-workloads" "NetworkPolicy/spire-server-api")
  drop_volumes+=(api-token)
fi
if ((${#live[@]} == 0 || ${#local_workloads[@]} == 0)); then
  drop_objects+=("Role/spire-server-hints" "RoleBinding/spire-server-hints")
fi
eso_namespace="${EXTERNAL_SECRETS_NAMESPACE:-${SECRET_STORE_NAMESPACES:-}}"
[[ "$eso_namespace" != "$namespace" ]] || drop_objects+=("Namespace/$namespace")
role="$(bundle_role_of "$CELL_NAME")" || die "could not read the bundle role of $CELL_NAME"
if [[ "$role" == cp ]]; then
  drop_objects+=("NetworkPolicy/spire-server-workloads")
fi
for v in ${drop_volumes[@]+"${drop_volumes[@]}"}; do
  edits+=" | del($pod.volumes[] | select(.name == \"$v\")) | del($pod.containers[].volumeMounts[] | select(.name == \"$v\"))"
done
keep_objects='select(.kind != null)'
for o in ${drop_objects[@]+"${drop_objects[@]}"}; do
  keep_objects+=" | select(.kind != \"${o%%/*}\" or .metadata.name != \"${o#*/}\")"
done

# Each entry becomes one YAML file in the ConfigMap, as spire-controller-manager expects.
ENTRIES="$entries" WORKLOAD_PEERS="$workload_peers" API_PEERS="$api_peers" API_PORT="${API_SERVER_PORT:-0}" yq "
  (select(.kind == \"NetworkPolicy\" and .metadata.name == \"spire-server-workloads\") | .spec.ingress[0].from) = (env(WORKLOAD_PEERS) | ... style=\"\")
  | (select(.kind == \"NetworkPolicy\" and .metadata.name == \"spire-server-api\") | .spec.egress[0]) |= (.to = (env(API_PEERS) | ... style=\"\") | .ports[0].port = env(API_PORT))
  | (select(.kind == \"ConfigMap\" and .metadata.name == \"spire-entries\") | .data) = (env(ENTRIES) | ... style=\"\" | map_values(to_yaml) | .[] style=\"literal\")
  $edits
" "$here/manifests.yaml" \
  | yq "$keep_objects" \
  | sed -e "s|@SPIRE_PLUGIN_IMAGE@|$plugin_image|" -e "s|@SPIRE_CONFIG_CHECKSUM@|$config_checksum|" -e "s|@API_SERVICE_IP@|${API_SERVICE_IP:-}|"
echo "---"
echo "$config_maps"
