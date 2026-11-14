#!/usr/bin/env bash
# Render the hub of the mesh view and Kiali in management, a link component. It owns the namespace
# mesh-view-system alone.
#
# The bundle holds:
#   - Namespace mesh-view-system, with a default deny and the policies of flows N3, N8, N11, N12, N13,
#     N14, N23, N24 and N25.
#   - The hub: Deployment mesh-view-hub with cell-proxy and a k8s_psat SPIRE agent sidecar
#     (hub.yaml), one --tunnel-cell argument for each cell of MESH_VIEW_CELLS, Service
#     mesh-view-listener on node port 31445, and the ClusterIP Service mesh-view-hub with one port
#     for each cell.
#   - Kiali from the vendored kiali-server chart (kiali-values.yaml), with its image by digest, the
#     viewer Role in each namespace of MESH_VIEW_NAMESPACES, and
#     the remote cluster Secret kiali-multi-cluster-secret: one kubeconfig for each cell, with the
#     address of the hub port of the cell, an empty user and no credential.
# The Deployment of Kiali carries the annotation poc.internal/link-stage=after-tunnels. cell:link
# applies the other objects first, waits until the hub logs tunnel_up for each cell, and then
# applies the Deployment of Kiali, because Kiali reads its remote cluster Secret once at start.
#
# The render reads these facts from outside the cluster, so it runs in the link phase:
#   - the node address of VIEW_CONTROL_PLANE (dev-cp) from the host service. Only that address
#     reaches the node port.
#   - the root of the environment trust domain, from the live SPIRE server of VIEW_CONTROL_PLANE, as
#     ConfigMap peer-root (components/lib/peer-root.sh).
#   - the root of the management trust domain, from the live SPIRE server of this cluster, for the
#     trust bundle of the sidecar.
#   - the public key of mgmtd, as ConfigMap registry-signer (components/lib/registry.sh). cell-proxy
#     refuses a registry that another key signed. mgmtd publishes ConfigMap cell-registry itself, and
#     cell-proxy loads it again every 10 seconds. So the bundle holds a Role that lets
#     mgmtd write it, and no registry.
#   - the cell-proxy image that `mise run images` built, by digest.
# Kiali reads only the namespaces of MESH_VIEW_NAMESPACES, in each cluster. The chart with
# cluster_wide_access false lists the namespace of Kiali alone, because it reads the other namespaces
# with a lookup that helm template cannot make. So the render sets the discovery selectors of the
# Kiali config itself, and sets the config checksum of the pod from the result.
# Inputs: MESH_VIEW_CELLS, MESH_VIEW_NAMESPACES, VIEW_CONTROL_PLANE and SPIRE_TRUST_DOMAIN from
# cells/management.env,
# POC_ENV, KIALI_VERSION and KIALI_IMAGE from cells/common.env, and the cluster facts from
# build/<cluster>/facts.env.
set -euo pipefail
: "${CELL_NAME:?}" "${POC_ENV:?}" "${MESH_VIEW_CELLS:?}" "${MESH_VIEW_NAMESPACES:?}" "${VIEW_CONTROL_PLANE:?}" "${SPIRE_TRUST_DOMAIN:?}"
: "${KIALI_VERSION:?}" "${KIALI_IMAGE:?}"
: "${NODE_IPS:?}" "${API_SERVER_IPS:?}" "${API_SERVER_PORT:?}" "${API_SERVICE_IP:?}" "${DNS_SERVICE_IP:?}"

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
namespace=mesh-view-system
component=mesh-view-hub
env_cluster="$VIEW_CONTROL_PLANE"
env_td=dev.env.poc.internal
chart="$root/vendor/charts/kiali-server-${KIALI_VERSION#v}/kiali-server"

die() { printf 'error: mesh-view-hub render: %s\n' "$*" >&2; exit 1; }

source "$root/scripts/ko-image.sh"
source "$root/components/lib/addresses.sh"
source "$root/components/lib/peer-root.sh"
source "$root/components/lib/registry.sh"
source "$root/components/lib/spire-sidecar.sh"

[[ "$POC_ENV" =~ ^[a-z0-9][a-z0-9-]{0,30}$ ]] || die "POC_ENV '$POC_ENV' is not a short DNS label"
[[ "$SPIRE_TRUST_DOMAIN" == mgmt.poc.internal ]] || die "SPIRE_TRUST_DOMAIN '$SPIRE_TRUST_DOMAIN' is not mgmt.poc.internal, the domain that the hub probe expects"
[[ "$KIALI_IMAGE" == "quay.io/kiali/kiali:${KIALI_VERSION}@sha256:"* && "$KIALI_IMAGE" =~ @sha256:[0-9a-f]{64}$ ]] \
  || die "KIALI_IMAGE '$KIALI_IMAGE' is not quay.io/kiali/kiali:$KIALI_VERSION pinned by digest"
[[ -d "$chart" ]] || die "no chart in $chart. Run: mise run vendor:fetch"

read -r -a entries <<<"$MESH_VIEW_CELLS"
((${#entries[@]} > 0)) || die "MESH_VIEW_CELLS names no cell"
cells=() ports=()
for e in "${entries[@]}"; do
  [[ "$e" =~ ^([a-z0-9]([a-z0-9-]{0,57}[a-z0-9])?)=([0-9]{4,5})$ ]] || die "MESH_VIEW_CELLS entry '$e' is not <cell>=<port> with a cell name of at most 59 characters"
  cell="${BASH_REMATCH[1]}" port="${BASH_REMATCH[3]}"
  case "$cell" in cp | dev-cp | management | rogue) die "MESH_VIEW_CELLS names the reserved name $cell" ;; esac
  ((port >= 1024 && port <= 65535 && port != 8444 && port != 20001 && port != 31445)) || die "MESH_VIEW_CELLS port $port of $cell is out of range or in use"
  [[ " ${cells[*]-} " != *" $cell "* ]] || die "MESH_VIEW_CELLS names $cell twice"
  [[ " ${ports[*]-} " != *" $port "* ]] || die "MESH_VIEW_CELLS gives the port $port to two cells"
  cells+=("$cell") ports+=("$port")
done

read -r -a mesh_namespaces <<<"$MESH_VIEW_NAMESPACES"
for n in "${mesh_namespaces[@]}"; do
  [[ "$n" =~ ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$ ]] || die "MESH_VIEW_NAMESPACES entry '$n' is not a namespace name"
done
[[ " ${mesh_namespaces[*]} " == *" $namespace "* ]] || mesh_namespaces+=("$namespace")
namespaces_json="$(printf '%s\n' "${mesh_namespaces[@]}" | jq -Rcn '[inputs]')"

node_ips="$(ipv4_list NODE_IPS)" || exit 1
api_ips="$(ipv4_list API_SERVER_IPS)" || exit 1
[[ "$API_SERVER_PORT" =~ ^[0-9]+$ ]] || die "API_SERVER_PORT '$API_SERVER_PORT' is not a port number"
ipv4='^([0-9]{1,3}\.){3}[0-9]{1,3}$'
[[ "$API_SERVICE_IP" =~ $ipv4 && "$DNS_SERVICE_IP" =~ $ipv4 ]] || die "API_SERVICE_IP or DNS_SERVICE_IP is not an IPv4 address"
if ! facts="$(cd "$root" && mise run hostsvc -- facts --cluster "$env_cluster" 2>/dev/null)"; then
  die "no host service facts for $env_cluster: ${facts:-no output}. Run: CELL=$env_cluster mise run cell:up"
fi
env_ip="$(jq -r '.nodeIP // ""' <<<"$facts")"
[[ "$env_ip" =~ $ipv4 ]] || die "node address of $env_cluster is '$env_ip', not an IPv4 address"

peers() { for ip in "$@"; do printf '{"ipBlock":{"cidr":"%s/32"}}\n' "$ip"; done | jq -cs .; }
node_peers="$(peers $node_ips)"
api_peers="$(peers $api_ips)"
env_peers="$(peers "$env_ip")"
cell_ports="$(printf '%s\n' "${ports[@]}" | jq -Rcn '[inputs | {protocol: "TCP", port: tonumber}]')"
tunnel_args="$(for i in "${!cells[@]}"; do printf -- '--tunnel-cell=%s=:%s\n' "${cells[$i]}" "${ports[$i]}"; done | jq -Rcn '[inputs]')"

cell_proxy_image="$(ko_image cell-proxy)" || die "no cell-proxy image"
peer_root="$(peer_root_configmap peer-root "$namespace" "$env_cluster" "$env_td")" || exit 1
own_bundle="$(peer_root_pem "$CELL_NAME" "$SPIRE_TRUST_DOMAIN")" || exit 1
registry_signer="$(registry_signer_configmap "$namespace")" || exit 1
peer_sum="$(yq -r '.metadata.annotations["poc.internal/peer-root-sha256"]' <<<"$peer_root")"
signer_sum="$(yq -r '.metadata.annotations["poc.internal/registry-signer-sha256"]' <<<"$registry_signer")"
[[ "$peer_sum" =~ ^[0-9a-f]{64}$ && "$signer_sum" =~ ^[0-9a-f]{64}$ ]] || die "the peer root or the registry signer has no checksum"

# The tunnel ID is the role mesh-view of one cell. The first capture group is the cell name.
allow_id="^spiffe://${env_td//./\\.}/cell/([a-z0-9-]+)/mesh-view\$"

hub="$(sed -e "s|@CELL_PROXY_IMAGE@|$cell_proxy_image|" -e "s|@PEER_ROOT_SHA256@|$peer_sum|" \
    -e "s|@REGISTRY_SIGNER_SHA256@|$signer_sum|" -e "s|@PEER_TRUST_DOMAIN@|$env_td|" \
    -e "s|@API_SERVICE_IP@|$API_SERVICE_IP|" -e "s|@DNS_SERVICE_IP@|$DNS_SERVICE_IP|" \
    "$here/hub.yaml" \
  | ALLOW="$allow_id" NODE="$node_peers" ENVP="$env_peers" API="$api_peers" APIPORT="$API_SERVER_PORT" PORTS="$cell_ports" TARGS="$tunnel_args" \
    CELLS="$(printf '%s\n' "${cells[@]}" | jq -Rcn '[inputs]')" PORTLIST="$(printf '%s\n' "${ports[@]}" | jq -Rcn '[inputs | tonumber]')" yq '
      (.. | select(. == "--allow-id=@ALLOW_ID@")) = "--allow-id=" + strenv(ALLOW)
      | (select(.kind == "Deployment") | .spec.template.spec.containers[0].args) |= (map(select(. != "--tunnel-cell=@TUNNEL_CELL@")) + env(TARGS))
      | (.. | select(. == "@NODE_PEERS@")) |= (env(NODE) | ... style="")
      | (.. | select(. == "@ENV_NODE_PEERS@")) |= (env(ENVP) | ... style="")
      | (.. | select(. == "@API_SERVER_PEERS@")) |= (env(API) | ... style="")
      | (.. | select(. == "@API_SERVER_PORT@")) |= env(APIPORT)
      | (.. | select(. == "@CELL_PORTS@")) |= (env(PORTS) | ... style="")
      | (select(.kind == "Service" and .metadata.name == "mesh-view-hub") | .spec.ports) = (env(PORTLIST) | to_entries
          | map({"name": ("cell-" + (.key + 1 | tostring)), "port": .value, "targetPort": .value, "appProtocol": "http"}))')"
deployment="$(yq 'select(.kind == "Deployment")' <<<"$hub" \
  | SPIRE_SIDECAR_SERVER_ADDRESS=spire-server.spire-system.svc.cluster.local SPIRE_SIDECAR_SERVER_PORT=8081 \
    SPIRE_SIDECAR_TRUST_DOMAIN="$SPIRE_TRUST_DOMAIN" SPIRE_SIDECAR_BUNDLE="$own_bundle" SPIRE_SIDECAR_CLUSTER="$CELL_NAME" \
    spire_sidecar mesh-view-hub k8s_psat)" || die "the SPIRE sidecar of the hub failed"

# The remote cluster Secret: one kubeconfig for each cell, keyed by the cell name. The server is the
# hub port of the cell. The user is empty, so the Secret holds no credential.
kubeconfigs="$(for i in "${!cells[@]}"; do
  CELL="${cells[$i]}" SERVER="http://mesh-view-hub.$namespace.svc:${ports[$i]}" yq -n '
    .apiVersion = "v1" | .kind = "Config"
    | .clusters = [{"name": strenv(CELL), "cluster": {"server": strenv(SERVER)}}]
    | .users = [{"name": strenv(CELL), "user": {}}]
    | .contexts = [{"name": strenv(CELL), "context": {"cluster": strenv(CELL), "user": strenv(CELL)}}]
    | .["current-context"] = strenv(CELL)' | CELL="${cells[$i]}" yq -o=json -I=0 '{(strenv(CELL)): (. | to_yaml)}'
done | jq -cs 'add')"
clusters_sum="$(jq -cS . <<<"$kubeconfigs" | sha256)"
clusters_secret="$(DATA="$kubeconfigs" NS="$namespace" yq -n '
  .apiVersion = "v1" | .kind = "Secret" | .metadata.name = "kiali-multi-cluster-secret" | .metadata.namespace = strenv(NS)
  | .type = "Opaque" | .stringData = (strenv(DATA) | from_json)')"

# Kiali from the chart. The release namespace is the namespace of the hub. The render keeps the
# objects of the chart, replaces the image tag by the pinned digest, and removes the Istio proxy
# annotation. Pods/portforward leaves the viewer Role: no workload of the plane may forward a port.
# The chart makes a new random login signing key at each render, which would restart Kiali at each link
# phase. The render derives a key from the root of the trust domain of this cluster. That key is
# predictable: anyone who reads the public root can compute it. Kiali can read the key from a Secret, but
# the External Secrets Operator of this cluster serves one namespace, observability-system, so it cannot make
# a Secret in mesh-view-system without breaking the Grafana password. The key signs nothing under the
# anonymous strategy, and the render refuses any other strategy, because a predictable key must never
# protect a login.
[[ "$(yq -r '.auth.strategy' "$here/kiali-values.yaml")" == anonymous ]] || die "auth.strategy in kiali-values.yaml is not anonymous, and the login signing key is derived from public roots"
signing_key="$(printf 'kiali login of %s\n%s' "$namespace" "$own_bundle" | sha256 | cut -c1-32)"
kiali="$(helm template kiali "$chart" --namespace "$namespace" --kube-version 1.37.0 --values "$here/kiali-values.yaml" \
    --set "login_token.signing_key=$signing_key" \
  | KIALI_IMAGE="$KIALI_IMAGE" SUM="$clusters_sum" yq 'select(.kind != null)
    | (select(.kind == "Role" or .kind == "ClusterRole") | .rules) |= map(select((.resources // []) | contains(["pods/portforward"]) | not))
    | with(select(.kind == "Deployment");
        .spec.template.spec.containers[0].image = strenv(KIALI_IMAGE)
        | del(.spec.template.metadata.annotations["proxy.istio.io/config"])
        | .spec.template.metadata.annotations["poc.internal/clusters-sha256"] = strenv(SUM)
        | .metadata.annotations["poc.internal/link-stage"] = "after-tunnels")')" || die "helm template of the kiali-server chart failed"
# Kiali reads the namespaces of the list, in the cells and in management.
kiali="$(NAMESPACES="$namespaces_json" yq '
  (select(.kind == "ConfigMap" and .metadata.name == "kiali") | .data."config.yaml") |= (from_yaml
    | .deployment.discovery_selectors = {"default": [{"matchExpressions": [{"key": "kubernetes.io/metadata.name", "operator": "In", "values": env(NAMESPACES)}]}]}
    | to_yaml)' <<<"$kiali")"
config_text="$(yq -N 'select(.kind == "ConfigMap" and .metadata.name == "kiali") | .data."config.yaml"' <<<"$kiali")"
config_sum="$(printf '%s' "$config_text" | sha256)"
kiali="$(SUM="$config_sum" yq '(select(.kind == "Deployment") | .spec.template.metadata.annotations["checksum/config"]) = strenv(SUM)' <<<"$kiali")"
rendered_strategy="$(yq -N 'select(.kind == "ConfigMap" and .metadata.name == "kiali") | .data."config.yaml"' <<<"$kiali" | yq -r '.auth.strategy')"
[[ "$rendered_strategy" == anonymous ]] || die "the rendered Kiali config sets auth.strategy '$rendered_strategy', not anonymous, and the login signing key is predictable"
kinds="$(yq -N '.kind' <<<"$kiali" | sort | paste -sd' ' -)"
[[ "$kinds" == "ConfigMap Deployment Role RoleBinding Service ServiceAccount" ]] || die "the kiali-server chart renders '$kinds', and the hub expects ConfigMap Deployment Role RoleBinding Service ServiceAccount"
! yq -N 'select(.kind == "Role") | .rules[].resources[]' <<<"$kiali" | grep -qx 'pods/portforward' \
  || die "a rule of the kiali viewer Role still names pods/portforward"

# The home cluster cache of Kiali watches each namespace of the list too, even with
# ignore_home_cluster, and it stops when the API server refuses one. So the viewer Role and its
# binding exist in each namespace of the list in management. The home manager does not cache
# ConfigMaps, so the copies of the Role grant none.
viewer_roles="$(for n in "${mesh_namespaces[@]}"; do
  [[ "$n" == "$namespace" ]] && continue
  NS="$n" yq 'select(.kind == "Role" or .kind == "RoleBinding") | .metadata.namespace = strenv(NS)
    | (select(.kind == "Role") | .rules[].resources) |= map(select(. != "configmaps"))
    | (select(.kind == "Role") | .rules) |= map(select(.resources | length > 0))' <<<"$kiali"
  echo "---"
done)"

# Every object carries the harness label of the link component, and every pod template too, so
# cell:verify can tie each pod of a plane ServiceAccount to its workload.
{
  NS="$namespace" yq -n '.apiVersion = "v1" | .kind = "Namespace" | .metadata.name = strenv(NS)
    | .metadata.labels = {"istio-injection": "disabled", "pod-security.kubernetes.io/enforce": "restricted"}'
  echo "---"
  yq 'select(.kind != "Deployment")' <<<"$hub"
  echo "---"
  echo "$deployment"
  echo "---"
  echo "$peer_root"
  echo "---"
  echo "$registry_signer"
  echo "---"
  registry_publisher_rbac "$namespace"
  echo "---"
  echo "$clusters_secret"
  echo "---"
  echo "$kiali"
  echo "---"
  echo "$viewer_roles"
} | COMP="$component" yq 'select(.kind != null)
    | .metadata.labels["cell.poc.internal/harness"] = strenv(COMP)
    | with(select(.spec.template.metadata != null); .spec.template.metadata.labels["cell.poc.internal/harness"] = strenv(COMP))'
