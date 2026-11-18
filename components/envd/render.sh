#!/usr/bin/env bash
# Render envd, the environment executor of dev-cp, a harness component in namespace envd-system.
#
# The bundle holds Namespace envd-system, ServiceAccount envd, Deployment envd with the k8s_psat SPIRE
# agent sidecar, ConfigMaps peer-root and mgmt-spec-key, the objects of the sidecar, the
# NetworkPolicies default-deny, allow-dns and envd (flows N30, N31, N35, N39, N8, N11 and N23), and Role
# and RoleBinding envd-records in spire-system. The Role lets envd write ConfigMap
# spire-system/cell-records and read ConfigMap spire-system/attest-hints, and nothing else. Every object
# carries the harness label of the component. The step flags name ConfigMaps cell-steps and step-status in
# cell-controller-system. The cell controller render holds the Role envd-steps for them, and its component comes
# first in the topology.
#
# envd applies the signed bundle sets of dev-cp, so the bundle also holds Role envd-argocd in argocd, ClusterRole and
# binding envd-netpol-read, Role and RoleBinding envd-bundle-state, the egress rules of flows N48 (the registry mirror) and
# N46 (the bundle store), and the guard bundles-spare-harness (components/lib/bundle-guard.sh, role cp).
#
# The bundle also holds the harness plane policies of role cp. Each one admits a plane flow for every pod of its
# namespace, so a bundle cannot move a pod out of the policy by a label:
#   - cell-system/plane-envd-store: envd to the bundle store, TCP 5000 (flow N46).
#   - spire-system/plane-envd: envd to the SPIRE server, TCP 8081.
#   - spire-system/plane-workloads: the other local plane workloads of SPIRE_LOCAL_WORKLOADS (the pods of each service
#     account) to the SPIRE server, TCP 8081.
#   - spire-system/plane-cells: the node address of each live cell to the SPIRE server, TCP 8081.
#   - relay-system/plane-cells: the node address of each live cell to the relay routes, TCP on each container port of
#     RELAY_VIEW_ROUTES and RELAY_TELEMETRY_ROUTES.
#   - relay-system/plane-upstream: the relay to the node of RELAY_TARGET, TCP on each target port of those routes.
# A live cell is a cluster of SPIRE_AGENT_CELLS whose node has an address (live_cells in components/lib/live-cells.sh). With
# no live cell, both plane-cells policies are absent. A live cell whose facts do not read stops the render, because a cell
# that the render left out would lose its place in the admit lists.
#
# The render reads these facts from outside the cluster, so the harness runs it after the waves:
#   - the node address of the management cluster, from the host service. The envd arguments and the
#     egress rule of flow N30 hold it, with the API node port of mgmtd.
#   - the root of the management trust domain, from the live SPIRE server of management, as
#     ConfigMap peer-root.
#   - the public signing key of mgmtd, from ConfigMap mgmt-signing-pub in management, as ConfigMap
#     mgmt-spec-key. The SPIRE server of this cluster pins the same key.
#   - the root of the environment trust domain, from the live SPIRE server of this cluster, for the
#     trust bundle of the sidecar.
#   - the address of the registry mirror on the kind network, from the host service (facts --registry). envd reads the
#     signed bundle sets from it (flow N48), and the policy of envd admits only that address on port 5000.
#   - the node address of each live cell, from the host service.
#   - the envd image that `mise run images` built, by digest.
# The pod template carries the SHA-256 of the peer root and of the key, so a change restarts the pod.
# Inputs: POC_ENV, SPIRE_TRUST_DOMAIN, RELAY_TARGET, SPIRE_AGENT_CELLS, RELAY_VIEW_ROUTES and RELAY_TELEMETRY_ROUTES from the
# cell settings, and the cluster facts from build/<cluster>/facts.env.
set -euo pipefail
: "${CELL_NAME:?}" "${POC_ENV:?}" "${SPIRE_TRUST_DOMAIN:?}" "${RELAY_TARGET:?}"
: "${SPIRE_AGENT_CELLS:?}" "${RELAY_VIEW_ROUTES:?}" "${RELAY_TELEMETRY_ROUTES:?}" "${SPIRE_LOCAL_WORKLOADS:?}"
: "${NODE_IPS:?}" "${API_SERVER_IPS:?}" "${API_SERVER_PORT:?}" "${API_SERVICE_IP:?}" "${DNS_SERVICE_IP:?}"

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
namespace=envd-system
component=envd
mgmt_td=mgmt.poc.internal
api_port=31446

die() { printf 'error: envd render: %s\n' "$*" >&2; exit 1; }

source "$root/scripts/ko-image.sh"
source "$root/components/lib/addresses.sh"
source "$root/components/lib/peer-root.sh"
source "$root/components/lib/mgmt-key.sh"
source "$root/components/lib/spire-sidecar.sh"
source "$root/components/lib/live-cells.sh"
guard="$root/components/lib/bundle-guard.sh"

[[ "$POC_ENV" =~ ^[a-z0-9][a-z0-9-]{0,30}$ ]] || die "POC_ENV '$POC_ENV' is not a short DNS label"
[[ "$SPIRE_TRUST_DOMAIN" == dev.env.poc.internal ]] || die "SPIRE_TRUST_DOMAIN '$SPIRE_TRUST_DOMAIN' is not dev.env.poc.internal, the domain of the envd ID"
ipv4='^([0-9]{1,3}\.){3}[0-9]{1,3}$'
[[ "$DNS_SERVICE_IP" =~ $ipv4 && "$API_SERVICE_IP" =~ $ipv4 ]] || die "DNS_SERVICE_IP or API_SERVICE_IP is not an IPv4 address"
[[ "$API_SERVER_PORT" =~ ^[0-9]+$ ]] || die "API_SERVER_PORT '$API_SERVER_PORT' is not a port number"
node_ips="$(ipv4_list NODE_IPS)" || exit 1
api_ips="$(ipv4_list API_SERVER_IPS)" || exit 1

if ! facts="$(cd "$root" && mise run hostsvc -- facts --cluster "$RELAY_TARGET" 2>/dev/null)"; then
  die "no host service facts for $RELAY_TARGET: ${facts:-no output}. Run: CELL=$RELAY_TARGET mise run cell:up"
fi
mgmt_ip="$(jq -r '.nodeIP // ""' <<<"$facts")"
[[ "$mgmt_ip" =~ $ipv4 ]] || die "node address of $RELAY_TARGET is '$mgmt_ip', not an IPv4 address"

if ! registry="$(cd "$root" && mise run hostsvc -- facts --registry 2>/dev/null)"; then
  die "no registry mirror address from the host service: ${registry:-no output}. Run: mise run harness:status"
fi
registry_ip="$(jq -r '.address // ""' <<<"$registry")"
registry_port="$(jq -r '.port // 0' <<<"$registry")"
[[ "$registry_ip" =~ $ipv4 ]] || die "no registry mirror address: the address of the mirror is '$registry_ip', not an IPv4 address"
[[ "$registry_port" == 5000 ]] || die "the registry mirror port is '$registry_port', and the NetworkPolicy of envd admits port 5000"

# The live cells of the catalog, with the node address of each.
read -r -a catalog <<<"$SPIRE_AGENT_CELLS"
((${#catalog[@]} > 0)) || die "SPIRE_AGENT_CELLS names no cell, so no cell could reach the SPIRE server or the relay"
for cell in "${catalog[@]}"; do
  [[ "$cell" != "$RELAY_TARGET" ]] || die "SPIRE_AGENT_CELLS names the relay target $RELAY_TARGET"
done
live_all="$(live_cells)" || die "could not list the live cells"
cell_ips=()
for cell in $live_all; do
  [[ " ${catalog[*]} " == *" $cell "* ]] || continue
  if ! cell_facts="$(cd "$root" && mise run hostsvc -- facts --cluster "$cell" 2>/dev/null)"; then
    die "no host service facts for the live cell $cell: ${cell_facts:-no output}. Read them: mise run hostsvc -- facts --cluster $cell"
  fi
  cell_ip="$(jq -r '.nodeIP // ""' <<<"$cell_facts")"
  [[ "$cell_ip" =~ $ipv4 ]] || die "node address of $cell is '$cell_ip', not an IPv4 address"
  cell_ips+=("$cell_ip")
done

# The routes of the relay. A route is <node port>:<container port>=<target node port>. The cells reach the container ports, and
# the relay reaches the target ports of RELAY_TARGET. The node ports and container ports are unique across both lists.
route_ports='[]' target_ports='[]'
seen_node=" " seen_container=" "
for list in RELAY_VIEW_ROUTES RELAY_TELEMETRY_ROUTES; do
  read -r -a routes <<<"${!list}"
  ((${#routes[@]} > 0)) || die "${list} has no route"
  for route in "${routes[@]}"; do
    [[ "$route" =~ ^([0-9]{5}):([0-9]{1,5})=([0-9]{5})$ ]] || die "route '$route' of $list is not <node port>:<container port>=<target node port>"
    node="${BASH_REMATCH[1]}" container="${BASH_REMATCH[2]}" target="${BASH_REMATCH[3]}"
    ((container >= 1024 && container <= 65535 && container != 8080)) || die "route '$route' of $list has the container port $container, want 1024 to 65535 and not the health port 8080"
    [[ "$seen_node" != *" $node "* && "$seen_container" != *" $container "* ]] || die "route '$route' of $list repeats a node port or a container port"
    seen_node+="$node " seen_container+="$container "
    route_ports="$(jq -c --argjson p "$container" '. + [{protocol: "TCP", port: $p}]' <<<"$route_ports")"
    target_ports="$(jq -c --argjson p "$target" 'if any(.[]; .port == $p) then . else . + [{protocol: "TCP", port: $p}] end' <<<"$target_ports")"
  done
done

# The local plane workloads other than envd, as peers: each is <spiffe path>=<namespace>/<service account>, and its pods carry
# the label app.kubernetes.io/name=<service account>.
workload_peers='[]'
read -r -a local_workloads <<<"$SPIRE_LOCAL_WORKLOADS"
for w in "${local_workloads[@]}"; do
  [[ "$w" =~ ^[a-z0-9-]+(/[a-z0-9-]+)*=([a-z0-9-]+)/([a-z0-9-]+)$ ]] || die "SPIRE_LOCAL_WORKLOADS entry '$w' is not <spiffe path>=<namespace>/<service account>"
  [[ "${BASH_REMATCH[2]}/${BASH_REMATCH[3]}" != envd-system/envd ]] || continue
  workload_peers="$(jq -c --arg ns "${BASH_REMATCH[2]}" --arg sa "${BASH_REMATCH[3]}" '. + [{
    namespaceSelector: {matchLabels: {"kubernetes.io/metadata.name": $ns}},
    podSelector: {matchLabels: {"app.kubernetes.io/name": $sa}}}]' <<<"$workload_peers")"
done

peer_root="$(peer_root_configmap peer-root "$namespace" "$RELAY_TARGET" "$mgmt_td")" || exit 1
peer_sum="$(yq -r '.metadata.annotations["poc.internal/peer-root-sha256"]' <<<"$peer_root")"
[[ "$peer_sum" =~ ^[0-9a-f]{64}$ ]] || die "the peer root has no checksum"
spec_pub="$(mgmt_signing_pub)" || exit 1
spec_sum="$(printf '%s' "$spec_pub" | sha256)"
spec_key="$(NS="$namespace" PUB="$spec_pub" SUM="$spec_sum" yq -n '
  .apiVersion = "v1" | .kind = "ConfigMap" | .metadata.name = "mgmt-spec-key" | .metadata.namespace = strenv(NS)
  | .metadata.annotations["poc.internal/spec-key-sha256"] = strenv(SUM)
  | .data["spec.pub"] = strenv(PUB)')"
own_bundle="$(peer_root_pem "$CELL_NAME" "$SPIRE_TRUST_DOMAIN")" || exit 1
envd_image="$(ko_image envd)" || die "no envd image"

manifests="$(sed -e "s|@ENVD_IMAGE@|$envd_image|" -e "s|@PEER_ROOT_SHA256@|$peer_sum|" -e "s|@SPEC_KEY_SHA256@|$spec_sum|" \
  -e "s|@UPSTREAM@|$mgmt_ip:$api_port|" -e "s|@CLUSTER@|$CELL_NAME|" -e "s|@REGISTRY_ADDRESS@|$registry_ip:$registry_port|" -e "s|@MGMT_TRUST_DOMAIN@|$mgmt_td|g" -e "s|@POC_ENV@|$POC_ENV|" -e "s|@POC_TRUST_DOMAIN@|$SPIRE_TRUST_DOMAIN|g" "$here/manifests.yaml")"
grep -q '@[A-Z_]*@' <<<"$manifests" && die "the manifests keep a token that the render does not replace"

deployment="$(yq 'select(.kind == "Deployment")' <<<"$manifests" \
  | SPIRE_SIDECAR_SERVER_ADDRESS=spire-server.spire-system.svc.cluster.local SPIRE_SIDECAR_SERVER_PORT=8081 \
    SPIRE_SIDECAR_TRUST_DOMAIN="$SPIRE_TRUST_DOMAIN" SPIRE_SIDECAR_BUNDLE="$own_bundle" SPIRE_SIDECAR_CLUSTER="$CELL_NAME" \
    spire_sidecar envd k8s_psat)" || die "the SPIRE sidecar of envd failed"

# The envd policy. Flow N30 reaches the API node port of mgmtd. Flow N31 reaches the API server for
# ConfigMap cell-records: its node address, and the ClusterIP of its Service on 443. Flow N39 reaches the cell
# gateway on 8452. Flow N35 is allow-dns, which the namespace has apart from this policy. Flow N8 reaches the
# SPIRE server for the sidecar, and N11 the collector. Flow N23 admits the node addresses on the health
# port for the kubelet probes. Flow N48 reaches the registry mirror on 5000, and flow N46 the bundle store on 5000.
peers() { for ip in "$@"; do printf '{"ipBlock":{"cidr":"%s/32"}}\n' "$ip"; done | jq -cs .; }
policy="$(jq -n --arg ns "$namespace" --argjson mgmt "$(peers "$mgmt_ip")" --argjson mgmtport "$api_port" \
  --argjson api "$(peers $api_ips)" --argjson apiport "$API_SERVER_PORT" --argjson apisvc "$(peers "$API_SERVICE_IP")" \
  --argjson nodes "$(peers $node_ips)" --argjson mirror "$(peers "$registry_ip")" '
  {apiVersion: "networking.k8s.io/v1", kind: "NetworkPolicy", metadata: {name: "envd", namespace: $ns},
   spec: {podSelector: {matchLabels: {"app.kubernetes.io/name": "envd"}}, policyTypes: ["Ingress", "Egress"],
     ingress: [{from: $nodes, ports: [{protocol: "TCP", port: 8080}]}],
     egress: [
       {to: $mgmt, ports: [{protocol: "TCP", port: $mgmtport}]},
       {to: $api, ports: [{protocol: "TCP", port: $apiport}]},
       {to: $apisvc, ports: [{protocol: "TCP", port: 443}]},
       {to: [{namespaceSelector: {matchLabels: {"kubernetes.io/metadata.name": "spire-system"}},
              podSelector: {matchLabels: {"app.kubernetes.io/name": "spire-server"}}}],
        ports: [{protocol: "TCP", port: 8081}]},
       {to: [{namespaceSelector: {matchLabels: {"kubernetes.io/metadata.name": "gateway-system"}},
              podSelector: {matchLabels: {"app.kubernetes.io/name": "cell-gateway"}}}],
        ports: [{protocol: "TCP", port: 8452}]},
       {to: [{namespaceSelector: {matchLabels: {"kubernetes.io/metadata.name": "observability-system"}},
              podSelector: {matchLabels: {"app.kubernetes.io/name": "otel-collector"}}}],
        ports: [{protocol: "TCP", port: 4317}]},
       {to: $mirror, ports: [{protocol: "TCP", port: 5000}]},
       {to: [{namespaceSelector: {matchLabels: {"kubernetes.io/metadata.name": "cell-system"}},
              podSelector: {matchLabels: {"app.kubernetes.io/name": "bundle-store"}}}],
        ports: [{protocol: "TCP", port: 5000}]}]}}' | yq -P '.')"

# The harness plane policies of role cp. Each selects every pod of its namespace. The ports and peers are the ones that the
# rules of the SPIRE server and relay bundles held before these policies took the flows.
envd_peer='{"namespaceSelector":{"matchLabels":{"kubernetes.io/metadata.name":"envd-system"}},"podSelector":{"matchLabels":{"app.kubernetes.io/name":"envd"}}}'
planes="$(jq -n --argjson envd "[$envd_peer]" --argjson cells "$(peers ${cell_ips[@]+"${cell_ips[@]}"})" --argjson routes "$route_ports" \
  --argjson mgmt "$(peers "$mgmt_ip")" --argjson targets "$target_ports" --argjson workloads "$workload_peers" '
  def plane($ns; $name; $types; $rules):
    {apiVersion: "networking.k8s.io/v1", kind: "NetworkPolicy", metadata: {name: $name, namespace: $ns},
     spec: ({podSelector: {}, policyTypes: $types} + (if $types == ["Ingress"] then {ingress: $rules} else {egress: $rules} end))};
  [plane("cell-system"; "plane-envd-store"; ["Ingress"]; [{from: $envd, ports: [{protocol: "TCP", port: 5000}]}]),
   plane("spire-system"; "plane-envd"; ["Ingress"]; [{from: $envd, ports: [{protocol: "TCP", port: 8081}]}]),
   (if ($workloads | length) > 0 then
     plane("spire-system"; "plane-workloads"; ["Ingress"]; [{from: $workloads, ports: [{protocol: "TCP", port: 8081}]}])
   else empty end),
   (if ($cells | length) > 0 then
     plane("spire-system"; "plane-cells"; ["Ingress"]; [{from: $cells, ports: [{protocol: "TCP", port: 8081}]}]),
     plane("relay-system"; "plane-cells"; ["Ingress"]; [{from: $cells, ports: $routes}])
   else empty end),
   plane("relay-system"; "plane-upstream"; ["Egress"]; [{to: $mgmt, ports: $targets}])]' | yq -P '.[] | split_doc')"

guards="$("$guard" cp)" || die "the bundle guard failed"

dns="$(cat <<EOF2
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny
  namespace: $namespace
spec:
  podSelector: {}
  policyTypes: [Ingress, Egress]
---
# Flow N35: every pod of the namespace resolves names through the cluster DNS.
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-dns
  namespace: $namespace
spec:
  podSelector: {}
  policyTypes: [Egress]
  egress:
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: kube-system
          podSelector:
            matchLabels:
              k8s-app: kube-dns
        - ipBlock:
            cidr: $DNS_SERVICE_IP/32
      ports:
        - protocol: UDP
          port: 53
        - protocol: TCP
          port: 53
EOF2
)"

# Every object carries the harness label of the component, and the pod template too, so cell:verify
# can tie each pod of the plane ServiceAccount to its workload.
{
  yq 'select(.kind != "Deployment")' <<<"$manifests"
  echo "---"
  echo "$deployment"
  echo "---"
  echo "$peer_root"
  echo "---"
  echo "$spec_key"
  echo "---"
  echo "$policy"
  echo "---"
  echo "$dns"
  echo "---"
  echo "$planes"
  echo "---"
  echo "$guards"
} | COMP="$component" yq 'select(.kind != null)
    | .metadata.labels["cell.poc.internal/harness"] = strenv(COMP)
    | with(select(.spec.template.metadata != null); .spec.template.metadata.labels["cell.poc.internal/harness"] = strenv(COMP))'
