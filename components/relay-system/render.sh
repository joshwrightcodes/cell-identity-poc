#!/usr/bin/env bash
# Render the relay of the environment control plane, a bundle at wave 8.
#
# Three Deployments run the relay binary: relay-view with the routes of RELAY_VIEW_ROUTES (the central
# view and the mesh view), relay-telemetry with the routes of RELAY_TELEMETRY_ROUTES, so a telemetry
# backlog cannot slow the view, and relay-bind with the routes of RELAY_BIND_ROUTES (the bind requests
# of the cells to mgmtd). The render makes relay-bind only when RELAY_BIND_ROUTES is set. Each route is
# <node port>:<container port>=<node port of RELAY_TARGET>. A NodePort Service with the local traffic
# policy admits the routes on the node.
#
# The render reads these facts from the host service, as the M2 renders do:
#   - the node address of RELAY_TARGET. The relay dials it, and the NetworkPolicy admits only it.
#   - the node address of each cell of SPIRE_AGENT_CELLS. Only these addresses reach the routes.
# The relay image is the one that `mise run images` built, by digest.
# Inputs: RELAY_TARGET, RELAY_VIEW_ROUTES, RELAY_TELEMETRY_ROUTES, RELAY_BIND_ROUTES (optional) and
# SPIRE_AGENT_CELLS from cells/<cluster>.env, and NODE_IPS and DNS_SERVICE_IP from build/<cluster>/facts.env.
set -euo pipefail
: "${RELAY_TARGET:?}" "${RELAY_VIEW_ROUTES:?}" "${RELAY_TELEMETRY_ROUTES:?}" "${SPIRE_AGENT_CELLS:?}" "${NODE_IPS:?}" "${DNS_SERVICE_IP:?}"

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
namespace=relay-system

die() { printf 'error: relay-system render: %s\n' "$*" >&2; exit 1; }

source "$root/scripts/ko-image.sh"
source "$root/components/lib/addresses.sh"

bind_routes="${RELAY_BIND_ROUTES:-}"

ipv4='^([0-9]{1,3}\.){3}[0-9]{1,3}$'
[[ "$DNS_SERVICE_IP" =~ $ipv4 ]] || die "DNS_SERVICE_IP '$DNS_SERVICE_IP' is not an IPv4 address"
node_ips="$(ipv4_list NODE_IPS)" || exit 1

# node_ip <cluster> prints the node address of a cluster from the host service.
node_ip() {
  local facts ip
  if ! facts="$(cd "$root" && mise run hostsvc -- facts --cluster "$1" 2>/dev/null)"; then
    die "no host service facts for $1: ${facts:-no output}. Create the cluster: mise run hostsvc -- up --only $1"
  fi
  ip="$(jq -r '.nodeIP // ""' <<<"$facts")"
  [[ "$ip" =~ $ipv4 ]] || die "node address of $1 is '$ip', not an IPv4 address"
  printf '%s\n' "$ip"
}

target_ip="$(node_ip "$RELAY_TARGET")"
read -r -a cells <<<"$SPIRE_AGENT_CELLS"
((${#cells[@]} > 0)) || die "SPIRE_AGENT_CELLS names no cell, so no cell could reach the relay"
cell_ips=()
for cell in "${cells[@]}"; do
  [[ "$cell" != "$RELAY_TARGET" ]] || die "SPIRE_AGENT_CELLS names the relay target $RELAY_TARGET"
  cell_ips+=("$(node_ip "$cell")")
done
relay_image="$(ko_image relay)" || die "no relay image"

peers() { for ip in "$@"; do printf '{"ipBlock":{"cidr":"%s/32"}}\n' "$ip"; done | jq -cs .; }
cell_peers="$(peers "${cell_ips[@]}")"
node_peers="$(peers $node_ips)"
target_peers="$(peers "$target_ip")"

# check_routes <name> <routes> stops the render for a bad route. The node ports and container ports
# must be unique across both Deployments.
seen_node=" " seen_container=" "
check_routes() {
  local name="$1" routes route node container target p
  read -r -a routes <<<"$2"
  ((${#routes[@]} > 0)) || die "$name has no route"
  for route in "${routes[@]}"; do
    [[ "$route" =~ ^([0-9]{5}):([0-9]{1,5})=([0-9]{5})$ ]] || die "route '$route' of $name is not <node port>:<container port>=<target node port>"
    node="${BASH_REMATCH[1]}" container="${BASH_REMATCH[2]}" target="${BASH_REMATCH[3]}"
    for p in "$node" "$target"; do
      ((p >= 30000 && p <= 32767)) || die "route '$route' of $name has the node port $p outside 30000 to 32767"
    done
    ((container >= 1024 && container <= 65535 && container != 8080)) || die "route '$route' of $name has the container port $container, want 1024 to 65535 and not the health port 8080"
    [[ "$seen_node" != *" $node "* ]] || die "the node port $node appears in two routes"
    [[ "$seen_container" != *" $container "* ]] || die "the container port $container appears in two routes"
    seen_node+="$node " seen_container+="$container "
  done
}
check_routes relay-view "$RELAY_VIEW_ROUTES"
check_routes relay-telemetry "$RELAY_TELEMETRY_ROUTES"
[[ -z "${RELAY_BIND_ROUTES+x}" || -n "${bind_routes// /}" ]] || die "relay-bind has no route"
[[ -z "${bind_routes// /}" ]] || check_routes relay-bind "$bind_routes"

# relay <name> <routes> prints the Deployment, the Service and the NetworkPolicy of one relay, for
# routes that check_routes accepted.
relay() {
  local name="$1" routes route node container target args=() ports='[]' service='[]' route_ports='[]' target_ports='[]'
  read -r -a routes <<<"$2"
  for route in "${routes[@]}"; do
    [[ "$route" =~ ^([0-9]{5}):([0-9]{1,5})=([0-9]{5})$ ]]
    node="${BASH_REMATCH[1]}" container="${BASH_REMATCH[2]}" target="${BASH_REMATCH[3]}"
    args+=("--route" "$container=$target_ip:$target")
    ports="$(jq -c --argjson p "$container" '. + [{name: ("route-" + ($p | tostring)), containerPort: $p}]' <<<"$ports")"
    service="$(jq -c --argjson p "$container" --argjson n "$node" '. + [{name: ("route-" + ($p | tostring)), port: $p, targetPort: $p, nodePort: $n}]' <<<"$service")"
    route_ports="$(jq -c --argjson p "$container" '. + [{protocol: "TCP", port: $p}]' <<<"$route_ports")"
    target_ports="$(jq -c --argjson p "$target" '. + [{protocol: "TCP", port: $p}] | unique' <<<"$target_ports")"
  done
  args+=("--health" ":8080")
  ports="$(jq -c '. + [{name: "health", containerPort: 8080}]' <<<"$ports")"
  ARGS="$(printf '%s\n' "${args[@]}" | jq -Rcn '[inputs]')" PORTS="$ports" SERVICE="$service" ROUTE_PORTS="$route_ports" \
    TARGET_PORTS="$target_ports" CELLS="$cell_peers" NODES="$node_peers" TARGET="$target_peers" NAME="$name" IMAGE="$relay_image" yq '
    select(.kind == "Deployment" or .kind == "Service" or .kind == "NetworkPolicy")
    | (.. | select(. == "@RELAY@")) = strenv(NAME)
    | (.. | select(. == "@RELAY_IMAGE@")) = strenv(IMAGE)
    | (.. | select(. == "@RELAY_ARGS@")) |= (env(ARGS) | ... style="")
    | (.. | select(. == "@RELAY_PORTS@")) |= (env(PORTS) | ... style="")
    | (.. | select(. == "@SERVICE_PORTS@")) |= (env(SERVICE) | ... style="")
    | (.. | select(. == "@ROUTE_PORTS@")) |= (env(ROUTE_PORTS) | ... style="")
    | (.. | select(. == "@TARGET_PORTS@")) |= (env(TARGET_PORTS) | ... style="")
    | (.. | select(. == "@CELL_PEERS@")) |= (env(CELLS) | ... style="")
    | (.. | select(. == "@NODE_PEERS@")) |= (env(NODES) | ... style="")
    | (.. | select(. == "@TARGET_PEERS@")) |= (env(TARGET) | ... style="")' "$here/manifests.yaml"
}

view="$(relay relay-view "$RELAY_VIEW_ROUTES")" || die "could not render relay-view"
telemetry="$(relay relay-telemetry "$RELAY_TELEMETRY_ROUTES")" || die "could not render relay-telemetry"
bind=""
[[ -z "${bind_routes// /}" ]] || bind="$(relay relay-bind "$bind_routes")" || die "could not render relay-bind"
yq 'select(.kind == "Namespace" or .kind == "ServiceAccount")' "$here/manifests.yaml"
echo "---"
echo "$view"
echo "---"
echo "$telemetry"
if [[ -n "$bind" ]]; then
  echo "---"
  echo "$bind"
fi
cat <<EOF
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny
  namespace: $namespace
spec:
  podSelector: {}
  policyTypes: [Ingress, Egress]
---
# The relay resolves the collector name, so the namespace needs DNS.
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
EOF
