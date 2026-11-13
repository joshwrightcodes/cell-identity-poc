#!/usr/bin/env bash
# Render the mesh-view tunnel of one cell, a harness component. It owns the namespace
# mesh-view-system alone.
#
# The bundle holds Namespace mesh-view-system with a default deny, the tunnel Deployment with
# cell-proxy and a cluster_jwt SPIRE agent sidecar (tunnel.yaml), ConfigMap mgmt-root, the
# ClusterRole mesh-view-read and its binding, the Role for ConfigMaps in istio-system, the read-only
# guard of the ServiceAccount (guard.yaml), and the NetworkPolicies of flows N22, N24 and N11. Every object and the pod template carry the harness
# label cell.poc.internal/harness=mesh-view.
#
# The render reads these facts from outside the cell:
#   - the node address of SPIRE_SERVER_CLUSTER, the environment control plane, from the host
#     service. cell-proxy dials the relay there on 30445, and the SPIRE agent the server on 30081.
#   - the roots of the management trust domain, from the live SPIRE server of management, as
#     ConfigMap mgmt-root (components/lib/peer-root.sh). The pod template carries their SHA-256.
#   - the roots of the environment trust domain, from the server in SPIRE_SERVER_CLUSTER, for the
#     trust bundle of the SPIRE agent sidecar.
#   - the cell-proxy and cluster-jwt-agent images that `mise run images` built, by digest.
# Inputs: SPIRE_SERVER_CLUSTER from cells/<cluster>.env, POC_ENV from cells/common.env, and the
# cluster facts from build/<cluster>/facts.env.
set -euo pipefail
: "${CELL_NAME:?}" "${SPIRE_SERVER_CLUSTER:?}" "${POC_ENV:?}"
: "${API_SERVER_IPS:?}" "${API_SERVER_PORT:?}" "${API_SERVICE_IP:?}" "${DNS_SERVICE_IP:?}"

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
component=mesh-view
namespace=mesh-view-system
env_td=dev.env.poc.internal
mgmt_cluster=management
mgmt_td=mgmt.poc.internal
relay_port=30445
spire_node_port=30081

die() { printf 'error: mesh-view render: %s\n' "$*" >&2; exit 1; }

source "$root/scripts/ko-image.sh"
source "$root/components/lib/addresses.sh"
source "$root/components/lib/peer-root.sh"
source "$root/components/lib/spire-sidecar.sh"

[[ "$POC_ENV" =~ ^[a-z0-9][a-z0-9-]{0,30}$ ]] || die "POC_ENV '$POC_ENV' is not a short DNS label"
ipv4='^([0-9]{1,3}\.){3}[0-9]{1,3}$'
[[ "$API_SERVICE_IP" =~ $ipv4 && "$DNS_SERVICE_IP" =~ $ipv4 ]] || die "API_SERVICE_IP or DNS_SERVICE_IP is not an IPv4 address"
[[ "$API_SERVER_PORT" =~ ^[0-9]+$ ]] || die "API_SERVER_PORT '$API_SERVER_PORT' is not a port number"
api_ips="$(ipv4_list API_SERVER_IPS)" || exit 1

if ! facts="$(cd "$root" && mise run hostsvc -- facts --cluster "$SPIRE_SERVER_CLUSTER" 2>/dev/null)"; then
  die "no host service facts for $SPIRE_SERVER_CLUSTER: ${facts:-no output}. Run: CELL=$SPIRE_SERVER_CLUSTER mise run cell:up"
fi
env_ip="$(jq -r '.nodeIP // ""' <<<"$facts")"
[[ "$env_ip" =~ $ipv4 ]] || die "node address of $SPIRE_SERVER_CLUSTER is '$env_ip', not an IPv4 address"

cell_proxy_image="$(ko_image cell-proxy)" || die "no cell-proxy image"
mgmt_root="$(peer_root_configmap mgmt-root "$namespace" "$mgmt_cluster" "$mgmt_td")" || exit 1
mgmt_sum="$(yq -r '.metadata.annotations["poc.internal/peer-root-sha256"]' <<<"$mgmt_root")"
[[ "$mgmt_sum" =~ ^[0-9a-f]{64}$ ]] || die "ConfigMap mgmt-root has no checksum"
env_bundle="$(peer_root_pem "$SPIRE_SERVER_CLUSTER" "$env_td")" || exit 1

manifests="$(sed -e "s|@CELL_PROXY_IMAGE@|$cell_proxy_image|" -e "s|@PEER_ROOT_SHA256@|$mgmt_sum|" \
  -e "s|@UPSTREAM@|$env_ip:$relay_port|" "$here/tunnel.yaml")"
deployment="$(yq 'select(.kind == "Deployment")' <<<"$manifests" \
  | SPIRE_SIDECAR_SERVER_ADDRESS="$env_ip" SPIRE_SIDECAR_SERVER_PORT="$spire_node_port" SPIRE_SIDECAR_TRUST_DOMAIN="$env_td" \
    SPIRE_SIDECAR_BUNDLE="$env_bundle" SPIRE_SIDECAR_CELL="@CELL_NAME@" \
    spire_sidecar mesh-view cluster_jwt)" || die "the SPIRE sidecar of the tunnel failed"

api_peers() {
  local ip
  for ip in $api_ips; do
    printf '        - ipBlock:\n            cidr: %s/32\n' "$ip"
  done
}

policies() {
  cat <<EOF2
apiVersion: v1
kind: Namespace
metadata:
  name: $namespace
  labels:
    istio-injection: disabled
    pod-security.kubernetes.io/enforce: restricted
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
# Flow N24: every pod resolves the Service names of its peers.
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
---
# The tunnel pod accepts no connection: the probes run inside the pod, and the tunnel is an
# outbound connection. Flow N22: it reaches the relay and the SPIRE server of $SPIRE_SERVER_CLUSTER by node
# address, and the API server of this cell. Flow N11: it exports its own OTLP to the collector.
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: mesh-view
  namespace: $namespace
spec:
  podSelector:
    matchLabels:
      app.kubernetes.io/name: mesh-view
  policyTypes: [Ingress, Egress]
  egress:
    - to:
        - ipBlock:
            cidr: $env_ip/32
      ports:
        - protocol: TCP
          port: $relay_port
        - protocol: TCP
          port: $spire_node_port
    - to:
$(api_peers)
      ports:
        - protocol: TCP
          port: $API_SERVER_PORT
    - to:
        - ipBlock:
            cidr: $API_SERVICE_IP/32
      ports:
        - protocol: TCP
          port: 443
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: observability-system
          podSelector:
            matchLabels:
              app.kubernetes.io/name: otel-collector
      ports:
        - protocol: TCP
          port: 4317
EOF2
}

# Every object carries the harness label of the component, and the pod template too, so cell:verify
# can tie each pod of the ServiceAccount to its workload.
{
  policies
  echo "---"
  yq 'select(.kind != "Deployment")' <<<"$manifests"
  echo "---"
  sed "s|@POC_ENV@|$POC_ENV|g" "$here/guard.yaml"
  echo "---"
  echo "$deployment"
  echo "---"
  echo "$mgmt_root"
} | COMP="$component" yq 'select(.kind != null)
    | .metadata.labels["cell.poc.internal/harness"] = strenv(COMP)
    | with(select(.spec.template.metadata != null); .spec.template.metadata.labels["cell.poc.internal/harness"] = strenv(COMP))'
