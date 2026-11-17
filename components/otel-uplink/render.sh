#!/usr/bin/env bash
# Render the uplink of the collector, a harness component in observability-system. COLLECTOR_PLANE
# picks the form:
#   cell         the upstream is the relay of SPIRE_SERVER_CLUSTER (dev-cp) on node port 30444. The
#                sidecar is a cluster_jwt agent that attests to the SPIRE server of dev-cp on node
#                port 30081, the peer root is ConfigMap mgmt-root, and the pod gets the SVID
#                spiffe://dev.env.poc.internal/cell/<cell>/otel.
#   environment  (dev-cp) the upstream is the gateway in RELAY_TARGET (management) on the node port
#                of RELAY_TELEMETRY_ROUTES. The sidecar is a k8s_psat agent that attests to the SPIRE
#                server of this cluster, the peer root is ConfigMap peer-root, and the pod gets the
#                SVID spiffe://dev.env.poc.internal/cp/otel.
# The bundle holds ServiceAccount, Deployment, Service and NetworkPolicy otel-uplink, the peer root
# ConfigMap, and the objects of the SPIRE agent sidecar (components/lib/spire-sidecar.sh). It holds
# no Namespace, because the namespaces bundle owns observability-system, so every object and the pod
# template carry the harness label cell.poc.internal/harness=otel-uplink.
#
# The render reads these facts from outside the cluster, so the harness runs it after the waves:
#   - the node address of the upstream cluster, from the host service.
#   - the roots of the management trust domain, from the live SPIRE server of management, for the
#     peer root ConfigMap (components/lib/peer-root.sh). The pod template carries their SHA-256.
#   - the roots of the environment trust domain, from the live SPIRE server of the environment
#     control plane, for the trust bundle of the sidecar.
#   - the cell-proxy and cluster-jwt-agent images that `mise run images` built, by digest.
# Inputs: COLLECTOR_PLANE, SPIRE_SERVER_CLUSTER (cell) or SPIRE_TRUST_DOMAIN, RELAY_TARGET and
# RELAY_TELEMETRY_ROUTES (dev-cp) from cells/<cluster>.env, POC_ENV from cells/common.env, and the
# cluster facts from build/<cluster>/facts.env.
set -euo pipefail
: "${CELL_NAME:?}" "${POC_ENV:?}" "${COLLECTOR_PLANE:?}" "${NODE_IPS:?}" "${API_SERVER_IPS:?}" "${API_SERVER_PORT:?}" "${API_SERVICE_IP:?}"

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
component=otel-uplink
namespace=observability-system
env_td=dev.env.poc.internal
mgmt_cluster=management
mgmt_td=mgmt.poc.internal
relay_port=30444
spire_node_port=30081

die() { printf 'error: otel-uplink render: %s\n' "$*" >&2; exit 1; }

source "$root/scripts/ko-image.sh"
source "$root/components/lib/addresses.sh"
source "$root/components/lib/peer-root.sh"
source "$root/components/lib/spire-sidecar.sh"

[[ "$POC_ENV" =~ ^[a-z0-9][a-z0-9-]{0,30}$ ]] || die "POC_ENV '$POC_ENV' is not a short DNS label"
ipv4='^([0-9]{1,3}\.){3}[0-9]{1,3}$'
node_ips="$(ipv4_list NODE_IPS)" || exit 1
api_ips="$(ipv4_list API_SERVER_IPS)" || exit 1
[[ "$API_SERVICE_IP" =~ $ipv4 ]] || die "API_SERVICE_IP '$API_SERVICE_IP' is not an IPv4 address"
[[ "$API_SERVER_PORT" =~ ^[0-9]+$ ]] || die "API_SERVER_PORT '$API_SERVER_PORT' is not a port number"

# node_ip_of <cluster> prints the node address of a cluster from the host service.
node_ip_of() {
  local facts ip
  if ! facts="$(cd "$root" && mise run hostsvc -- facts --cluster "$1" 2>/dev/null)"; then
    die "no host service facts for $1: ${facts:-no output}. Run: CELL=$1 mise run cell:up"
  fi
  ip="$(jq -r '.nodeIP // ""' <<<"$facts")"
  [[ "$ip" =~ $ipv4 ]] || die "node address of $1 is '$ip', not an IPv4 address"
  printf '%s\n' "$ip"
}

case "$COLLECTOR_PLANE" in
  cell)
    : "${SPIRE_SERVER_CLUSTER:?}"
    upstream_ip="$(node_ip_of "$SPIRE_SERVER_CLUSTER")" || exit 1
    upstream="$upstream_ip:$relay_port"
    peer_configmap=mgmt-root
    sidecar_mode=cluster_jwt
    sidecar_bundle="$(peer_root_pem "$SPIRE_SERVER_CLUSTER" "$env_td")" || exit 1
    ;;
  environment)
    : "${SPIRE_TRUST_DOMAIN:?}" "${RELAY_TARGET:?}" "${RELAY_TELEMETRY_ROUTES:?}"
    [[ "$SPIRE_TRUST_DOMAIN" == "$env_td" ]] || die "SPIRE_TRUST_DOMAIN '$SPIRE_TRUST_DOMAIN' is not $env_td"
    read -r -a routes <<<"$RELAY_TELEMETRY_ROUTES"
    ((${#routes[@]} == 1)) && [[ "${routes[0]}" =~ ^[0-9]+:[0-9]+=([0-9]+)$ ]] \
      || die "RELAY_TELEMETRY_ROUTES '$RELAY_TELEMETRY_ROUTES' is not one <node port>:<container port>=<target node port> route"
    gateway_port="${BASH_REMATCH[1]}"
    upstream_ip="$(node_ip_of "$RELAY_TARGET")" || exit 1
    upstream="$upstream_ip:$gateway_port"
    peer_configmap=peer-root
    sidecar_mode=k8s_psat
    sidecar_bundle="$(peer_root_pem "$CELL_NAME" "$SPIRE_TRUST_DOMAIN")" || exit 1
    ;;
  *) die "COLLECTOR_PLANE '$COLLECTOR_PLANE' is not cell or environment, so the cluster has no uplink" ;;
esac

cell_proxy_image="$(ko_image cell-proxy)" || die "no cell-proxy image"
peer_root="$(peer_root_configmap "$peer_configmap" "$namespace" "$mgmt_cluster" "$mgmt_td")" || exit 1
peer_sum="$(yq -r '.metadata.annotations["poc.internal/peer-root-sha256"]' <<<"$peer_root")"
[[ "$peer_sum" =~ ^[0-9a-f]{64}$ ]] || die "ConfigMap $peer_configmap has no checksum"

manifests="$(sed -e "s|@CELL_PROXY_IMAGE@|$cell_proxy_image|" -e "s|@PEER_ROOT_SHA256@|$peer_sum|" \
  -e "s|@PEER_ROOT_CONFIGMAP@|$peer_configmap|" -e "s|@UPSTREAM@|$upstream|" "$here/manifests.yaml")"

# In a cell, cell-proxy sends the proof of its pod before the first payload byte: --proof, the four variables of
# the pod identity, and a projected API token that only this container mounts. The uplink of dev-cp has an SVID of
# the cp path, which sends no proof.
if [[ "$COLLECTOR_PLANE" == cell ]]; then
  manifests="$(yq '
    (select(.kind == "Deployment") | .spec.template.spec.containers[] | select(.name == "cell-proxy")) |= (
      .args += ["--proof"]
      | .env += [
        {"name": "POD_UID", "valueFrom": {"fieldRef": {"fieldPath": "metadata.uid"}}},
        {"name": "POD_NAMESPACE", "valueFrom": {"fieldRef": {"fieldPath": "metadata.namespace"}}},
        {"name": "SERVICE_ACCOUNT", "valueFrom": {"fieldRef": {"fieldPath": "spec.serviceAccountName"}}}]
      | .volumeMounts += [{"name": "proof-api-token", "mountPath": "/var/run/secrets/kubernetes.io/serviceaccount", "readOnly": true}])
    | (select(.kind == "Deployment") | .spec.template.spec.volumes) += [{"name": "proof-api-token", "projected": {"sources": [
        {"serviceAccountToken": {"path": "token", "expirationSeconds": 3600}},
        {"configMap": {"name": "kube-root-ca.crt", "items": [{"key": "ca.crt", "path": "ca.crt"}]}},
        {"downwardAPI": {"items": [{"path": "namespace", "fieldRef": {"fieldPath": "metadata.namespace"}}]}}]}}]' <<<"$manifests")"
fi

if [[ "$sidecar_mode" == cluster_jwt ]]; then
  deployment="$(yq 'select(.kind == "Deployment")' <<<"$manifests" \
    | SPIRE_SIDECAR_SERVER_ADDRESS="$upstream_ip" SPIRE_SIDECAR_SERVER_PORT="$spire_node_port" SPIRE_SIDECAR_TRUST_DOMAIN="$env_td" \
      SPIRE_SIDECAR_BUNDLE="$sidecar_bundle" SPIRE_SIDECAR_CELL="@CELL_NAME@" \
      spire_sidecar otel-uplink cluster_jwt)" || die "the SPIRE sidecar of the uplink failed"
else
  deployment="$(yq 'select(.kind == "Deployment")' <<<"$manifests" \
    | SPIRE_SIDECAR_SERVER_ADDRESS=spire-server.spire-system.svc.cluster.local SPIRE_SIDECAR_SERVER_PORT=8081 \
      SPIRE_SIDECAR_TRUST_DOMAIN="$SPIRE_TRUST_DOMAIN" SPIRE_SIDECAR_BUNDLE="$sidecar_bundle" SPIRE_SIDECAR_CLUSTER="$CELL_NAME" \
      spire_sidecar otel-uplink k8s_psat)" || die "the SPIRE sidecar of the uplink failed"
fi

node_peers() {
  local ip
  for ip in $node_ips; do
    printf '        - ipBlock:\n            cidr: %s/32\n' "$ip"
  done
}
api_peers() {
  local ip
  for ip in $api_ips; do
    printf '        - ipBlock:\n            cidr: %s/32\n' "$ip"
  done
}

policy() {
  cat <<EOF
# Flows N8, N19 and N21 for the uplink pod. The pod admits the collector of the cluster on 4319, and a
# node address on 4319 for the kubelet probes (flow N23). Its egress is the SPIRE server, the
# upstream, and the collector for its own telemetry. The pod has no mesh proxy.
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: otel-uplink
  namespace: $namespace
spec:
  podSelector:
    matchLabels:
      app.kubernetes.io/name: otel-uplink
  policyTypes: [Ingress, Egress]
  ingress:
    - from:
        - podSelector:
            matchLabels:
              app.kubernetes.io/name: otel-collector
      ports:
        - protocol: TCP
          port: 4319
    - from:
$(node_peers)
      ports:
        - protocol: TCP
          port: 4319
  egress:
    - to:
        - podSelector:
            matchLabels:
              app.kubernetes.io/name: otel-collector
      ports:
        - protocol: TCP
          port: 4317
EOF
  if [[ "$sidecar_mode" == cluster_jwt ]]; then
    cat <<EOF
    - to:
        - ipBlock:
            cidr: $upstream_ip/32
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
EOF
  else
    cat <<EOF
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: spire-system
          podSelector:
            matchLabels:
              app.kubernetes.io/name: spire-server
      ports:
        - protocol: TCP
          port: 8081
    - to:
        - ipBlock:
            cidr: $upstream_ip/32
      ports:
        - protocol: TCP
          port: $gateway_port
EOF
  fi
}

# Every object carries the harness label of the component, and the pod template too, so cell:verify
# can tie each pod of the ServiceAccount to its workload.
{
  yq 'select(.kind != "Deployment")' <<<"$manifests"
  echo "---"
  echo "$deployment"
  echo "---"
  echo "$peer_root"
  echo "---"
  policy
} | COMP="$component" yq 'select(.kind != null)
    | .metadata.labels["cell.poc.internal/harness"] = strenv(COMP)
    | with(select(.spec.template.metadata != null); .spec.template.metadata.labels["cell.poc.internal/harness"] = strenv(COMP))'
