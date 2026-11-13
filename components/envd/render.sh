#!/usr/bin/env bash
# Render envd, the environment executor of dev-cp, a harness component in namespace envd-system.
#
# The bundle holds Namespace envd-system, ServiceAccount envd, Deployment envd with the k8s_psat SPIRE
# agent sidecar, ConfigMaps peer-root and mgmt-spec-key, the objects of the sidecar, the
# NetworkPolicies default-deny, allow-dns and envd (flows N30, N31, N35, N8, N11 and N23), and Role
# and RoleBinding envd-records in spire-system. The Role lets envd write ConfigMap
# spire-system/cell-records, and nothing else. Every object carries the harness label of the component.
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
#   - the envd image that `mise run images` built, by digest.
# The pod template carries the SHA-256 of the peer root and of the key, so a change restarts the pod.
# Inputs: POC_ENV, SPIRE_TRUST_DOMAIN and RELAY_TARGET from the cell settings, and the cluster facts
# from build/<cluster>/facts.env.
set -euo pipefail
: "${CELL_NAME:?}" "${POC_ENV:?}" "${SPIRE_TRUST_DOMAIN:?}" "${RELAY_TARGET:?}"
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
  -e "s|@UPSTREAM@|$mgmt_ip:$api_port|" -e "s|@MGMT_TRUST_DOMAIN@|$mgmt_td|g" -e "s|@POC_ENV@|$POC_ENV|" "$here/manifests.yaml")"
grep -q '@[A-Z_]*@' <<<"$manifests" && die "the manifests keep a token that the render does not replace"

deployment="$(yq 'select(.kind == "Deployment")' <<<"$manifests" \
  | SPIRE_SIDECAR_SERVER_ADDRESS=spire-server.spire-system.svc.cluster.local SPIRE_SIDECAR_SERVER_PORT=8081 \
    SPIRE_SIDECAR_TRUST_DOMAIN="$SPIRE_TRUST_DOMAIN" SPIRE_SIDECAR_BUNDLE="$own_bundle" SPIRE_SIDECAR_CLUSTER="$CELL_NAME" \
    spire_sidecar envd k8s_psat)" || die "the SPIRE sidecar of envd failed"

# The envd policy. Flow N30 reaches the API node port of mgmtd. Flow N31 reaches the API server for
# ConfigMap cell-records: its node address, and the ClusterIP of its Service on 443. Flow N35 is allow-dns,
# which the namespace has apart from this policy. Flow N8 reaches the
# SPIRE server for the sidecar, and N11 the collector. Flow N23 admits the node addresses on the health
# port for the kubelet probes.
peers() { for ip in "$@"; do printf '{"ipBlock":{"cidr":"%s/32"}}\n' "$ip"; done | jq -cs .; }
policy="$(jq -n --arg ns "$namespace" --argjson mgmt "$(peers "$mgmt_ip")" --argjson mgmtport "$api_port" \
  --argjson api "$(peers $api_ips)" --argjson apiport "$API_SERVER_PORT" --argjson apisvc "$(peers "$API_SERVICE_IP")" \
  --argjson nodes "$(peers $node_ips)" '
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
       {to: [{namespaceSelector: {matchLabels: {"kubernetes.io/metadata.name": "observability-system"}},
              podSelector: {matchLabels: {"app.kubernetes.io/name": "otel-collector"}}}],
        ports: [{protocol: "TCP", port: 4317}]}]}}' | yq -P '.')"

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
} | COMP="$component" yq 'select(.kind != null)
    | .metadata.labels["cell.poc.internal/harness"] = strenv(COMP)
    | with(select(.spec.template.metadata != null); .spec.template.metadata.labels["cell.poc.internal/harness"] = strenv(COMP))'
