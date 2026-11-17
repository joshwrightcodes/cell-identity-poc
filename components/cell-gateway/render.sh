#!/usr/bin/env bash
# Render the cell gateway of dev-cp, a harness component in namespace gateway-system.
#
# The bundle holds Namespace gateway-system, ServiceAccount cell-gateway, StatefulSet cell-gateway with
# the k8s_psat SPIRE agent sidecar, Services cell-gateway-stream (node port 30450), cell-gateway-bind
# (30451) and cell-gateway (8452), ConfigMap mgmt-spec-key, the objects of the sidecar, and the
# NetworkPolicies default-deny, allow-dns and cell-gateway (flows N37 to N40, N8, N11 and N23). Every
# object carries the harness label of the component.
#
# The render reads these facts from outside the cluster, so the harness runs it after the waves:
#   - the node address of each cell of the topology that has the cell-identity set, from the host
#     service. Each one goes into a --cell-node argument and into the ingress rules of flows N37 and N38.
#   - the public signing key of mgmtd, from ConfigMap mgmt-signing-pub in management, as ConfigMap
#     mgmt-spec-key. envd and the SPIRE server of this cluster pin the same key.
#   - the root of the environment trust domain, from the live SPIRE server of this cluster, for the
#     trust bundle of the sidecar.
#   - the cellgw image that `mise run images` built, by digest.
# The pod template carries the SHA-256 of the key, so a change restarts the pod.
# Inputs: POC_ENV and SPIRE_TRUST_DOMAIN from the cell settings, and the cluster facts from
# build/<cluster>/facts.env.
set -euo pipefail
: "${CELL_NAME:?}" "${POC_ENV:?}" "${SPIRE_TRUST_DOMAIN:?}"
: "${NODE_IPS:?}" "${DNS_SERVICE_IP:?}"

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
namespace=gateway-system
component=cell-gateway

die() { printf 'error: cell-gateway render: %s\n' "$*" >&2; exit 1; }

source "$root/scripts/ko-image.sh"
source "$root/components/lib/addresses.sh"
source "$root/components/lib/peer-root.sh"
source "$root/components/lib/mgmt-key.sh"
source "$root/components/lib/spire-sidecar.sh"

[[ "$POC_ENV" =~ ^[a-z0-9][a-z0-9-]{0,30}$ ]] || die "POC_ENV '$POC_ENV' is not a short DNS label"
[[ "$SPIRE_TRUST_DOMAIN" == dev.env.poc.internal ]] || die "SPIRE_TRUST_DOMAIN '$SPIRE_TRUST_DOMAIN' is not dev.env.poc.internal, the domain of the gateway ID"
ipv4='^([0-9]{1,3}\.){3}[0-9]{1,3}$'
[[ "$DNS_SERVICE_IP" =~ $ipv4 ]] || die "DNS_SERVICE_IP is not an IPv4 address"
node_ips="$(ipv4_list NODE_IPS)" || exit 1

cells="$(yq -r '.clusters[] | select(.components[] == "cell-identity") | .name' "$root/harness/topology.yaml")" || die "could not read the topology"
[[ -n "$cells" ]] || die "no cluster in harness/topology.yaml has the cell-identity set, so the gateway has no cell"
cell_ips=() cell_args=""
for cell in $cells; do
  if ! facts="$(cd "$root" && mise run hostsvc -- facts --cluster "$cell" 2>/dev/null)"; then
    die "no host service facts for $cell: ${facts:-no output}. Create the cluster: mise run hostsvc -- up --only $cell"
  fi
  ip="$(jq -r '.nodeIP // ""' <<<"$facts")"
  [[ "$ip" =~ $ipv4 ]] || die "node address of $cell is '$ip', not an IPv4 address"
  cell_ips+=("$ip")
  cell_args+="            - --cell-node=$cell=$ip"$'\n'
done
cell_args="${cell_args%$'\n'}"

spec_pub="$(mgmt_signing_pub)" || exit 1
spec_sum="$(printf '%s' "$spec_pub" | sha256)"
spec_key="$(NS="$namespace" PUB="$spec_pub" SUM="$spec_sum" yq -n '
  .apiVersion = "v1" | .kind = "ConfigMap" | .metadata.name = "mgmt-spec-key" | .metadata.namespace = strenv(NS)
  | .metadata.annotations["poc.internal/spec-key-sha256"] = strenv(SUM)
  | .data["spec.pub"] = strenv(PUB)')"
own_bundle="$(peer_root_pem "$CELL_NAME" "$SPIRE_TRUST_DOMAIN")" || exit 1
gateway_image="$(ko_image cellgw)" || die "no cellgw image"

manifests="$(sed -e "s|@CELLGW_IMAGE@|$gateway_image|" -e "s|@SPEC_KEY_SHA256@|$spec_sum|" \
  -e "s|@SPIRE_TRUST_DOMAIN@|$SPIRE_TRUST_DOMAIN|g" -e "s|@POC_ENV@|$POC_ENV|" "$here/manifests.yaml" \
  | ARGS="$cell_args" awk '$0 == "@CELL_NODE_ARGS@" { print ENVIRON["ARGS"]; next } { print }')"
grep -q '@[A-Z_]*@' <<<"$manifests" && die "the manifests keep a token that the render does not replace"

statefulset="$(yq 'select(.kind == "StatefulSet")' <<<"$manifests" \
  | SPIRE_SIDECAR_SERVER_ADDRESS=spire-server.spire-system.svc.cluster.local SPIRE_SIDECAR_SERVER_PORT=8081 \
    SPIRE_SIDECAR_TRUST_DOMAIN="$SPIRE_TRUST_DOMAIN" SPIRE_SIDECAR_BUNDLE="$own_bundle" SPIRE_SIDECAR_CLUSTER="$CELL_NAME" \
    spire_sidecar cell-gateway k8s_psat)" || die "the SPIRE sidecar of the cell gateway failed"

# The gateway policy. Flows N37 and N38 admit the cell node addresses on the stream and the bind port, each in
# its own rule. Flow N39 admits envd on 8452. Flow N23 admits the node addresses of this cluster on the
# health port for the kubelet probes. Flow N8 reaches the SPIRE server for the sidecar, and N11 the collector.
# Flow N40 is allow-dns, which the namespace has apart from this policy.
peers() { for ip in "$@"; do printf '{"ipBlock":{"cidr":"%s/32"}}\n' "$ip"; done | jq -cs .; }
policy="$(jq -n --arg ns "$namespace" --argjson cells "$(peers "${cell_ips[@]}")" --argjson nodes "$(peers $node_ips)" '
  {apiVersion: "networking.k8s.io/v1", kind: "NetworkPolicy", metadata: {name: "cell-gateway", namespace: $ns},
   spec: {podSelector: {matchLabels: {"app.kubernetes.io/name": "cell-gateway"}}, policyTypes: ["Ingress", "Egress"],
     ingress: [
       {from: $cells, ports: [{protocol: "TCP", port: 8450}]},
       {from: $cells, ports: [{protocol: "TCP", port: 8451}]},
       {from: [{namespaceSelector: {matchLabels: {"kubernetes.io/metadata.name": "envd-system"}},
                podSelector: {matchLabels: {"app.kubernetes.io/name": "envd"}}}],
        ports: [{protocol: "TCP", port: 8452}]},
       {from: $nodes, ports: [{protocol: "TCP", port: 8080}]}],
     egress: [
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
# Flow N40: every pod of the namespace resolves names through the cluster DNS.
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
  yq 'select(.kind != "StatefulSet")' <<<"$manifests"
  echo "---"
  echo "$statefulset"
  echo "---"
  echo "$spec_key"
  echo "---"
  echo "$policy"
  echo "---"
  echo "$dns"
} | COMP="$component" yq 'select(.kind != null)
    | .metadata.labels["cell.poc.internal/harness"] = strenv(COMP)
    | with(select(.spec.template.metadata != null); .spec.template.metadata.labels["cell.poc.internal/harness"] = strenv(COMP))'
