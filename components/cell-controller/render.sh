#!/usr/bin/env bash
# Render the cell controller of dev-cp, a harness component in namespace cell-controller-system.
#
# The bundle holds Namespace cell-controller-system, ServiceAccount cell-controller, Deployment cell-controller
# with the k8s_psat SPIRE agent sidecar, Role and RoleBinding cell-controller, Role and RoleBinding envd-steps (the
# Role that lets envd write ConfigMap cell-steps and read step-status, so the namespace exists before envd uses it),
# ConfigMaps hostsvc-pin and mgmt-spec-key, the objects of the sidecar, and the NetworkPolicies default-deny,
# allow-dns and cell-controller (flows N42, N43, N44, N8, N11 and N23). Every object carries the harness label of the
# component.
#
# The render reads these facts from outside the cluster, so the harness runs it after the waves:
#   - the host service: it starts when it does not serve, and its certificate goes into ConfigMap hostsvc-pin. The
#     one address that host.docker.internal has in the node container of this cluster goes into --hostsvc-addr and
#     into the egress rule of flow N42, with HOSTSVC_PORT.
#   - the public signing key of mgmtd, from ConfigMap mgmt-signing-pub in management, cross-checked with mgmtd, as key
#     spec.pub of ConfigMap mgmt-spec-key. The staged key goes in as next.pub, and only when it equals stagedKey.
#   - the root of the environment trust domain, from the live SPIRE server of this cluster, for the trust bundle of
#     the sidecar.
#   - the cell controller image that `mise run images` built, by digest.
# The pod template carries the SHA-256 of the pin and of the keys, so a change restarts the pod.
# Inputs: POC_ENV, SPIRE_TRUST_DOMAIN and HOSTSVC_PORT from the cell settings, and the cluster facts from
# build/<cluster>/facts.env.
set -euo pipefail
: "${CELL_NAME:?}" "${POC_ENV:?}" "${SPIRE_TRUST_DOMAIN:?}" "${HOSTSVC_PORT:?}"
: "${NODE_IPS:?}" "${API_SERVER_IPS:?}" "${API_SERVER_PORT:?}" "${API_SERVICE_IP:?}" "${DNS_SERVICE_IP:?}"

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
namespace=cell-controller-system
component=cell-controller

die() { printf 'error: cell-controller render: %s\n' "$*" >&2; exit 1; }

source "$root/scripts/ko-image.sh"
source "$root/components/lib/addresses.sh"
source "$root/components/lib/peer-root.sh"
source "$root/components/lib/mgmt-key.sh"
source "$root/components/lib/hostsvc-pin.sh"
source "$root/components/lib/spire-sidecar.sh"

[[ "$POC_ENV" =~ ^[a-z0-9][a-z0-9-]{0,30}$ ]] || die "POC_ENV '$POC_ENV' is not a short DNS label"
[[ "$SPIRE_TRUST_DOMAIN" == dev.env.poc.internal ]] || die "SPIRE_TRUST_DOMAIN '$SPIRE_TRUST_DOMAIN' is not dev.env.poc.internal, the domain of the cell controller ID"
ipv4='^([0-9]{1,3}\.){3}[0-9]{1,3}$'
[[ "$DNS_SERVICE_IP" =~ $ipv4 && "$API_SERVICE_IP" =~ $ipv4 ]] || die "DNS_SERVICE_IP or API_SERVICE_IP is not an IPv4 address"
[[ "$API_SERVER_PORT" =~ ^[0-9]+$ ]] || die "API_SERVER_PORT '$API_SERVER_PORT' is not a port number"
[[ "$HOSTSVC_PORT" =~ ^[1-9][0-9]{0,4}$ ]] && ((HOSTSVC_PORT <= 65535)) || die "HOSTSVC_PORT '$HOSTSVC_PORT' is not a port"
node_ips="$(ipv4_list NODE_IPS)" || exit 1
api_ips="$(ipv4_list API_SERVER_IPS)" || exit 1

host_ip="$(hostsvc_address "$CELL_NAME")" || exit 1
pin="$(hostsvc_pin_configmap "$namespace")" || exit 1
pin_sum="$(yq -r '.metadata.annotations["poc.internal/hostsvc-pin-sha256"]' <<<"$pin")"
[[ "$pin_sum" =~ ^[0-9a-f]{64}$ ]] || die "the host service pin has no checksum"

spec_pub="$(mgmt_signing_pub)" || exit 1
next_pub="$(mgmt_signing_next_pub)" || exit 1
# The checksum covers the staged key too, so the stage pass and the later passes of a rotation each restart the pod.
spec_sum="$(printf '%s' "$spec_pub${next_pub:+$'\n'$next_pub}" | sha256)"
spec_key="$(NS="$namespace" PUB="$spec_pub" NEXT="$next_pub" SUM="$spec_sum" yq -n '
  .apiVersion = "v1" | .kind = "ConfigMap" | .metadata.name = "mgmt-spec-key" | .metadata.namespace = strenv(NS)
  | .metadata.annotations["poc.internal/spec-key-sha256"] = strenv(SUM)
  | .data["spec.pub"] = strenv(PUB)
  | (select(strenv(NEXT) != "") | .data["next.pub"]) = strenv(NEXT)')"
own_bundle="$(peer_root_pem "$CELL_NAME" "$SPIRE_TRUST_DOMAIN")" || exit 1
image="$(ko_image cell-controller)" || die "no cell-controller image"

manifests="$(sed -e "s|@CELL_CONTROLLER_IMAGE@|$image|" -e "s|@HOSTSVC_PIN_SHA256@|$pin_sum|" -e "s|@SPEC_KEY_SHA256@|$spec_sum|" \
  -e "s|@HOSTSVC_ADDR@|$host_ip:$HOSTSVC_PORT|" -e "s|@POC_ENV@|$POC_ENV|" "$here/manifests.yaml")"
grep -q '@[A-Z_]*@' <<<"$manifests" && die "the manifests keep a token that the render does not replace"

deployment="$(yq 'select(.kind == "Deployment")' <<<"$manifests" \
  | SPIRE_SIDECAR_SERVER_ADDRESS=spire-server.spire-system.svc.cluster.local SPIRE_SIDECAR_SERVER_PORT=8081 \
    SPIRE_SIDECAR_TRUST_DOMAIN="$SPIRE_TRUST_DOMAIN" SPIRE_SIDECAR_BUNDLE="$own_bundle" SPIRE_SIDECAR_CLUSTER="$CELL_NAME" \
    spire_sidecar cell-controller k8s_psat)" || die "the SPIRE sidecar of cell-controller failed"

# The cell controller policy. Flow N42 reaches the host service on HOSTSVC_PORT, at the one address that the node
# resolves, and no other port of it. Flow N43 reaches the API server for the two ConfigMaps: its node address, and the
# ClusterIP of its Service on 443. Flow N8 reaches the SPIRE server for the sidecar, and N11 the collector. Flow N23
# admits the node addresses on the health port for the kubelet probes. Flow N44 is allow-dns, which the namespace has
# apart from this policy.
peers() { for ip in "$@"; do printf '{"ipBlock":{"cidr":"%s/32"}}\n' "$ip"; done | jq -cs .; }
policy="$(jq -n --arg ns "$namespace" --argjson host "$(peers "$host_ip")" --argjson hostport "$HOSTSVC_PORT" \
  --argjson api "$(peers $api_ips)" --argjson apiport "$API_SERVER_PORT" --argjson apisvc "$(peers "$API_SERVICE_IP")" \
  --argjson nodes "$(peers $node_ips)" '
  {apiVersion: "networking.k8s.io/v1", kind: "NetworkPolicy", metadata: {name: "cell-controller", namespace: $ns},
   spec: {podSelector: {matchLabels: {"app.kubernetes.io/name": "cell-controller"}}, policyTypes: ["Ingress", "Egress"],
     ingress: [{from: $nodes, ports: [{protocol: "TCP", port: 8080}]}],
     egress: [
       {to: $host, ports: [{protocol: "TCP", port: $hostport}]},
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
# Flow N44: every pod of the namespace resolves names through the cluster DNS.
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
  echo "$pin"
  echo "---"
  echo "$spec_key"
  echo "---"
  echo "$policy"
  echo "---"
  echo "$dns"
} | COMP="$component" yq 'select(.kind != null)
    | .metadata.labels["cell.poc.internal/harness"] = strenv(COMP)
    | with(select(.spec.template.metadata != null); .spec.template.metadata.labels["cell.poc.internal/harness"] = strenv(COMP))'
