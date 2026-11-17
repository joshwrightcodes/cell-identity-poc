#!/usr/bin/env bash
# Render the management plane stand-in of management, a link component in namespace mgmt-system.
#
# The bundle holds Namespace mgmt-system, ServiceAccount, Role and RoleBinding, StatefulSet mgmtd with
# the k8s_psat SPIRE agent sidecar, Service mgmt-api (node port 31446), the
# ConfigMaps mgmt-intent, hostsvc-pin and peer-root, the objects of the sidecar, and the
# NetworkPolicies default-deny, allow-dns and mgmtd (flows N26, N28, N29, N8, N11 and N23). Every
# object carries the harness label of the component. mgmtd makes ConfigMap mgmt-signing-pub itself, and
# ConfigMap cell-registry in the namespaces of the view servers (--registry-namespaces in manifests.yaml).
#
# The render reads these facts from outside the cluster, so it runs in the link phase:
#   - the host service (components/lib/hostsvc-pin.sh): it starts when it does not serve, and the
#     render copies its certificate into ConfigMap hostsvc-pin. The address of host.docker.internal
#     in the node container of this cluster goes into the argument --hostsvc-addr and into the
#     egress rule of flow N28.
#   - the intent: the cells are the clusters that harness/topology.yaml gives the cell-identity set,
#     and the subjects of each cell come from SPIRE_CELL_SUBJECTS in cells/dev-cp.env.
#   - the root of the environment trust domain, from the live SPIRE server of VIEW_CONTROL_PLANE, as
#     ConfigMap peer-root. The render leaves it out only when VIEW_CONTROL_PLANE does not exist or its
#     SPIRE server StatefulSet does not exist. When the StatefulSet exists, a failed read stops the
#     render. The node address of VIEW_CONTROL_PLANE goes into the ingress rule of flow N26, and the
#     render leaves that rule out while the cluster does not exist.
#   - the root of the management trust domain, from the live SPIRE server of this cluster, for the
#     trust bundle of the sidecar.
#   - the mgmtd image that `mise run images` built, by digest.
# The pod template carries the SHA-256 of the peer root (absent when it is left out), of the
# host service certificate and of the intent, so a change restarts the pod.
# Inputs: POC_ENV, SPIRE_TRUST_DOMAIN, VIEW_CONTROL_PLANE and HOSTSVC_PORT from the cell settings, and
# the cluster facts from build/<cluster>/facts.env.
set -euo pipefail
: "${CELL_NAME:?}" "${POC_ENV:?}" "${SPIRE_TRUST_DOMAIN:?}" "${VIEW_CONTROL_PLANE:?}" "${HOSTSVC_PORT:?}"
: "${NODE_IPS:?}" "${API_SERVER_IPS:?}" "${API_SERVER_PORT:?}" "${API_SERVICE_IP:?}" "${DNS_SERVICE_IP:?}"

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
namespace=mgmt-system
component=mgmt-api
env_cluster="$VIEW_CONTROL_PLANE"
env_td=dev.env.poc.internal
bind_namespace=cell-identity-system
bind_account=celld

die() { printf 'error: mgmt-api render: %s\n' "$*" >&2; exit 1; }

source "$root/scripts/ko-image.sh"
source "$root/components/lib/addresses.sh"
source "$root/components/lib/peer-root.sh"
source "$root/components/lib/hostsvc-pin.sh"
source "$root/components/lib/spire-sidecar.sh"

[[ "$POC_ENV" =~ ^[a-z0-9][a-z0-9-]{0,30}$ ]] || die "POC_ENV '$POC_ENV' is not a short DNS label"
[[ "$SPIRE_TRUST_DOMAIN" == mgmt.poc.internal ]] || die "SPIRE_TRUST_DOMAIN '$SPIRE_TRUST_DOMAIN' is not mgmt.poc.internal, the domain of the mgmtd ID"
[[ "$HOSTSVC_PORT" =~ ^[1-9][0-9]{0,4}$ ]] && ((HOSTSVC_PORT <= 65535)) || die "HOSTSVC_PORT '$HOSTSVC_PORT' is not a port"
ipv4='^([0-9]{1,3}\.){3}[0-9]{1,3}$'
[[ "$DNS_SERVICE_IP" =~ $ipv4 && "$API_SERVICE_IP" =~ $ipv4 ]] || die "DNS_SERVICE_IP or API_SERVICE_IP is not an IPv4 address"
[[ "$API_SERVER_PORT" =~ ^[0-9]+$ ]] || die "API_SERVER_PORT '$API_SERVER_PORT' is not a port number"
node_ips="$(ipv4_list NODE_IPS)" || exit 1
api_ips="$(ipv4_list API_SERVER_IPS)" || exit 1

# The intent: the cells with the cell-identity set, and the subjects that each of them may present.
cells="$(yq -r '.clusters[] | select(.components[] == "cell-identity") | .name' "$root/harness/topology.yaml")" || die "could not read the topology"
[[ -n "$cells" ]] || die "no cluster in harness/topology.yaml has the cell-identity set, so the intent has no cell"
subjects_raw="$(source "$root/cells/dev-cp.env"; printf '%s\n' "${SPIRE_CELL_SUBJECTS:-}")"
[[ -n "$subjects_raw" ]] || die "cells/dev-cp.env sets no SPIRE_CELL_SUBJECTS"
subjects='[]'
for entry in $subjects_raw; do
  [[ "$entry" =~ ^([a-z0-9-]+)/([a-z0-9-]+)(=[a-z0-9-]+)?$ ]] || die "SPIRE_CELL_SUBJECTS entry '$entry' is not <namespace>/<service account>=<role>"
  subjects="$(jq -c --arg ns "${BASH_REMATCH[1]}" --arg sa "${BASH_REMATCH[2]}" '. + [{namespace: $ns, serviceAccount: $sa}]' <<<"$subjects")"
done
jq -e --arg ns "$bind_namespace" --arg sa "$bind_account" 'any(.[]; .namespace == $ns and .serviceAccount == $sa)' <<<"$subjects" >/dev/null \
  || die "SPIRE_CELL_SUBJECTS in cells/dev-cp.env lacks the bind subject $bind_namespace/$bind_account"
intent="$(printf '%s\n' $cells | jq -Rcn --arg env "$POC_ENV" --arg ns "$bind_namespace" --arg sa "$bind_account" --argjson subjects "$subjects" \
  '{env: $env, bindSubject: {namespace: $ns, serviceAccount: $sa}, cells: [inputs | select(length > 0) | {name: ., subjects: $subjects}]}')" \
  || die "could not build the intent"
intent_sum="$(printf '%s' "$intent" | sha256)"
intent_cm="$(NS="$namespace" INTENT="$intent" yq -n '
  .apiVersion = "v1" | .kind = "ConfigMap" | .metadata.name = "mgmt-intent" | .metadata.namespace = strenv(NS)
  | .metadata.annotations["poc.internal/intent-sha256"] = "'"$intent_sum"'"
  | .data["intent.json"] = strenv(INTENT)')"

host_ip="$(hostsvc_address "$CELL_NAME")" || exit 1
pin="$(hostsvc_pin_configmap "$namespace")" || exit 1
pin_sum="$(yq -r '.metadata.annotations["poc.internal/hostsvc-pin-sha256"]' <<<"$pin")"
[[ "$pin_sum" =~ ^[0-9a-f]{64}$ ]] || die "the host service pin has no checksum"
own_bundle="$(peer_root_pem "$CELL_NAME" "$SPIRE_TRUST_DOMAIN")" || exit 1

# The environment control plane: the peer root and the node address.
peer_root="" peer_sum=absent env_ip=""
kind_clusters="$(kind get clusters 2>/dev/null || true)"
if grep -qx "$env_cluster" <<<"$kind_clusters"; then
  if ! facts="$(cd "$root" && mise run hostsvc -- facts --cluster "$env_cluster" 2>/dev/null)"; then
    die "no host service facts for $env_cluster: ${facts:-no output}. Run: CELL=$env_cluster mise run cell:up"
  fi
  env_ip="$(jq -r '.nodeIP // ""' <<<"$facts")"
  [[ "$env_ip" =~ $ipv4 ]] || die "node address of $env_cluster is '$env_ip', not an IPv4 address"
  server="$(kubectl --context "kind-$env_cluster" -n spire-system get statefulset spire-server -o name --ignore-not-found)" \
    || die "could not read StatefulSet spire-server in $env_cluster"
  if [[ -n "$server" ]]; then
    peer_root="$(peer_root_configmap peer-root "$namespace" "$env_cluster" "$env_td")" || exit 1
    peer_sum="$(yq -r '.metadata.annotations["poc.internal/peer-root-sha256"]' <<<"$peer_root")"
    [[ "$peer_sum" =~ ^[0-9a-f]{64}$ ]] || die "the peer root has no checksum"
  fi
fi

mgmtd_image="$(ko_image mgmtd)" || die "no mgmtd image"

peers() { for ip in "$@"; do printf '{"ipBlock":{"cidr":"%s/32"}}\n' "$ip"; done | jq -cs .; }
manifests="$(sed -e "s|@MGMTD_IMAGE@|$mgmtd_image|" -e "s|@PEER_ROOT_SHA256@|$peer_sum|" -e "s|@HOSTSVC_PIN_SHA256@|$pin_sum|" \
  -e "s|@INTENT_SHA256@|$intent_sum|" -e "s|@PEER_TRUST_DOMAIN@|$env_td|g" -e "s|@HOSTSVC_ADDR@|$host_ip:$HOSTSVC_PORT|" "$here/manifests.yaml")"
grep -q '@[A-Z_]*@' <<<"$manifests" && die "the manifests keep a token that the render does not replace"

statefulset="$(yq 'select(.kind == "StatefulSet")' <<<"$manifests" \
  | SPIRE_SIDECAR_SERVER_ADDRESS=spire-server.spire-system.svc.cluster.local SPIRE_SIDECAR_SERVER_PORT=8081 \
    SPIRE_SIDECAR_TRUST_DOMAIN="$SPIRE_TRUST_DOMAIN" SPIRE_SIDECAR_BUNDLE="$own_bundle" SPIRE_SIDECAR_CLUSTER="$CELL_NAME" \
    spire_sidecar mgmtd k8s_psat)" || die "the SPIRE sidecar of mgmtd failed"

# The mgmtd policy: flow N8 (SPIRE sidecar to the SPIRE server), N28 (key requests to the host
# service), N29 (ConfigMaps mgmt-signing-pub and cell-registry through the API server) and N11 (OTLP to the collector)
# leave the pod. Flow N26 admits only the node of VIEW_CONTROL_PLANE, which the local traffic policy keeps as the source
# address. While that cluster does not exist, the pod admits no peer on the API port.
ingress="$(peers $node_ips | jq -c '[{from: ., ports: [{protocol: "TCP", port: 8080}]}]')"
if [[ -n "$env_ip" ]]; then
  ingress="$(jq -c --argjson from "$(peers "$env_ip")" '[{from: $from, ports: [{protocol: "TCP", port: 8446}]}] + .' <<<"$ingress")"
fi
api_peers="$(peers $api_ips)"
policy="$(jq -n --arg ns "$namespace" --argjson ingress "$ingress" --argjson host "$(peers "$host_ip")" --argjson hostport "$HOSTSVC_PORT" \
  --argjson api "$api_peers" --argjson apiport "$API_SERVER_PORT" --argjson apisvc "$(peers "$API_SERVICE_IP")" '
  {apiVersion: "networking.k8s.io/v1", kind: "NetworkPolicy", metadata: {name: "mgmtd", namespace: $ns},
   spec: {podSelector: {matchLabels: {"app.kubernetes.io/name": "mgmtd"}}, policyTypes: ["Ingress", "Egress"],
     ingress: $ingress,
     egress: [
       {to: [{namespaceSelector: {matchLabels: {"kubernetes.io/metadata.name": "spire-system"}},
              podSelector: {matchLabels: {"app.kubernetes.io/name": "spire-server"}}}],
        ports: [{protocol: "TCP", port: 8081}]},
       {to: $host, ports: [{protocol: "TCP", port: $hostport}]},
       {to: $api, ports: [{protocol: "TCP", port: $apiport}]},
       {to: $apisvc, ports: [{protocol: "TCP", port: 443}]},
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
# Flow N36: every pod of the namespace resolves names through the cluster DNS.
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

# Every object carries the harness label of the link component, and the pod template too, so
# cell:verify can tie each pod of the plane ServiceAccount to its workload.
{
  yq 'select(.kind != "StatefulSet")' <<<"$manifests"
  echo "---"
  echo "$statefulset"
  echo "---"
  echo "$intent_cm"
  echo "---"
  echo "$pin"
  if [[ -n "$peer_root" ]]; then
    echo "---"
    echo "$peer_root"
  fi
  echo "---"
  echo "$policy"
  echo "---"
  echo "$dns"
} | COMP="$component" yq 'select(.kind != null)
    | .metadata.labels["cell.poc.internal/harness"] = strenv(COMP)
    | with(select(.spec.template.metadata != null); .spec.template.metadata.labels["cell.poc.internal/harness"] = strenv(COMP))'
