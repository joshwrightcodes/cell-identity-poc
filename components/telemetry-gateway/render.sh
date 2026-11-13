#!/usr/bin/env bash
# Render the telemetry gateway of management, a link component in observability-system.
#
# The bundle holds ServiceAccount, Deployment and NetworkPolicy telemetry-gateway, Service
# telemetry-listener on node port 31444, ConfigMaps peer-root and cell-registry, and the objects of
# the k8s_psat SPIRE agent sidecar (components/lib/spire-sidecar.sh). It holds no Namespace,
# because the namespaces bundle owns observability-system, so every object carries the harness
# label that cell:verify uses to tell them from the objects of the bundles.
#
# The render reads these facts from outside the cluster, so it runs in the link phase:
#   - the node address of VIEW_CONTROL_PLANE (dev-cp) from the host service. Only that address
#     reaches the node port.
#   - the root of the environment trust domain, from the live SPIRE server of VIEW_CONTROL_PLANE,
#     as ConfigMap peer-root (components/lib/peer-root.sh).
#   - the root of the management trust domain, from the live SPIRE server of this cluster, for the
#     trust bundle of the sidecar.
#   - a signed record for each cell of VIEW_CELLS, as ConfigMap cell-registry
#     (components/lib/registry.sh). Each cell must have a bound celld.
#   - the cell-proxy image that `mise run images` built, by digest.
# The pod template carries the SHA-256 of the peer root and of the registry content, so a new root
# or a new set of cells restarts the pod.
# Inputs: VIEW_CELLS, VIEW_CONTROL_PLANE and SPIRE_TRUST_DOMAIN from cells/management.env, POC_ENV
# from cells/common.env, and the cluster facts from build/<cluster>/facts.env.
set -euo pipefail
: "${CELL_NAME:?}" "${POC_ENV:?}" "${VIEW_CELLS:?}" "${VIEW_CONTROL_PLANE:?}" "${SPIRE_TRUST_DOMAIN:?}"

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
namespace=observability-system
component=telemetry-gateway
env_cluster="$VIEW_CONTROL_PLANE"
env_td=dev.env.poc.internal

die() { printf 'error: telemetry-gateway render: %s\n' "$*" >&2; exit 1; }

source "$root/scripts/ko-image.sh"
source "$root/components/lib/addresses.sh"
source "$root/components/lib/peer-root.sh"
source "$root/components/lib/registry.sh"
source "$root/components/lib/spire-sidecar.sh"

[[ "$POC_ENV" =~ ^[a-z0-9][a-z0-9-]{0,30}$ ]] || die "POC_ENV '$POC_ENV' is not a short DNS label"
[[ "$SPIRE_TRUST_DOMAIN" == mgmt.poc.internal ]] || die "SPIRE_TRUST_DOMAIN '$SPIRE_TRUST_DOMAIN' is not mgmt.poc.internal, the domain that the gateway probe expects"
read -r -a cells <<<"$VIEW_CELLS"
((${#cells[@]} > 0)) || die "VIEW_CELLS names no cell"
for cell in "${cells[@]}"; do
  [[ "$cell" =~ ^[a-z0-9]([a-z0-9-]{0,57}[a-z0-9])?$ ]] || die "VIEW_CELLS entry '$cell' is not a cell name of at most 59 characters"
  case "$cell" in cp | dev-cp | management | rogue) die "VIEW_CELLS names the reserved name $cell" ;; esac
done

ipv4='^([0-9]{1,3}\.){3}[0-9]{1,3}$'
if ! facts="$(cd "$root" && mise run hostsvc -- facts --cluster "$env_cluster" 2>/dev/null)"; then
  die "no host service facts for $env_cluster: ${facts:-no output}. Run: CELL=$env_cluster mise run cell:up"
fi
env_ip="$(jq -r '.nodeIP // ""' <<<"$facts")"
[[ "$env_ip" =~ $ipv4 ]] || die "node address of $env_cluster is '$env_ip', not an IPv4 address"
env_peers="$(printf '{"ipBlock":{"cidr":"%s/32"}}\n' "$env_ip" | jq -cs .)"

cell_proxy_image="$(ko_image cell-proxy)" || die "no cell-proxy image"
peer_root="$(peer_root_configmap peer-root "$namespace" "$env_cluster" "$env_td")" || exit 1
own_bundle="$(peer_root_pem "$CELL_NAME" "$SPIRE_TRUST_DOMAIN")" || exit 1
registry="$(registry_configmap "$namespace" "$POC_ENV" "${cells[@]}")" || exit 1
peer_sum="$(yq -r '.metadata.annotations["poc.internal/peer-root-sha256"]' <<<"$peer_root")"
registry_sum="$(yq -r '.metadata.annotations["poc.internal/registry-content-sha256"]' <<<"$registry")"
[[ "$peer_sum" =~ ^[0-9a-f]{64}$ && "$registry_sum" =~ ^[0-9a-f]{64}$ ]] || die "the peer root or the registry has no checksum"

# A sender is a cell or dev-cp, and its role is otel. The pattern holds the whole ID.
allow_id="^spiffe://${env_td//./\\.}/(cell/[a-z0-9-]+|cp)/otel\$"

gateway="$(sed -e "s|@CELL_PROXY_IMAGE@|$cell_proxy_image|" -e "s|@PEER_ROOT_SHA256@|$peer_sum|" \
    -e "s|@REGISTRY_SHA256@|$registry_sum|" -e "s|@PEER_TRUST_DOMAIN@|$env_td|" "$here/gateway.yaml" \
  | ALLOW="$allow_id" PEERS="$env_peers" yq '(.. | select(. == "--allow-id=@ALLOW_ID@")) = "--allow-id=" + strenv(ALLOW)
      | (.. | select(. == "@ENV_NODE_PEERS@")) |= (env(PEERS) | ... style="")')"
deployment="$(yq 'select(.kind == "Deployment")' <<<"$gateway" \
  | SPIRE_SIDECAR_SERVER_ADDRESS=spire-server.spire-system.svc.cluster.local SPIRE_SIDECAR_SERVER_PORT=8081 \
    SPIRE_SIDECAR_TRUST_DOMAIN="$SPIRE_TRUST_DOMAIN" SPIRE_SIDECAR_BUNDLE="$own_bundle" SPIRE_SIDECAR_CLUSTER="$CELL_NAME" \
    spire_sidecar telemetry-gateway k8s_psat)" || die "the SPIRE sidecar of the gateway failed"

# Every object carries the harness label of the link component, and every pod template too, so
# cell:verify can tie each pod of the plane ServiceAccount to its workload.
{
  yq 'select(.kind != "Deployment")' <<<"$gateway"
  echo "---"
  echo "$deployment"
  echo "---"
  echo "$peer_root"
  echo "---"
  echo "$registry"
} | COMP="$component" yq 'select(.kind != null)
    | .metadata.labels["cell.poc.internal/harness"] = strenv(COMP)
    | with(select(.spec.template.metadata != null); .spec.template.metadata.labels["cell.poc.internal/harness"] = strenv(COMP))'
