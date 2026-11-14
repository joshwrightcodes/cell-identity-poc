#!/usr/bin/env bash
# Render celld and its SPIRE agent sidecar for one cell.
#
# The render reads three facts from outside the cell:
#   - the node address of SPIRE_SERVER_CLUSTER, from the host service. The agent connects to it,
#     and the NetworkPolicy allows only that address on the SPIRE node port.
#   - the trust bundle of the SPIRE server, from the server in SPIRE_SERVER_CLUSTER, through
#     components/lib/peer-root.sh. It becomes ConfigMap spire-trust-bundle. The bundle holds only
#     public certificates.
#   - the public signing key of mgmtd, from ConfigMap mgmt-signing-pub in management, as ConfigMap
#     mgmt-op-key (key op.pub). celld trusts an operation only when this key signed it. celld dials the
#     stream port 30450 and the bind port 30451 of the cell gateway on the node of SPIRE_SERVER_CLUSTER.
#     The pod template carries the SHA-256 of the trust bundle and of the key, because celld loads both
#     only at start, so a change restarts the pod.
#   - the plugin and celld images that `mise run images` built on this Mac, pinned by the digests
#     in build/images.env. The agent config carries the SHA-256 of the plugin binary, so the agent
#     checks the binary before it runs it.
# components/lib/spire-sidecar.sh adds the agent to the celld Deployment, with the M2 names of its
# ConfigMaps and socket volume, so the deployed pod stays the same.
# Inputs: SPIRE_SERVER_CLUSTER from cells/<cluster>.env, POC_ENV from cells/common.env, and the
# cluster facts from build/facts.env.
set -euo pipefail
: "${CELL_NAME:?}" "${SPIRE_SERVER_CLUSTER:?}" "${POC_ENV:?}" "${API_SERVER_IPS:?}" "${API_SERVER_PORT:?}" "${API_SERVICE_IP:?}" "${DNS_SERVICE_IP:?}"

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
trust_domain=dev.env.poc.internal

die() { printf 'error: cell-identity render: %s\n' "$*" >&2; exit 1; }

source "$root/scripts/ko-image.sh"
source "$root/components/lib/peer-root.sh"
source "$root/components/lib/spire-sidecar.sh"
source "$root/components/lib/addresses.sh"
source "$root/components/lib/mgmt-key.sh"

celld_image="$(ko_image celld)" || die "no celld image"

ipv4='^([0-9]{1,3}\.){3}[0-9]{1,3}$'
if ! facts="$(cd "$root" && mise run hostsvc -- facts --cluster "$SPIRE_SERVER_CLUSTER" 2>/dev/null)"; then
  die "no host service facts for $SPIRE_SERVER_CLUSTER: ${facts:-no output}"
fi
server_ip="$(jq -r '.nodeIP // ""' <<<"$facts")"
[[ "$server_ip" =~ $ipv4 ]] || die "node address of $SPIRE_SERVER_CLUSTER is '$server_ip', not an IPv4 address"

bundle="$(peer_root_pem "$SPIRE_SERVER_CLUSTER" "$trust_domain")" || exit 1
bundle_sum="$(printf '%s' "$bundle" | sha256)"
op_pub="$(mgmt_signing_pub)" || exit 1
op_sum="$(printf '%s' "$op_pub" | sha256)"
op_key="$(PUB="$op_pub" SUM="$op_sum" yq -n '
  .apiVersion = "v1" | .kind = "ConfigMap" | .metadata.name = "mgmt-op-key" | .metadata.namespace = "cell-identity-system"
  | .metadata.annotations["poc.internal/op-key-sha256"] = strenv(SUM)
  | .data["op.pub"] = strenv(PUB)')"
[[ "$POC_ENV" =~ ^[a-z0-9][a-z0-9-]{0,30}$ ]] || die "POC_ENV '$POC_ENV' is not a short DNS label"

api_ips="$(ipv4_list API_SERVER_IPS)" || exit 1
api_peers="$(for ip in $api_ips; do printf '{"ipBlock":{"cidr":"%s/32"}}\n' "$ip"; done | jq -cs .)"
[[ "$API_SERVER_PORT" =~ ^[0-9]+$ ]] || die "API_SERVER_PORT '$API_SERVER_PORT' is not a port number"

manifests="$(PEERS="$api_peers" PORT="$API_SERVER_PORT" yq '
  (select(.kind == "NetworkPolicy" and .metadata.name == "celld") | .spec.egress[] | select(.to == "@API_SERVER_PEERS@")) |= (
    .to = (env(PEERS) | ... style="") | .ports[0].port = env(PORT))
' "$here/manifests.yaml" \
  | sed -e "s|@CELLD_IMAGE@|$celld_image|" -e "s|@TRUST_BUNDLE_SHA256@|$bundle_sum|" -e "s|@OP_KEY_SHA256@|$op_sum|" \
    -e "s|@CELL_NAME@|$CELL_NAME|" -e "s|@POC_ENV@|$POC_ENV|" \
    -e "s|@GATEWAY_STREAM@|$server_ip:30450|" -e "s|@GATEWAY_BIND@|$server_ip:30451|" -e "s|@GATEWAY_ADDRESS@|$server_ip|" \
    -e "s|@SPIRE_SERVER_ADDRESS@|$server_ip|" \
    -e "s|@API_SERVICE_IP@|$API_SERVICE_IP|" \
    -e "s|@DNS_SERVICE_IP@|$DNS_SERVICE_IP|")"

celld="$(yq 'select(.kind == "Deployment" and .metadata.name == "celld")' <<<"$manifests" \
  | SPIRE_SIDECAR_SERVER_ADDRESS="$server_ip" SPIRE_SIDECAR_SERVER_PORT=30081 SPIRE_SIDECAR_TRUST_DOMAIN="$trust_domain" \
    SPIRE_SIDECAR_BUNDLE="$bundle" SPIRE_SIDECAR_CELL="@CELL_NAME@" \
    SPIRE_SIDECAR_AGENT_CONFIGMAP=spire-agent SPIRE_SIDECAR_BUNDLE_CONFIGMAP=spire-trust-bundle SPIRE_SIDECAR_SOCKET_VOLUME=agent-socket \
    spire_sidecar celld cluster_jwt)" || die "the SPIRE sidecar of celld failed"

# Every object carries the harness label, so cell:verify can find the objects of the component.
{
  yq 'select(.kind != "Deployment" or .metadata.name != "celld")' <<<"$manifests"
  echo "---"
  echo "$celld"
  echo "---"
  echo "$op_key"
} | yq '.metadata.labels["cell.poc.internal/harness"] = "cell-identity"'
