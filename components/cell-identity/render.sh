#!/usr/bin/env bash
# Render celld and its SPIRE agent sidecar for one cell.
#
# The render reads three facts from outside the cell:
#   - the node address of SPIRE_SERVER_CLUSTER, from the host service. The agent connects to it,
#     and the NetworkPolicy allows only that address on the SPIRE node port.
#   - the trust bundle of the SPIRE server, from the server in SPIRE_SERVER_CLUSTER. It becomes
#     ConfigMap spire-trust-bundle. The bundle holds only public certificates.
#   - the plugin and celld images from the local registry, pinned by digest. The agent config
#     carries the SHA-256 of the plugin binary, so the agent checks the binary before it runs it.
# Inputs: SPIRE_SERVER_CLUSTER from cells/<cluster>.env, and the cluster facts from build/facts.env.
set -euo pipefail
: "${SPIRE_SERVER_CLUSTER:?}" "${API_SERVER_IPS:?}" "${API_SERVER_PORT:?}" "${API_SERVICE_IP:?}" "${DNS_SERVICE_IP:?}"

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
namespace=cell-identity-system
plugin_repo=localhost:5001/cluster-jwt-agent
plugin_binary=/ko-app/cluster-jwt-agent
celld_repo=localhost:5001/celld
server_namespace=spire-system
server_pod=spire-server-0

die() { printf 'error: cell-identity render: %s\n' "$*" >&2; exit 1; }

source "$root/scripts/ko-image.sh"

plugin_digest="$(ko_digest "$plugin_repo")" || die "no agent plugin image"
checksum="$(ko_binary_sha256 "$plugin_repo" "$plugin_digest" "$plugin_binary")" || die "no agent plugin checksum"
celld_digest="$(ko_digest "$celld_repo")" || die "no celld image"

ipv4='^([0-9]{1,3}\.){3}[0-9]{1,3}$'
if ! facts="$(cd "$root" && mise run hostsvc -- facts --cluster "$SPIRE_SERVER_CLUSTER" 2>/dev/null)"; then
  die "no host service facts for $SPIRE_SERVER_CLUSTER: ${facts:-no output}"
fi
server_ip="$(jq -r '.nodeIP // ""' <<<"$facts")"
[[ "$server_ip" =~ $ipv4 ]] || die "node address of $SPIRE_SERVER_CLUSTER is '$server_ip', not an IPv4 address"

# The server prints its X.509 roots as PEM. The output must hold certificates and nothing else.
if ! bundle="$(kubectl --context "kind-$SPIRE_SERVER_CLUSTER" -n "$server_namespace" exec "$server_pod" -c spire-server -- \
  /opt/spire/bin/spire-server bundle show -socketPath /run/spire/sockets/api.sock -format pem 2>&1)"; then
  die "could not read the trust bundle from $server_pod in $SPIRE_SERVER_CLUSTER. Run CELL=$SPIRE_SERVER_CLUSTER mise run cell:up first. kubectl: $(tail -n 1 <<<"$bundle")"
fi
grep -q '^-----BEGIN CERTIFICATE-----$' <<<"$bundle" || die "the trust bundle from $SPIRE_SERVER_CLUSTER holds no certificate"
if grep -vqE '^(-----(BEGIN|END) CERTIFICATE-----|[A-Za-z0-9+/=]*)$' <<<"$bundle"; then
  die "the trust bundle from $SPIRE_SERVER_CLUSTER holds more than PEM certificates"
fi

api_peers="$(for ip in $API_SERVER_IPS; do [[ "$ip" =~ $ipv4 ]] || exit 1; printf '{"ipBlock":{"cidr":"%s/32"}}\n' "$ip"; done | jq -cs .)" \
  || die "API_SERVER_IPS '$API_SERVER_IPS' holds an address that is not IPv4"
[[ "$API_SERVER_PORT" =~ ^[0-9]+$ ]] || die "API_SERVER_PORT '$API_SERVER_PORT' is not a port number"

agent_conf="$(sed -e "s|@SPIRE_SERVER_ADDRESS@|$server_ip|" -e "s|@SPIRE_AGENT_PLUGIN_CHECKSUM@|$checksum|" "$here/agent.conf")"

# config_map <name> <key> <content> prints a ConfigMap with one literal block value.
config_map() {
  NAME="$1" KEY="$2" VALUE="$3" NS="$namespace" yq -n '
    .apiVersion = "v1" | .kind = "ConfigMap" | .metadata.name = strenv(NAME) | .metadata.namespace = strenv(NS)
    | .data[strenv(KEY)] = strenv(VALUE) | .data[strenv(KEY)] style="literal"'
}
config_maps="$(config_map spire-agent agent.conf "$agent_conf"; echo "---"; config_map spire-trust-bundle bundle.crt "$bundle")"
config_checksum="$(printf '%s' "$config_maps" | sha256)"

PEERS="$api_peers" PORT="$API_SERVER_PORT" yq '
  (select(.kind == "NetworkPolicy" and .metadata.name == "celld") | .spec.egress[] | select(.to == "@API_SERVER_PEERS@")) |= (
    .to = (env(PEERS) | ... style="") | .ports[0].port = env(PORT))
' "$here/manifests.yaml" \
  | sed -e "s|@SPIRE_AGENT_PLUGIN_IMAGE@|$plugin_repo@$plugin_digest|" \
    -e "s|@CELLD_IMAGE@|$celld_repo@$celld_digest|" \
    -e "s|@SPIRE_AGENT_CONFIG_CHECKSUM@|$config_checksum|" \
    -e "s|@SPIRE_SERVER_ADDRESS@|$server_ip|" \
    -e "s|@API_SERVICE_IP@|$API_SERVICE_IP|" \
    -e "s|@DNS_SERVICE_IP@|$DNS_SERVICE_IP|"
echo "---"
echo "$config_maps"
