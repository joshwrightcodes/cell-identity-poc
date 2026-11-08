#!/usr/bin/env bash
# Render celld and its SPIRE agent sidecar for one cell.
#
# The render reads three facts from outside the cell:
#   - the node address of SPIRE_SERVER_CLUSTER, from the host service. The agent connects to it,
#     and the NetworkPolicy allows only that address on the SPIRE node port.
#   - the trust bundle of the SPIRE server, from the server in SPIRE_SERVER_CLUSTER. It becomes
#     ConfigMap spire-trust-bundle. The bundle holds only public certificates.
#   - the plugin and celld images that `mise run images` built on this Mac, pinned by the digests
#     in build/images.env. The agent config carries the SHA-256 of the plugin binary, so the agent
#     checks the binary before it runs it.
# Inputs: SPIRE_SERVER_CLUSTER from cells/<cluster>.env, and the cluster facts from build/facts.env.
set -euo pipefail
: "${CELL_NAME:?}" "${SPIRE_SERVER_CLUSTER:?}" "${API_SERVER_IPS:?}" "${API_SERVER_PORT:?}" "${API_SERVICE_IP:?}" "${DNS_SERVICE_IP:?}"

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
namespace=cell-identity-system
plugin_binary=/ko-app/cluster-jwt-agent
server_namespace=spire-system
server_pod=spire-server-0
trust_domain=dev.env.poc.internal

die() { printf 'error: cell-identity render: %s\n' "$*" >&2; exit 1; }

source "$root/scripts/ko-image.sh"

plugin_image="$(ko_image cluster-jwt-agent)" || die "no agent plugin image"
checksum="$(ko_binary_sha256 "$plugin_image" "$plugin_binary")" || die "no agent plugin checksum"
celld_image="$(ko_image celld)" || die "no celld image"

ipv4='^([0-9]{1,3}\.){3}[0-9]{1,3}$'
if ! facts="$(cd "$root" && mise run hostsvc -- facts --cluster "$SPIRE_SERVER_CLUSTER" 2>/dev/null)"; then
  die "no host service facts for $SPIRE_SERVER_CLUSTER: ${facts:-no output}"
fi
server_ip="$(jq -r '.nodeIP // ""' <<<"$facts")"
[[ "$server_ip" =~ $ipv4 ]] || die "node address of $SPIRE_SERVER_CLUSTER is '$server_ip', not an IPv4 address"

# The server prints its X.509 roots as PEM.
kubectl_err="$(mktemp)"
trap 'rm -f "$kubectl_err"' EXIT
if ! bundle="$(kubectl --context "kind-$SPIRE_SERVER_CLUSTER" -n "$server_namespace" exec "$server_pod" -c spire-server -- \
  /opt/spire/bin/spire-server bundle show -socketPath /run/spire/sockets/api.sock -format pem 2>"$kubectl_err")"; then
  die "could not read the trust bundle from $server_pod in $SPIRE_SERVER_CLUSTER. Run CELL=$SPIRE_SERVER_CLUSTER mise run cell:up first. kubectl: $(tail -n 1 "$kubectl_err")"
fi
# pkigen checks that each certificate is a CA of the trust domain and valid now, and prints the
# certificates again. It prints one JSON error line instead when a check fails.
if ! checked="$(cd "$root" && mise run pki -- trust-bundle --trust-domain "$trust_domain" <<<"$bundle" 2>/dev/null)"; then
  die "the trust bundle from $SPIRE_SERVER_CLUSTER failed the check: ${checked:-no output}"
fi
bundle="$checked"

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
# The checksum covers the config after hydrate replaces @CELL_NAME@, so it differs for each cell.
config_checksum="$(printf '%s' "${config_maps//@CELL_NAME@/$CELL_NAME}" | sha256)"

# Every object carries the harness label, so cell:verify can find the objects of the component.
{
  PEERS="$api_peers" PORT="$API_SERVER_PORT" yq '
    (select(.kind == "NetworkPolicy" and .metadata.name == "celld") | .spec.egress[] | select(.to == "@API_SERVER_PEERS@")) |= (
      .to = (env(PEERS) | ... style="") | .ports[0].port = env(PORT))
  ' "$here/manifests.yaml" \
    | sed -e "s|@SPIRE_AGENT_PLUGIN_IMAGE@|$plugin_image|" \
      -e "s|@CELLD_IMAGE@|$celld_image|" \
      -e "s|@SPIRE_AGENT_CONFIG_CHECKSUM@|$config_checksum|" \
      -e "s|@SPIRE_SERVER_ADDRESS@|$server_ip|" \
      -e "s|@API_SERVICE_IP@|$API_SERVICE_IP|" \
      -e "s|@DNS_SERVICE_IP@|$DNS_SERVICE_IP|"
  echo "---"
  echo "$config_maps"
} | yq '.metadata.labels["cell.poc.internal/harness"] = "cell-identity"'
