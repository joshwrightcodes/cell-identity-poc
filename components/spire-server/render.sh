#!/usr/bin/env bash
# Render the SPIRE server of the environment trust domain.
#
# For each cell in SPIRE_AGENT_CELLS, the render reads the node address from the host service and
# signs a test record of the cell for the ServiceAccount SPIRE_AGENT_SUBJECT of the agent pod. The
# NetworkPolicy admits only those node addresses, and the plugin trusts only those records.
# ConfigMap spire-entries gets two ClusterStaticEntry manifests for each cell: a node alias that
# matches the attested agents of the cell, and the celld ID under that alias.
# The plugin image comes from the local registry, pinned by digest. The server config carries the
# SHA-256 of the plugin binary from that image, so the server checks the binary before it runs it.
# Inputs come from cells/<cluster>.env: SPIRE_AGENT_CELLS and SPIRE_AGENT_SUBJECT.
set -euo pipefail
: "${SPIRE_AGENT_CELLS:?}" "${SPIRE_AGENT_SUBJECT:?}"

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
namespace=spire-system
plugin_repo=localhost:5001/cluster-jwt-server
plugin_binary=/ko-app/cluster-jwt-server

die() { printf 'error: spire-server render: %s\n' "$*" >&2; exit 1; }

source "$root/scripts/ko-image.sh"

# The plugin image and the checksum of the binary in it.
digest="$(ko_digest "$plugin_repo")" || die "no plugin image"
checksum="$(ko_binary_sha256 "$plugin_repo" "$digest" "$plugin_binary")" || die "no plugin checksum"

ipv4='^([0-9]{1,3}\.){3}[0-9]{1,3}$'
[[ "$SPIRE_AGENT_SUBJECT" =~ ^[a-z0-9-]+/[a-z0-9-]+$ ]] || die "SPIRE_AGENT_SUBJECT '$SPIRE_AGENT_SUBJECT' is not <namespace>/<service account>"
trust_domain=dev.env.poc.internal
peers='[]'
sources='[]'
entries='{}'
keys=()
records=""
for cell in $SPIRE_AGENT_CELLS; do
  if ! facts="$(cd "$root" && mise run hostsvc -- facts --cluster "$cell" 2>/dev/null)"; then
    die "no host service facts for $cell: ${facts:-no output}"
  fi
  ip="$(jq -r '.nodeIP // ""' <<<"$facts")"
  [[ "$ip" =~ $ipv4 ]] || die "node address of $cell is '$ip', not an IPv4 address"
  peers="$(jq -c --arg cidr "$ip/32" '. + [{ipBlock: {cidr: $cidr}}]' <<<"$peers")"

  if ! record="$(cd "$root" && mise run record:fixture -- --cluster "$cell" --subject "$SPIRE_AGENT_SUBJECT" 2>/dev/null)"; then
    die "could not sign the record of $cell: ${record:-no output}"
  fi
  name="cell-record-$cell"
  yq -e ".kind == \"ConfigMap\" and .metadata.name == \"$name\" and (.data.\"record.dsse.json\" | length) > 0" <<<"$record" >/dev/null \
    || die "record:fixture printed no ConfigMap $name"
  key="$(yq -r '.data."signer.pub"' <<<"$record")"
  [[ "$key" =~ ^[A-Za-z0-9+/]+=*$ ]] || die "record:fixture printed no base64 public key for $cell"
  keys+=("$key")
  records+="---"$'\n'"$(yq ".metadata.namespace = \"$namespace\"" <<<"$record")"$'\n'
  sources="$(jq -c --arg name "$name" --arg path "$cell.dsse.json" \
    '. + [{configMap: {name: $name, items: [{key: "record.dsse.json", path: $path}]}}]' <<<"$sources")"

  # The cluster_jwt plugin gives an attested agent the selectors cluster_jwt:cell:<cell> and
  # cluster_jwt:sa:<namespace>:<service account>. The alias matches both. A celld process runs as uid 65532.
  alias_id="spiffe://$trust_domain/cell/$cell/nodes"
  entries="$(jq -c --arg cell "$cell" --arg td "$trust_domain" --arg alias "$alias_id" --arg sa "${SPIRE_AGENT_SUBJECT/\//:}" '
    . + {
      ($cell + "-nodes.yaml"): {apiVersion: "spire.spiffe.io/v1alpha1", kind: "ClusterStaticEntry",
        metadata: {name: ($cell + "-nodes")},
        spec: {spiffeID: $alias, parentID: ("spiffe://" + $td + "/spire/server"),
          selectors: ["cluster_jwt:cell:" + $cell, "cluster_jwt:sa:" + $sa]}},
      ($cell + "-celld.yaml"): {apiVersion: "spire.spiffe.io/v1alpha1", kind: "ClusterStaticEntry",
        metadata: {name: ($cell + "-celld")},
        spec: {spiffeID: ("spiffe://" + $td + "/cell/" + $cell + "/celld"), parentID: $alias,
          selectors: ["unix:uid:65532"]}}
    }' <<<"$entries")"
done
((${#keys[@]} > 0)) || die "SPIRE_AGENT_CELLS names no cell"

key_list="$(printf '"%s", ' "${keys[@]}")"
key_list="[${key_list%, }]"
server_conf="$(sed -e "s|@SPIRE_PLUGIN_CHECKSUM@|$checksum|" -e "s|@SPIRE_RECORD_PUBLIC_KEYS@|$key_list|" "$here/server.conf")"
controller_conf="$(cat "$here/controller-manager.yaml")"

# config_map <name> <key> <content> prints a ConfigMap with one literal block value.
config_map() {
  NAME="$1" KEY="$2" VALUE="$3" NS="$namespace" yq -n '
    .apiVersion = "v1" | .kind = "ConfigMap" | .metadata.name = strenv(NAME) | .metadata.namespace = strenv(NS)
    | .data[strenv(KEY)] = strenv(VALUE) | .data[strenv(KEY)] style="literal"'
}
config_maps="$(config_map spire-server server.conf "$server_conf"; echo "---"; config_map spire-controller-manager config.yaml "$controller_conf")"
config_checksum="$(printf '%s\n%s' "$config_maps" "$records" | sha256)"

# Each entry becomes one YAML file in the ConfigMap, as spire-controller-manager expects.
PEERS="$peers" SOURCES="$sources" ENTRIES="$entries" yq "
  (select(.kind == \"StatefulSet\") | .spec.template.spec.volumes[] | select(.name == \"records\") | .projected.sources) = (env(SOURCES) | ... style=\"\")
  | (select(.kind == \"NetworkPolicy\" and .metadata.name == \"spire-server-agents\") | .spec.ingress[0].from) = (env(PEERS) | ... style=\"\")
  | (select(.kind == \"ConfigMap\" and .metadata.name == \"spire-entries\") | .data) = (env(ENTRIES) | ... style=\"\" | map_values(to_yaml) | .[] style=\"literal\")
" "$here/manifests.yaml" \
  | sed -e "s|@SPIRE_PLUGIN_IMAGE@|$plugin_repo@$digest|" -e "s|@SPIRE_CONFIG_CHECKSUM@|$config_checksum|"
echo "---"
echo "$config_maps"
printf '%s' "$records"
