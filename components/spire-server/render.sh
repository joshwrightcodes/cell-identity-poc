#!/usr/bin/env bash
# Render the SPIRE server of the environment trust domain.
#
# For each cell in SPIRE_AGENT_CELLS, the render reads the node address from the host service and
# signs a test record of the cell for the ServiceAccount SPIRE_AGENT_SUBJECT of the agent pod. The
# NetworkPolicy admits only those node addresses, and the plugin trusts only those records.
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

sha256() {
  if command -v sha256sum >/dev/null; then sha256sum | cut -d' ' -f1; else shasum -a 256 | cut -d' ' -f1; fi
}

# The plugin image and the checksum of the binary in it. ko puts the binary in the last layer.
digest="$(oras resolve --plain-http "$plugin_repo:latest" 2>/dev/null)" \
  || die "no image $plugin_repo:latest. Run mise run images first."
[[ "$digest" =~ ^sha256:[0-9a-f]{64}$ ]] || die "image $plugin_repo:latest resolved to '$digest'"
manifest="$(oras manifest fetch --plain-http "$plugin_repo@$digest")"
jq -e '.mediaType == "application/vnd.oci.image.manifest.v1+json"' <<<"$manifest" >/dev/null \
  || die "$plugin_repo@$digest is not a single-platform image manifest"
layer="$(jq -r '.layers[-1].digest' <<<"$manifest")"
checksum="$(oras blob fetch --plain-http --output - "$plugin_repo@$layer" | tar -xzOf - "$plugin_binary" 2>/dev/null | sha256)" \
  || die "could not read $plugin_binary from $plugin_repo@$digest"
# The second value is the SHA-256 of empty input.
[[ "$checksum" =~ ^[0-9a-f]{64}$ && "$checksum" != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" ]] \
  || die "no $plugin_binary in the last layer of $plugin_repo@$digest"

ipv4='^([0-9]{1,3}\.){3}[0-9]{1,3}$'
peers='[]'
sources='[]'
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

PEERS="$peers" SOURCES="$sources" yq "
  (select(.kind == \"StatefulSet\") | .spec.template.spec.volumes[] | select(.name == \"records\") | .projected.sources) = (env(SOURCES) | ... style=\"\")
  | (select(.kind == \"NetworkPolicy\" and .metadata.name == \"spire-server-agents\") | .spec.ingress[0].from) = (env(PEERS) | ... style=\"\")
" "$here/manifests.yaml" \
  | sed -e "s|@SPIRE_PLUGIN_IMAGE@|$plugin_repo@$digest|" -e "s|@SPIRE_CONFIG_CHECKSUM@|$config_checksum|"
echo "---"
echo "$config_maps"
printf '%s' "$records"
