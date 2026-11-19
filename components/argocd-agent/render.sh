#!/usr/bin/env bash
# Render the Argo CD Agent of one cell, a harness component in the namespace argocd.
#
# The bundle holds the agent Deployment with cell-proxy and a cluster_jwt SPIRE agent sidecar
# (manifests.yaml), ConfigMap mgmt-root, the NetworkPolicy of flow N20, the agent Role in
# argocd, the read rules of the central view, and the view guard (guard.yaml). Every object and the pod template carry the
# harness label cell.poc.internal/harness=argocd-agent.
#
# The read rules let the resource proxy of the view read the live objects of the cell. render.sh
# derives them from the kinds of the bundles in AGENT_BUNDLES (default build/<cluster>/bundles),
# skips each object with a harness label, and maps each kind to its resource through a CRD of the
# bundles or, for a built-in kind, kubectl api-resources. It renders one Role and RoleBinding
# argocd-agent-read in each namespace, and one ClusterRole and ClusterRoleBinding argocd-agent-read
# for the cluster-scoped kinds and namespaces. Every rule is get, list and watch. No rule names
# Secrets, Events, or a subresource such as pods/exec, pods/attach, pods/portforward or */proxy.
# hydrate.sh renders harness components after the bundles, so the bundles are current.
#
# The render reads these facts from outside the cell:
#   - the node address of SPIRE_SERVER_CLUSTER, the environment control plane, from the host
#     service. cell-proxy dials the relay there on 30443, and the SPIRE agent the server on 30081.
#   - the roots of the management trust domain, from the live SPIRE server of management, as
#     ConfigMap mgmt-root (components/lib/peer-root.sh). The pod template carries their SHA-256.
#   - the roots of the environment trust domain, from the server in SPIRE_SERVER_CLUSTER, for the
#     trust bundle of the SPIRE agent sidecar.
#   - the cell-proxy and cluster-jwt-agent images that `mise run images` built, by digest.
# Inputs: SPIRE_SERVER_CLUSTER from cells/<cluster>.env, POC_ENV and ARGOCD_AGENT_IMAGE from
# cells/common.env, and the cluster facts from build/<cluster>/facts.env.
set -euo pipefail
: "${CELL_NAME:?}" "${SPIRE_SERVER_CLUSTER:?}" "${POC_ENV:?}" "${ARGOCD_AGENT_IMAGE:?}"
: "${API_SERVER_IPS:?}" "${API_SERVER_PORT:?}" "${API_SERVICE_IP:?}"

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
component=argocd-agent
namespace=argocd
env_td=dev.env.poc.internal
mgmt_cluster=management
mgmt_td=mgmt.poc.internal
bundles="${AGENT_BUNDLES:-${POC_BUILD_ROOT:-$root/build}/$CELL_NAME/bundles}"

die() { printf 'error: argocd-agent render: %s\n' "$*" >&2; exit 1; }

source "$root/scripts/ko-image.sh"
source "$root/components/lib/addresses.sh"
source "$root/components/lib/peer-root.sh"
source "$root/components/lib/spire-sidecar.sh"

[[ "$ARGOCD_AGENT_IMAGE" =~ @sha256:[0-9a-f]{64}$ ]] || die "ARGOCD_AGENT_IMAGE '$ARGOCD_AGENT_IMAGE' is not pinned by digest"
[[ "$POC_ENV" =~ ^[a-z0-9][a-z0-9-]{0,30}$ ]] || die "POC_ENV '$POC_ENV' is not a short DNS label, so it cannot go into the audience pattern of the guard"
ipv4='^([0-9]{1,3}\.){3}[0-9]{1,3}$'
[[ "$API_SERVICE_IP" =~ $ipv4 ]] || die "API_SERVICE_IP '$API_SERVICE_IP' is not an IPv4 address"
[[ "$API_SERVER_PORT" =~ ^[0-9]+$ ]] || die "API_SERVER_PORT '$API_SERVER_PORT' is not a port number"
api_ips="$(ipv4_list API_SERVER_IPS)" || exit 1
api_peers="$(for ip in $api_ips; do printf '{"ipBlock":{"cidr":"%s/32"}}\n' "$ip"; done | jq -cs .)"

if ! facts="$(cd "$root" && mise run hostsvc -- facts --cluster "$SPIRE_SERVER_CLUSTER" 2>/dev/null)"; then
  die "no host service facts for $SPIRE_SERVER_CLUSTER: ${facts:-no output}. Run: CELL=$SPIRE_SERVER_CLUSTER mise run cell:up"
fi
env_ip="$(jq -r '.nodeIP // ""' <<<"$facts")"
[[ "$env_ip" =~ $ipv4 ]] || die "node address of $SPIRE_SERVER_CLUSTER is '$env_ip', not an IPv4 address"

cell_proxy_image="$(ko_image cell-proxy)" || die "no cell-proxy image"
mgmt_root="$(peer_root_configmap mgmt-root "$namespace" "$mgmt_cluster" "$mgmt_td")" || exit 1
mgmt_sum="$(yq -r '.metadata.annotations["poc.internal/peer-root-sha256"]' <<<"$mgmt_root")"
[[ "$mgmt_sum" =~ ^[0-9a-f]{64}$ ]] || die "ConfigMap mgmt-root has no checksum"
env_bundle="$(peer_root_pem "$SPIRE_SERVER_CLUSTER" "$env_td")" || exit 1

# The read rules. kinds holds each kind of the bundles once, as {group, kind, ns}.
[[ -d "$bundles" ]] || die "no bundles in $bundles. Run: CELL=$CELL_NAME mise run cell:hydrate"
shopt -s nullglob
files=()
for f in "$bundles"/*/manifests.yaml; do
  [[ "$(basename "$(dirname "$f")")" == "$component" ]] || files+=("$f")
done
((${#files[@]} > 0)) || die "$bundles holds no bundle. Run: CELL=$CELL_NAME mise run cell:hydrate"
objects="$(yq -o=json -I=0 'select(.kind != null and (.metadata.labels["cell.poc.internal/harness"] // "") == "")
  | {"apiVersion": .apiVersion, "kind": .kind, "ns": (.metadata.namespace // ""),
     "crd": (if .kind == "CustomResourceDefinition" then {"group": .spec.group, "kind": .spec.names.kind, "plural": .spec.names.plural, "scope": .spec.scope} else null end)}' \
  "${files[@]}")" || die "could not read the bundles in $bundles"
# The app class has no bundle in the build directory. Its kinds and namespaces come from allow.json, so the view reads them too.
app_objects="$(jq -c '.classes[] | select(.project == "cell-app") | . as $c | $c.namespacedKinds[] as $k | $c.objectNamespaces[] as $n
  | {"apiVersion": (if ($k | contains("/")) then ($k | split("/")[0]) + "/v1" else "v1" end), "kind": ($k | split("/")[-1]), "ns": $n, "crd": null}' \
  "${BUNDLE_ALLOW_JSON:-$root/internal/bundle/allow.json}")" || die "could not read the app class of allow.json"
objects+=$'\n'"$app_objects"
# api-resources prints NAME, SHORTNAMES (may be empty), APIVERSION, NAMESPACED and KIND.
if ! api="$(kubectl --context "kind-$CELL_NAME" api-resources --no-headers 2>/dev/null)"; then
  die "kubectl api-resources failed for kind-$CELL_NAME. Check that the cluster answers"
fi
resources="$(awk 'NF >= 4 { print $1, $(NF-2), $(NF-1), $NF }' <<<"$api" | jq -Rcn '[inputs | split(" ")
  | {"plural": .[0], "group": (.[1] | if contains("/") then split("/")[0] else "" end),
     "namespaced": (.[2] == "true"), "kind": .[3]}]')"
rules="$(jq -cs --argjson api "$resources" '
  (map(select(.crd != null) | .crd | {group, kind, plural, namespaced: (.scope == "Namespaced")})) as $crds
  | map({group: (.apiVersion | if contains("/") then split("/")[0] else "" end), kind, ns})
  | unique
  | map(. as $o | (($crds + $api) | map(select(.group == $o.group and .kind == $o.kind)) | first) as $r
      | if $r == null then error("no resource for the kind \($o.kind) of the group \"\($o.group)\"")
        elif $r.namespaced and $o.ns == "" then error("the bundles hold a \($o.kind) with no namespace")
        else {group: $o.group, plural: $r.plural, ns: (if $r.namespaced then $o.ns else "" end)} end)
  | map(select((.group == "" and (.plural == "secrets" or .plural == "events")) or (.group == "events.k8s.io") | not))
  | . + [{group: "", plural: "namespaces", ns: ""}]
  | unique
  | group_by(.ns)
  | map({ns: .[0].ns, rules: (group_by(.group) | map({apiGroups: [.[0].group], resources: (map(.plural) | unique), verbs: ["get", "list", "watch"]}))})' \
  <<<"$objects")" || die "could not derive the read rules from the bundles in $bundles"
jq -e 'all(.[].rules[].resources[]; contains("/") | not)' >/dev/null <<<"$rules" || die "a read rule names a subresource"

read_rbac="$(jq -c --arg comp "$component" --arg ns "$namespace" '.[] as $set
  | if $set.ns == "" then
      {apiVersion: "rbac.authorization.k8s.io/v1", kind: "ClusterRole", metadata: {name: "argocd-agent-read"}, rules: $set.rules},
      {apiVersion: "rbac.authorization.k8s.io/v1", kind: "ClusterRoleBinding", metadata: {name: "argocd-agent-read"},
        roleRef: {apiGroup: "rbac.authorization.k8s.io", kind: "ClusterRole", name: "argocd-agent-read"},
        subjects: [{kind: "ServiceAccount", name: "argocd-agent", namespace: $ns}]}
    else
      {apiVersion: "rbac.authorization.k8s.io/v1", kind: "Role", metadata: {name: "argocd-agent-read", namespace: $set.ns}, rules: $set.rules},
      {apiVersion: "rbac.authorization.k8s.io/v1", kind: "RoleBinding", metadata: {name: "argocd-agent-read", namespace: $set.ns},
        roleRef: {apiGroup: "rbac.authorization.k8s.io", kind: "Role", name: "argocd-agent-read"},
        subjects: [{kind: "ServiceAccount", name: "argocd-agent", namespace: $ns}]}
    end' <<<"$rules" | while read -r o; do echo "---"; yq -P <<<"$o"; done)"

manifests="$(PEERS="$api_peers" PORT="$API_SERVER_PORT" yq '
  (select(.kind == "NetworkPolicy" and .metadata.name == "argocd-agent") | .spec.egress[] | select(.to == "@API_SERVER_PEERS@")) |= (
    .to = (env(PEERS) | ... style="") | .ports[0].port = env(PORT))
' "$here/manifests.yaml" \
  | sed -e "s|@ARGOCD_AGENT_IMAGE@|$ARGOCD_AGENT_IMAGE|" -e "s|@CELL_PROXY_IMAGE@|$cell_proxy_image|" \
    -e "s|@MGMT_ROOT_SHA256@|$mgmt_sum|" -e "s|@RELAY_ADDRESS@|$env_ip:30443|" \
    -e "s|@ENV_NODE_ADDRESS@|$env_ip|" -e "s|@API_SERVICE_IP@|$API_SERVICE_IP|")"

deployment="$(yq 'select(.kind == "Deployment" and .metadata.name == "argocd-agent")' <<<"$manifests" \
  | SPIRE_SIDECAR_SERVER_ADDRESS="$env_ip" SPIRE_SIDECAR_SERVER_PORT=30081 SPIRE_SIDECAR_TRUST_DOMAIN="$env_td" \
    SPIRE_SIDECAR_BUNDLE="$env_bundle" SPIRE_SIDECAR_CELL="@CELL_NAME@" \
    spire_sidecar argocd-agent cluster_jwt)" || die "the SPIRE sidecar of the agent failed"

{
  yq 'select(.kind != "Deployment")' <<<"$manifests"
  echo "---"
  echo "$deployment"
  echo "---"
  echo "$mgmt_root"
  echo "$read_rbac"
  echo "---"
  sed "s|@POC_ENV@|$POC_ENV|g" "$here/guard.yaml"
} | COMP="$component" yq 'select(.kind != null)
    | .metadata.labels["cell.poc.internal/harness"] = strenv(COMP)
    | with(select(.spec.template.metadata != null); .spec.template.metadata.labels["cell.poc.internal/harness"] = strenv(COMP))'
