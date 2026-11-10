#!/usr/bin/env bash
# Render the central Argo CD view of management, a link component.
#
# The bundle holds:
#   - Namespace central-view-system, and one agent namespace <env>-<cell> for each cell of
#     VIEW_CELLS, each with Pod Security restricted and a default deny. The principal creates no
#     namespace.
#   - argocd-server, argocd-repo-server and argocd-redis from the full Argo CD install, as
#     kustomization.yaml changes them. render.sh keeps only those parts, and sets
#     application.namespaces to the agent namespaces.
#   - The Argo CD Agent principal with cell-proxy and a k8s_psat SPIRE agent sidecar
#     (principal.yaml), a Role in each agent namespace that lets the principal write Applications
#     there, Service view-listener on node port 31443, and Job viewkeys.
#   - The NetworkPolicies of network-policy.yaml.
#
# The render reads these facts from outside the cluster, so it runs in the link phase:
#   - the node address of dev-cp, from the host service. Only that address reaches the node port.
#   - the root of the environment trust domain, from the live SPIRE server of dev-cp, as ConfigMap
#     peer-root (components/lib/peer-root.sh). cell-proxy trusts agents only through it.
#   - the root of the management trust domain, from the live SPIRE server of this cluster, for
#     the trust bundle of the sidecar.
#   - a signed record for each cell of VIEW_CELLS, as ConfigMap cell-registry
#     (components/lib/registry.sh). The cells must exist.
#   - the cell-proxy and viewkeys images that `mise run images` built, by digest.
# The pod template carries the SHA-256 of the peer root and of the registry content, so a new
# root or a new set of cells restarts the pod.
# Inputs: VIEW_CELLS and SPIRE_TRUST_DOMAIN from cells/management.env, POC_ENV and
# ARGOCD_AGENT_IMAGE from cells/common.env, and the cluster facts from build/<cluster>/facts.env.
set -euo pipefail
: "${CELL_NAME:?}" "${POC_ENV:?}" "${VIEW_CELLS:?}" "${SPIRE_TRUST_DOMAIN:?}" "${ARGOCD_AGENT_IMAGE:?}"
: "${NODE_IPS:?}" "${API_SERVER_IPS:?}" "${API_SERVER_PORT:?}" "${API_SERVICE_IP:?}" "${DNS_SERVICE_IP:?}"

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
namespace=central-view-system
component=central-view
# The environment control plane, and the trust domain of the agents in its cells.
env_cluster=dev-cp
env_td=dev.env.poc.internal

die() { printf 'error: central-view render: %s\n' "$*" >&2; exit 1; }

source "$root/scripts/ko-image.sh"
source "$root/components/lib/addresses.sh"
source "$root/components/lib/peer-root.sh"
source "$root/components/lib/registry.sh"
source "$root/components/lib/spire-sidecar.sh"

[[ "$POC_ENV" =~ ^[a-z0-9][a-z0-9-]{0,30}$ ]] || die "POC_ENV '$POC_ENV' is not a short DNS label"
[[ "$ARGOCD_AGENT_IMAGE" =~ @sha256:[0-9a-f]{64}$ ]] || die "ARGOCD_AGENT_IMAGE '$ARGOCD_AGENT_IMAGE' is not pinned by digest"
read -r -a cells <<<"$VIEW_CELLS"
((${#cells[@]} > 0)) || die "VIEW_CELLS names no cell"
agents=()
for cell in "${cells[@]}"; do
  # The agent name <env>-<cell> must fit a 63-character label.
  [[ "$cell" =~ ^[a-z0-9]([a-z0-9-]{0,57}[a-z0-9])?$ ]] || die "VIEW_CELLS entry '$cell' is not a cell name of at most 59 characters"
  case "$cell" in cp | dev-cp | management | rogue) die "VIEW_CELLS names the reserved name $cell" ;; esac
  agents+=("$POC_ENV-$cell")
done
agent_list="$(IFS=,; echo "${agents[*]}")"

node_ips="$(ipv4_list NODE_IPS)" || exit 1
api_ips="$(ipv4_list API_SERVER_IPS)" || exit 1
[[ "$API_SERVER_PORT" =~ ^[0-9]+$ ]] || die "API_SERVER_PORT '$API_SERVER_PORT' is not a port number"
ipv4='^([0-9]{1,3}\.){3}[0-9]{1,3}$'
[[ "$API_SERVICE_IP" =~ $ipv4 && "$DNS_SERVICE_IP" =~ $ipv4 ]] || die "API_SERVICE_IP or DNS_SERVICE_IP is not an IPv4 address"
if ! facts="$(cd "$root" && mise run hostsvc -- facts --cluster "$env_cluster" 2>/dev/null)"; then
  die "no host service facts for $env_cluster: ${facts:-no output}. Run: CELL=$env_cluster mise run cell:up"
fi
env_ip="$(jq -r '.nodeIP // ""' <<<"$facts")"
[[ "$env_ip" =~ $ipv4 ]] || die "node address of $env_cluster is '$env_ip', not an IPv4 address"

peers() { for ip in "$@"; do printf '{"ipBlock":{"cidr":"%s/32"}}\n' "$ip"; done | jq -cs .; }
node_peers="$(peers $node_ips)"
api_peers="$(peers $api_ips)"
env_peers="$(peers "$env_ip")"

cell_proxy_image="$(ko_image cell-proxy)" || die "no cell-proxy image"
viewkeys_image="$(ko_image viewkeys)" || die "no viewkeys image"
peer_root="$(peer_root_configmap peer-root "$namespace" "$env_cluster" "$env_td")" || exit 1
own_bundle="$(peer_root_pem "$CELL_NAME" "$SPIRE_TRUST_DOMAIN")" || exit 1
registry="$(registry_configmap "$namespace" "$POC_ENV" "${cells[@]}")" || exit 1
peer_sum="$(yq -r '.metadata.annotations["poc.internal/peer-root-sha256"]' <<<"$peer_root")"
registry_sum="$(yq -r '.metadata.annotations["poc.internal/registry-content-sha256"]' <<<"$registry")"
[[ "$peer_sum" =~ ^[0-9a-f]{64}$ && "$registry_sum" =~ ^[0-9a-f]{64}$ ]] || die "the peer root or the registry has no checksum"

# The agent name is the first capture group of the header value, and the header comes only from
# cell-proxy, which sets <env>-<cell> from the verified SVID.
auth="header:x-cell-agent:^(${POC_ENV//./\\.}-[a-z0-9-]{1,59})\$"
allow_id="^spiffe://${env_td//./\\.}/cell/([a-z0-9-]+)/argocd-agent\$"
# The principal identity only has to stay the same across renders of this cluster.
principal_uid="$(printf '%s/%s/argocd-agent-principal' "$CELL_NAME" "$namespace" | sha256 \
  | sed -E 's/^(.{8})(.{4})(.{4})(.{4})(.{12}).*/\1-\2-\3-\4-\5/')"

# The Argo CD parts of the full install that the view keeps.
keep='ConfigMap/argocd-cm ConfigMap/argocd-cmd-params-cm ConfigMap/argocd-rbac-cm ConfigMap/argocd-gpg-keys-cm
  ConfigMap/argocd-ssh-known-hosts-cm ConfigMap/argocd-tls-certs-cm
  ServiceAccount/argocd-server ServiceAccount/argocd-repo-server ServiceAccount/argocd-redis
  Role/argocd-server Role/argocd-redis RoleBinding/argocd-server RoleBinding/argocd-redis
  ClusterRole/argocd-server ClusterRoleBinding/argocd-server
  Service/argocd-server Service/argocd-repo-server Service/argocd-redis
  Deployment/argocd-server Deployment/argocd-repo-server Deployment/argocd-redis'
argocd="$(kustomize build --load-restrictor LoadRestrictionsNone "$here")" || die "kustomize build failed"
argocd="$(KEEP=" $(echo $keep) " yq 'select(.kind != null) | (" " + .kind + "/" + .metadata.name + " ") as $k | select(strenv(KEEP) | contains($k))' <<<"$argocd")"
got="$(yq -N '.kind + "/" + .metadata.name' <<<"$argocd" | sort | tr '\n' ' ')"
want="$(printf '%s\n' $keep | sort | tr '\n' ' ')"
[[ "$got" == "$want" ]] || die "the full install gives '$got', and the view keeps '$want'"
argocd="$(sed "s|@APPLICATION_NAMESPACES@|$agent_list|" <<<"$argocd")"

namespaces="$(for ns in "$namespace" "${agents[@]}"; do
  NS="$ns" yq -n '.apiVersion = "v1" | .kind = "Namespace" | .metadata.name = strenv(NS)
    | .metadata.labels = {"istio-injection": "disabled", "pod-security.kubernetes.io/enforce": "restricted"}'
  echo "---"
done
for ns in "${agents[@]}"; do
  NS="$ns" yq -n '.apiVersion = "networking.k8s.io/v1" | .kind = "NetworkPolicy"
    | .metadata.name = "default-deny" | .metadata.namespace = strenv(NS)
    | .spec.podSelector = {} | .spec.policyTypes = ["Ingress", "Egress"]'
  echo "---"
  NS="$ns" yq -n '.apiVersion = "rbac.authorization.k8s.io/v1" | .kind = "Role"
    | .metadata.name = "argocd-agent-principal" | .metadata.namespace = strenv(NS)
    | .rules = [{"apiGroups": ["argoproj.io"], "resources": ["applications", "applicationsets"],
        "verbs": ["create", "get", "list", "watch", "update", "patch", "delete"]}]'
  echo "---"
  NS="$ns" yq -n '.apiVersion = "rbac.authorization.k8s.io/v1" | .kind = "RoleBinding"
    | .metadata.name = "argocd-agent-principal" | .metadata.namespace = strenv(NS)
    | .roleRef = {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": "argocd-agent-principal"}
    | .subjects = [{"kind": "ServiceAccount", "name": "argocd-agent-principal", "namespace": "central-view-system"}]'
  echo "---"
  # A refresh in the UI patches the refresh annotation of the Application.
  NS="$ns" yq -n '.apiVersion = "rbac.authorization.k8s.io/v1" | .kind = "Role"
    | .metadata.name = "argocd-server" | .metadata.namespace = strenv(NS)
    | .rules = [{"apiGroups": ["argoproj.io"], "resources": ["applications"], "verbs": ["patch"]}]'
  echo "---"
  NS="$ns" yq -n '.apiVersion = "rbac.authorization.k8s.io/v1" | .kind = "RoleBinding"
    | .metadata.name = "argocd-server" | .metadata.namespace = strenv(NS)
    | .roleRef = {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": "argocd-server"}
    | .subjects = [{"kind": "ServiceAccount", "name": "argocd-server", "namespace": "central-view-system"}]'
  echo "---"
done)"

principal="$(sed -e "s|@ARGOCD_AGENT_IMAGE@|$ARGOCD_AGENT_IMAGE|" -e "s|@CELL_PROXY_IMAGE@|$cell_proxy_image|" \
    -e "s|@PEER_ROOT_SHA256@|$peer_sum|" -e "s|@REGISTRY_SHA256@|$registry_sum|" \
    -e "s|@AGENT_NAMESPACES@|$agent_list|" -e "s|@PEER_TRUST_DOMAIN@|$env_td|" -e "s|@PRINCIPAL_UID@|$principal_uid|" \
    "$here/principal.yaml" \
  | AUTH="$auth" ALLOW="$allow_id" yq '(.. | select(. == "--auth=@PRINCIPAL_AUTH@")) = "--auth=" + strenv(AUTH)
      | (.. | select(. == "--allow-id=@ALLOW_ID@")) = "--allow-id=" + strenv(ALLOW)')"
deployment="$(yq 'select(.kind == "Deployment")' <<<"$principal" \
  | SPIRE_SIDECAR_SERVER_ADDRESS=spire-server.spire-system.svc.cluster.local SPIRE_SIDECAR_SERVER_PORT=8081 \
    SPIRE_SIDECAR_TRUST_DOMAIN="$SPIRE_TRUST_DOMAIN" SPIRE_SIDECAR_BUNDLE="$own_bundle" SPIRE_SIDECAR_CLUSTER="$CELL_NAME" \
    spire_sidecar argocd-agent-principal k8s_psat)" || die "the SPIRE sidecar of the principal failed"

secrets_list="$(printf '"%s"\n' argocd-agent-ca argocd-agent-resource-proxy-tls argocd-agent-jwt argocd-secret \
  $(printf 'cluster-%s ' "${agents[@]}") | jq -cs .)"
viewkeys="$(sed -e "s|@VIEWKEYS_IMAGE@|$viewkeys_image|" -e "s|@AGENTS@|$agent_list|" "$here/viewkeys-job.yaml" \
  | SECRETS="$secrets_list" yq '(select(.kind == "Role") | .rules[1].resourceNames) = (env(SECRETS) | ... style="flow")')"

policies="$(NODE="$node_peers" API="$api_peers" ENVP="$env_peers" PORT="$API_SERVER_PORT" yq '
    (.. | select(. == "@NODE_PEERS@")) |= (env(NODE) | ... style="")
    | (.. | select(. == "@ENV_NODE_PEERS@")) |= (env(ENVP) | ... style="")
    | (.. | select(. == "@API_SERVER_PEERS@")) |= (env(API) | ... style="")
    | (.. | select(. == "@API_SERVER_PORT@")) |= env(PORT)' "$here/network-policy.yaml" \
  | sed -e "s|@API_SERVICE_IP@|$API_SERVICE_IP|" -e "s|@DNS_SERVICE_IP@|$DNS_SERVICE_IP|")"

# Every object carries the harness label of the link component, and every pod template too, so
# cell:verify can tie each pod of a plane ServiceAccount to its workload.
{
  echo "$namespaces"
  echo "$argocd"
  echo "---"
  yq 'select(.kind != "Deployment")' <<<"$principal"
  echo "---"
  echo "$deployment"
  echo "---"
  echo "$viewkeys"
  echo "---"
  echo "$policies"
  echo "---"
  echo "$peer_root"
  echo "---"
  echo "$registry"
} | COMP="$component" yq 'select(.kind != null)
    | .metadata.labels["cell.poc.internal/harness"] = strenv(COMP)
    | with(select(.spec.template.metadata != null); .spec.template.metadata.labels["cell.poc.internal/harness"] = strenv(COMP))'
