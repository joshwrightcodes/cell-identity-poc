# The SPIRE agent sidecar of a workload. Source this file from a render script.
#
# spire_sidecar <workload> <cluster_jwt|k8s_psat> reads one Deployment or StatefulSet on standard
# input. It prints the workload with a SPIRE agent sidecar, then the objects that the sidecar needs:
#   - shareProcessNamespace: true, so the unix workload attestor reads the uid of each caller from
#     /proc of the agent container.
#   - the spire-agent container as user 1000 with no capabilities, with requests and limits. It runs
#     as another user than each workload entry selects, so no entry matches the agent process.
#   - memory volumes for the agent data and the Workload API socket, the config and the trust
#     bundle, and a projected token that only the agent container mounts.
#   - the annotation cell.poc.internal/config-checksum. SPIRE reads its config and the trust bundle
#     only at start, so a change restarts the pod.
#   - ConfigMaps with agent.conf and the trust bundle (key bundle.crt).
#   - cluster_jwt only: the init container that installs the plugin from the cluster-jwt-agent
#     image, the downward API variables that the plugin reads, and a Role and RoleBinding
#     <workload>-token that let the agent request tokens for the ServiceAccount of the workload only.
# Each container that needs an SVID mounts the socket volume at /run/spire/agent itself. Each
# container of the workload sets a runAsUser other than 0 and 1000, directly or in the pod.
#
# Inputs:
#   SPIRE_SIDECAR_SERVER_ADDRESS    the address of the SPIRE server
#   SPIRE_SIDECAR_SERVER_PORT       its port: the node port 30081 for cells, 8081 in a plane
#   SPIRE_SIDECAR_TRUST_DOMAIN      the trust domain of the server
#   SPIRE_SIDECAR_BUNDLE            the PEM roots of that trust domain, already checked
#   SPIRE_SIDECAR_CELL              cluster_jwt: the cell, or @CELL_NAME@ for hydrate to replace
#   SPIRE_SIDECAR_CLUSTER           k8s_psat: the cluster name in the k8s_psat config of the server
#   POC_ENV                         cluster_jwt: the environment of the attestation audience
#   SPIRE_SIDECAR_AGENT_CONFIGMAP   default spire-agent-<workload>
#   SPIRE_SIDECAR_BUNDLE_CONFIGMAP  default spire-trust-bundle-<workload>
#   SPIRE_SIDECAR_SOCKET_VOLUME     default spire-agent-socket
#   CELL_NAME                       optional: the checksum covers the config with @CELL_NAME@ replaced
# The helper prints nothing when a check fails, and returns 1 with the reason on standard error.

SPIRE_SIDECAR_LIB="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SPIRE_SIDECAR_LIB/../../scripts/ko-image.sh"

SPIRE_AGENT_IMAGE=ghcr.io/spiffe/spire-agent:1.15.5@sha256:3652c732b0f0d36f4dd78394230a1b1cd0ddcc29548a46c67a996b1a78c14481

# The body runs in a subshell, so a failed check ends only the helper.
spire_sidecar() (
  set -euo pipefail
  workload="$1" mode="$2"
  die() { printf 'error: spire_sidecar %s: %s\n' "$workload" "$*" >&2; exit 1; }

  case "$mode" in
    cluster_jwt) [[ -n "${SPIRE_SIDECAR_CELL:-}" ]] || die "SPIRE_SIDECAR_CELL is not set"
      [[ "${POC_ENV:-}" =~ ^[a-z0-9][a-z0-9-]{0,30}$ ]] || die "POC_ENV '${POC_ENV:-}' is not a short DNS label" ;;
    k8s_psat) [[ "${SPIRE_SIDECAR_CLUSTER:-}" =~ ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$ ]] \
      || die "SPIRE_SIDECAR_CLUSTER '${SPIRE_SIDECAR_CLUSTER:-}' is not a cluster name" ;;
    *) die "mode '$mode' is not cluster_jwt or k8s_psat" ;;
  esac
  [[ "$workload" =~ ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$ ]] || die "the workload name is not a DNS label"
  [[ "${SPIRE_SIDECAR_SERVER_ADDRESS:-}" =~ ^[a-z0-9.-]+$ ]] || die "SPIRE_SIDECAR_SERVER_ADDRESS '${SPIRE_SIDECAR_SERVER_ADDRESS:-}' is not an address"
  [[ "${SPIRE_SIDECAR_SERVER_PORT:-}" =~ ^[1-9][0-9]{0,4}$ ]] && ((SPIRE_SIDECAR_SERVER_PORT <= 65535)) \
    || die "SPIRE_SIDECAR_SERVER_PORT '${SPIRE_SIDECAR_SERVER_PORT:-}' is not a port"
  [[ "${SPIRE_SIDECAR_TRUST_DOMAIN:-}" =~ ^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$ ]] || die "SPIRE_SIDECAR_TRUST_DOMAIN '${SPIRE_SIDECAR_TRUST_DOMAIN:-}' is not a trust domain name"
  [[ "${SPIRE_SIDECAR_BUNDLE:-}" == *"-----BEGIN CERTIFICATE-----"* ]] || die "SPIRE_SIDECAR_BUNDLE holds no PEM certificate"
  agent_cm="${SPIRE_SIDECAR_AGENT_CONFIGMAP:-spire-agent-$workload}"
  bundle_cm="${SPIRE_SIDECAR_BUNDLE_CONFIGMAP:-spire-trust-bundle-$workload}"
  socket="${SPIRE_SIDECAR_SOCKET_VOLUME:-spire-agent-socket}"

  input="$(cat)"
  [[ "$(yq -N '.kind' <<<"$input")" =~ ^(Deployment|StatefulSet)$ ]] || die "the input is not one Deployment or StatefulSet"
  ns="$(yq '.metadata.namespace // ""' <<<"$input")"
  sa="$(yq '.spec.template.spec.serviceAccountName // ""' <<<"$input")"
  [[ -n "$ns" && -n "$sa" ]] || die "the workload sets no namespace or no serviceAccountName"

  # The volume and container names of the sidecar must be free in the workload.
  token=agent-token
  own=(agent-config trust-bundle data "$socket" spire-agent)
  if [[ "$mode" == cluster_jwt ]]; then
    token=api-token
    own+=(plugins tmp install-agent-plugin)
  fi
  own+=("$token")
  taken="$(yq -N '(.spec.template.spec.volumes // [])[].name, (.spec.volumeClaimTemplates // [])[].metadata.name,
    (.spec.template.spec.initContainers // [])[].name, .spec.template.spec.containers[].name' <<<"$input")"
  for name in "${own[@]}"; do
    grep -qxF -- "$name" <<<"$taken" && die "the workload already has a volume or container named $name"
  done
  NAME="$socket" yq -e '[.spec.template.spec.containers[].volumeMounts[]? | select(.name == strenv(NAME))] | length > 0' <<<"$input" >/dev/null \
    || die "no container mounts $socket, so no container can reach the Workload API"
  # The pod shares one process namespace. A container that runs as the agent user could read the
  # agent key and token through /proc, and one with no fixed user runs as the image default.
  users="$(yq -N '(.spec.template.spec.securityContext.runAsUser // "") as $pod
    | ((.spec.template.spec.initContainers // []) + .spec.template.spec.containers)[]
    | .name + "=" + ((.securityContext.runAsUser // $pod) | tostring)' <<<"$input")"
  while IFS='=' read -r name uid; do
    [[ -n "$uid" ]] || die "container $name sets no runAsUser, so it could run as the agent user 1000"
    [[ "$uid" != 1000 && "$uid" != 0 ]] || die "container $name runs as user $uid, and only the agent may run as 1000, no container as root"
  done <<<"$users"

  if [[ "$mode" == cluster_jwt ]]; then
    plugin_image="$(ko_image cluster-jwt-agent)" || die "no agent plugin image"
    checksum="$(ko_binary_sha256 "$plugin_image" /ko-app/cluster-jwt-agent)" || die "no agent plugin checksum"
    template="$SPIRE_SIDECAR_LIB/spire-agent-cluster-jwt.conf"
  else
    plugin_image="" checksum="" template="$SPIRE_SIDECAR_LIB/spire-agent-k8s-psat.conf"
  fi
  agent_conf="$(sed -e "s|@SPIRE_WORKLOAD@|$workload|g" -e "s|@SPIRE_TRUST_DOMAIN@|$SPIRE_SIDECAR_TRUST_DOMAIN|g" \
    -e "s|@SPIRE_SERVER_ADDRESS@|$SPIRE_SIDECAR_SERVER_ADDRESS|" -e "s|@SPIRE_SERVER_PORT@|$SPIRE_SIDECAR_SERVER_PORT|" \
    -e "s|@SPIRE_AGENT_PLUGIN_CHECKSUM@|$checksum|" -e "s|@SPIRE_CELL@|${SPIRE_SIDECAR_CELL:-}|" \
    -e "s|@SPIRE_CLUSTER@|${SPIRE_SIDECAR_CLUSTER:-}|" -e "s|@POC_ENV@|${POC_ENV:-}|g" "$template")"

  # config_map <name> <key> <content> prints a ConfigMap with one literal block value.
  config_map() {
    NAME="$1" KEY="$2" VALUE="$3" NS="$ns" yq -n '
      .apiVersion = "v1" | .kind = "ConfigMap" | .metadata.name = strenv(NAME) | .metadata.namespace = strenv(NS)
      | .data[strenv(KEY)] = strenv(VALUE) | .data[strenv(KEY)] style="literal"'
  }
  config_maps="$(config_map "$agent_cm" agent.conf "$agent_conf"; echo "---"; config_map "$bundle_cm" bundle.crt "$SPIRE_SIDECAR_BUNDLE")"
  # The checksum covers the config after hydrate replaces @CELL_NAME@, so it differs for each cell.
  if [[ -n "${CELL_NAME:-}" ]]; then
    config_checksum="$(printf '%s' "${config_maps//@CELL_NAME@/$CELL_NAME}" | sha256)"
  else
    config_checksum="$(printf '%s' "$config_maps" | sha256)"
  fi

  # The agent image runs as root by default. The sidecar runs as user 1000. The image has no shell,
  # so the probes run the agent binary against the Workload API socket. The socket exists only after the
  # attestation, so the startup probe gives a bootstrapping agent 120 s, for example after an island heals,
  # before the liveness and readiness probes run.
  agent="$(cat <<EOF
name: spire-agent
image: $SPIRE_AGENT_IMAGE
args: ["-config", "/run/spire/config/agent.conf"]
startupProbe:
  exec:
    command: ["/opt/spire/bin/spire-agent", "healthcheck", "-socketPath", "/run/spire/agent/agent.sock"]
  periodSeconds: 10
  timeoutSeconds: 5
  failureThreshold: 12
readinessProbe:
  exec:
    command: ["/opt/spire/bin/spire-agent", "healthcheck", "-socketPath", "/run/spire/agent/agent.sock"]
  periodSeconds: 10
  timeoutSeconds: 5
livenessProbe:
  exec:
    command: ["/opt/spire/bin/spire-agent", "healthcheck", "-shallow", "-socketPath", "/run/spire/agent/agent.sock"]
  initialDelaySeconds: 30
  periodSeconds: 30
  timeoutSeconds: 5
securityContext:
  runAsUser: 1000
  runAsGroup: 1000
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true
  capabilities:
    drop: ["ALL"]
resources:
  requests:
    cpu: 20m
    memory: 32Mi
  limits:
    memory: 128Mi
volumeMounts:
  - name: agent-config
    mountPath: /run/spire/config
    readOnly: true
  - name: trust-bundle
    mountPath: /run/spire/bundle
    readOnly: true
  - name: data
    mountPath: /run/spire/data
  - name: $socket
    mountPath: /run/spire/agent
EOF
)"
  volumes="$(cat <<EOF
- name: agent-config
  configMap:
    name: $agent_cm
- name: trust-bundle
  configMap:
    name: $bundle_cm
- name: data
  emptyDir:
    medium: Memory
    sizeLimit: 1Mi
- name: $socket
  emptyDir:
    medium: Memory
    sizeLimit: 1Mi
EOF
)"
  if [[ "$mode" == cluster_jwt ]]; then
    # The cluster_jwt plugin binds its token to this pod and names it in the TokenRequest. go-plugin
    # creates the plugin socket in the temporary directory. The token volume has the same files as
    # the automatic token mount, for the agent container only.
    agent="$(yq '.env = [
        {"name": "POD_NAME", "valueFrom": {"fieldRef": {"fieldPath": "metadata.name"}}},
        {"name": "POD_UID", "valueFrom": {"fieldRef": {"fieldPath": "metadata.uid"}}},
        {"name": "POD_NAMESPACE", "valueFrom": {"fieldRef": {"fieldPath": "metadata.namespace"}}},
        {"name": "SERVICE_ACCOUNT", "valueFrom": {"fieldRef": {"fieldPath": "spec.serviceAccountName"}}}]
      | .volumeMounts += [
        {"name": "plugins", "mountPath": "/run/spire/plugins", "readOnly": true},
        {"name": "tmp", "mountPath": "/tmp"},
        {"name": "api-token", "mountPath": "/var/run/secrets/kubernetes.io/serviceaccount", "readOnly": true}]' <<<"$agent")"
    volumes="$(yq '. += [
        {"name": "plugins", "emptyDir": {"sizeLimit": "128Mi"}},
        {"name": "tmp", "emptyDir": {"medium": "Memory", "sizeLimit": "16Mi"}},
        {"name": "api-token", "projected": {"sources": [
          {"serviceAccountToken": {"path": "token", "expirationSeconds": 600}},
          {"configMap": {"name": "kube-root-ca.crt", "items": [{"key": "ca.crt", "path": "ca.crt"}]}},
          {"downwardAPI": {"items": [{"path": "namespace", "fieldRef": {"fieldPath": "metadata.namespace"}}]}}]}}]' <<<"$volumes")"
    # The plugin image copies its static binary into the shared plugin volume, read-only for every
    # user. User 1001 matches neither the agent nor a workload entry.
    init="$(PLUGIN="$plugin_image" yq -n '[{"name": "install-agent-plugin", "image": strenv(PLUGIN),
      "args": ["install", "/run/spire/plugins"],
      "securityContext": {"runAsUser": 1001, "runAsGroup": 1001, "allowPrivilegeEscalation": false,
        "readOnlyRootFilesystem": true, "capabilities": {"drop": ["ALL"]}},
      "resources": {"requests": {"cpu": "10m", "memory": "16Mi"}, "limits": {"memory": "64Mi"}},
      "volumeMounts": [{"name": "plugins", "mountPath": "/run/spire/plugins"}]}]')"
  else
    # The k8s_psat token has the audience that the server plugin checks.
    agent="$(yq '.volumeMounts += [{"name": "agent-token", "mountPath": "/var/run/secrets/tokens", "readOnly": true}]' <<<"$agent")"
    volumes="$(yq '. += [{"name": "agent-token", "projected": {"sources": [
        {"serviceAccountToken": {"path": "spire-agent", "audience": "spire-server", "expirationSeconds": 600}}]}}]' <<<"$volumes")"
    init='[]'
  fi

  patch='.spec.template.metadata.annotations["cell.poc.internal/config-checksum"] = strenv(SUM)
    | .spec.template.spec.shareProcessNamespace = true
    | .spec.template.spec.containers = [env(AGENT)] + .spec.template.spec.containers
    | .spec.template.spec.volumes = (.spec.template.spec.volumes // []) + env(VOLUMES)'
  [[ "$init" == '[]' ]] || patch+=' | .spec.template.spec.initContainers = env(INIT) + (.spec.template.spec.initContainers // [])'
  out="$(AGENT="$agent" VOLUMES="$volumes" INIT="$init" SUM="$config_checksum" yq "$patch" <<<"$input")"
  if [[ "$mode" == cluster_jwt ]]; then
    out+=$'\n---\n'"$(NAME="$workload-token" NS="$ns" SA="$sa" yq -n '
      .apiVersion = "rbac.authorization.k8s.io/v1" | .kind = "Role"
      | .metadata.name = strenv(NAME) | .metadata.namespace = strenv(NS)
      | .rules = [{"apiGroups": [""], "resources": ["serviceaccounts/token"], "resourceNames": [strenv(SA)], "verbs": ["create"]}]')"
    out+=$'\n---\n'"$(NAME="$workload-token" NS="$ns" SA="$sa" yq -n '
      .apiVersion = "rbac.authorization.k8s.io/v1" | .kind = "RoleBinding"
      | .metadata.name = strenv(NAME) | .metadata.namespace = strenv(NS)
      | .roleRef = {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": strenv(NAME)}
      | .subjects = [{"kind": "ServiceAccount", "name": strenv(SA), "namespace": strenv(NS)}]')"
  fi
  printf '%s\n---\n%s\n' "$out" "$config_maps"
)
