# Shared helpers. Source this file; do not run it.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# POC_BUILD_ROOT names another build directory, for the tests.
BUILD_ROOT="${POC_BUILD_ROOT:-$ROOT/build}"

log() { printf '==> %s\n' "$*" >&2; }

die() { printf 'error: %s\n' "$*" >&2; exit 1; }

# json_fail <name> <error> [key=value...] prints one JSON error line on standard output, in the
# shape of the Go commands (log/slog JSONHandler), and exits with status 1. A script whose standard
# output carries data uses it, so a caller never reads a partial result as data.
json_fail() {
  local name="$1" error="$2" pair args=()
  shift 2
  for pair in "$@"; do args+=(--arg "${pair%%=*}" "${pair#*=}"); done
  jq -nc --arg time "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --arg msg "$name failed" --arg error "$error" "${args[@]}" \
    '{time: $time, level: "ERROR", msg: $msg, error: $error} + (reduce ($ARGS.named | to_entries[] | select(.key != "time" and .key != "msg" and .key != "error")) as $e ({}; .[$e.key] = $e.value))'
  exit 1
}

# CELL names the cluster. cells/common.env and cells/$CELL.env hold its settings.
CELL="${CELL:-dev-cell-1}"
[[ -f "$ROOT/cells/$CELL.env" ]] || die "unknown cell '$CELL'. Known cells: $(cd "$ROOT/cells" && ls *.env | sed -e 's/\.env$//' -e '/^common$/d' | paste -sd' ' -)"
# A nested run inherits the variables of the outer cluster: mgmt:rotate-ca runs cell:up for each other
# cluster from a shell that holds the settings of management. A variable that a cell env file defines
# and that the cluster CELL leaves out would then reach its renders, for example COLLECTOR_STORE. So
# drop every variable that any cell env file defines, and take them from common.env and
# cells/$CELL.env alone.
for _name in $(sed -n 's/^\([A-Z_][A-Z0-9_]*\)=.*/\1/p' "$ROOT"/cells/*.env | sort -u); do
  [[ "$_name" == CELL ]] || unset "$_name"
done
unset _name
set -a
source "$ROOT/cells/common.env"
source "$ROOT/cells/$CELL.env"
set +a
[[ "$CELL_NAME" == "$CELL" ]] || die "cells/$CELL.env sets CELL_NAME=$CELL_NAME"

BUILD="$BUILD_ROOT/$CELL"
BUNDLES="$BUILD/bundles"
FACTS="$BUILD/facts.env"
# publish.sh writes the digest of each bundle that it pushed here, one <name>=<digest> line each.
PUBLISHED="$BUILD/published.env"

# Component sets. Each set name in harness/topology.yaml maps to a list of bundles.
# Each entry is <component>:<sync wave>:<destination namespace>.
BASE_CELL_COMPONENTS=(
  "namespaces:-2:default"
  "argocd:-1:argocd"
  "cell-system:-1:cell-system"
  "network-policy:0:default"
  "istio-base:1:istio-system"
  "istio-cni:2:istio-system"
  "istiod:3:istio-system"
  "observability-system:3:observability-system"
  "istio-egress:4:istio-egress"
  "mesh-policy:4:istio-system"
  "apps-demo:5:apps-demo"
)

# The External Secrets Operator. It must be healthy, with its CRDs, before a later wave applies an ExternalSecret.
EXTERNAL_SECRETS_COMPONENTS=(
  "external-secrets:6:external-secrets"
)

# The SPIRE server of the environment trust domain. It comes last, after the base cell is healthy.
SPIRE_SERVER_COMPONENTS=(
  "spire-server:7:spire-system"
)

# The relay of the environment control plane. Its render reads only node addresses from the host
# service, so it needs no earlier wave beyond the base cell.
RELAY_SYSTEM_COMPONENTS=(
  "relay-system:8:relay-system"
)

# The telemetry store of management: Grafana, Prometheus, Loki and Tempo in one StatefulSet, and the
# Password generator of the Grafana admin password. It needs the operator of external-secrets, so it
# comes after wave 6.
OBSERVABILITY_STORE_COMPONENTS=(
  "observability-store:8:observability-system"
)

# Harness components. The harness renders and applies them itself, like the bootstrap set. They stay
# out of the root bundle and out of every Argo CD Application. A bundle can still write to their
# namespace, as the residual limits in docs/design/poc-scope.md say.
# Each entry is <component>:<namespace>. A harness component can share its namespace with the
# objects of a bundle. Every harness object carries the label HARNESS_LABEL=<component>, and
# cell:up, cell:restart and cell:verify act only on the labelled objects there.
# celld with its SPIRE agent sidecar attests to the SPIRE server in SPIRE_SERVER_CLUSTER.
CELL_IDENTITY_HARNESS=(
  "cell-identity:cell-identity-system"
)
# The Argo CD Agent of the cell shares the namespace argocd with Argo CD. Its cell-proxy sidecar
# dials the relay of the environment control plane, and its SPIRE agent sidecar attests to the
# server in SPIRE_SERVER_CLUSTER.
ARGOCD_AGENT_HARNESS=(
  "argocd-agent:argocd"
)

# The uplink of the collector. It carries the telemetry of the cluster over SPIFFE mTLS: in a cell
# through the relay of dev-cp (cluster_jwt agent sidecar), in dev-cp straight to the gateway in
# management (k8s_psat agent sidecar). Both forms are the harness component otel-uplink, and the
# render picks the form from COLLECTOR_PLANE. dev-cp needs its SPIRE server for the trust bundle of
# the sidecar, and the server does not exist at the first hydrate, so the harness applies the
# uplink after the waves.
OTEL_UPLINK_HARNESS=(
  "otel-uplink:observability-system"
)

# envd pulls the signed spec and records from mgmtd and writes ConfigMap spire-system/cell-records, which
# the SPIRE server of dev-cp reads. It owns the namespace envd-system, and its Role and RoleBinding live
# in spire-system, next to the objects of the spire-server bundle. Its render reads the live SPIRE server
# of its own cluster, so it renders after the waves.
ENVD_HARNESS=(
  "envd:envd-system"
)

# The mesh-view tunnel of a cell reads the roots of management and of SPIRE_SERVER_CLUSTER, which
# exist before the cell, so it renders with the other harness components. It owns the namespace
# mesh-view-system, which only this cluster uses for the tunnel.
MESH_VIEW_HARNESS=(
  "mesh-view:mesh-view-system"
)

# LATE_HARNESS names the harness components whose render reads a live SPIRE server of the cluster
# itself. On a clean harness:up that server does not exist at the first hydrate, so up.sh renders
# these components after the waves (HYDRATE_ONLY=late) and the first hydrate skips them
# (CELL_UP_SKIP_LATE=1).
LATE_HARNESS=(otel-uplink envd)

# Link components. scripts/link.sh renders and applies them in the link phase, after every wave
# and harness component, because their render reads the live roots and node addresses of other
# clusters. They follow the harness rules: no Argo CD Application holds them, every object carries
# HARNESS_LABEL=<component>, and cell:verify and cell:restart act on the labelled objects.
# Each entry is <component>:<namespace>.
CENTRAL_VIEW_LINK=(
  "central-view:central-view-system"
)
# The management plane stand-in: mgmtd with its SPIRE agent sidecar, the intent, the host service pin
# and the public signing key. It owns the namespace mgmt-system. Its render reads the host service
# and the live roots of management and, when it exists, of VIEW_CONTROL_PLANE. It comes first, and it
# must run before dev-cp exists, because dev-cp reads its signing key.
MGMT_PLANE_LINK=(
  "mgmt-api:mgmt-system"
)
# The telemetry gateway shares observability-system with the collector and the store. It carries the
# harness label, so cell:verify tells its objects from those of the bundles.
TELEMETRY_GATEWAY_LINK=(
  "telemetry-gateway:observability-system"
)

# The hub of the mesh view in management, with Kiali. It owns the namespace mesh-view-system, and its
# render reads the live roots of VIEW_CONTROL_PLANE and the cells of MESH_VIEW_CELLS.
MESH_VIEW_HUB_LINK=(
  "mesh-view-hub:mesh-view-system"
)

# Read the component sets of $CELL from the topology. An unknown set name is an error.
COMPONENTS=()
HARNESS_COMPONENTS=()
LINK_COMPONENTS=()
set_names="$(yq -r ".clusters[] | select(.name == \"$CELL\") | .components[]" "$ROOT/harness/topology.yaml")"
for set_name in $set_names; do
  case "$set_name" in
    base-cell) COMPONENTS+=("${BASE_CELL_COMPONENTS[@]}") ;;
    external-secrets) COMPONENTS+=("${EXTERNAL_SECRETS_COMPONENTS[@]}") ;;
    spire-server) COMPONENTS+=("${SPIRE_SERVER_COMPONENTS[@]}") ;;
    relay-system) COMPONENTS+=("${RELAY_SYSTEM_COMPONENTS[@]}") ;;
    observability-store) COMPONENTS+=("${OBSERVABILITY_STORE_COMPONENTS[@]}") ;;
    cell-identity) HARNESS_COMPONENTS+=("${CELL_IDENTITY_HARNESS[@]}") ;;
    argocd-agent) HARNESS_COMPONENTS+=("${ARGOCD_AGENT_HARNESS[@]}") ;;
    mesh-view) HARNESS_COMPONENTS+=("${MESH_VIEW_HARNESS[@]}") ;;
    otel-uplink | telemetry-uplink) HARNESS_COMPONENTS+=("${OTEL_UPLINK_HARNESS[@]}") ;;
    envd) HARNESS_COMPONENTS+=("${ENVD_HARNESS[@]}") ;;
    mgmt-plane) LINK_COMPONENTS+=("${MGMT_PLANE_LINK[@]}") ;;
    central-view) LINK_COMPONENTS+=("${CENTRAL_VIEW_LINK[@]}") ;;
    telemetry-gateway) LINK_COMPONENTS+=("${TELEMETRY_GATEWAY_LINK[@]}") ;;
    mesh-view-hub) LINK_COMPONENTS+=("${MESH_VIEW_HUB_LINK[@]}") ;;
    *) die "unknown component set '$set_name' for cell $CELL in harness/topology.yaml" ;;
  esac
done

# The bootstrap set. Bootstrap applies these bundles once, before Argo CD takes over.
BOOTSTRAP=(namespaces argocd cell-system)

BUNDLE_STORE_HOST="bundle-store.cell-system.svc.cluster.local:5000"

k() { kubectl --context "kind-$CELL_NAME" "$@"; }

# wait_for <description> <timeout seconds> <command...>
wait_for() {
  local what="$1" timeout="$2"; shift 2
  local end=$((SECONDS + timeout))
  until "$@" >/dev/null 2>&1; do
    ((SECONDS < end)) || die "timed out after ${timeout}s: $what"
    sleep 5
  done
}

# Start a port-forward to the bundle store. Sets BUNDLE_BUNDLE_STORE_PF_PID.
bundle_store_forward() {
  if curl -fsS "http://127.0.0.1:${CELL_BUNDLE_STORE_PORT}/v2/" >/dev/null 2>&1; then
    die "port ${CELL_BUNDLE_STORE_PORT} already serves a bundle store, probably from an old port-forward. Find its process with: lsof -nP -iTCP:${CELL_BUNDLE_STORE_PORT} -sTCP:LISTEN. Stop that process, then run the command again."
  fi
  # Call kubectl directly, not through k, so $! is the kubectl process that the trap kills.
  kubectl --context "kind-$CELL_NAME" -n cell-system port-forward svc/bundle-store "${CELL_BUNDLE_STORE_PORT}:5000" \
    >/dev/null 2>&1 &
  BUNDLE_STORE_PF_PID=$!
  trap 'kill "$BUNDLE_STORE_PF_PID" 2>/dev/null || true' EXIT
  wait_for "port-forward to the bundle store" 30 curl -fsS "http://127.0.0.1:${CELL_BUNDLE_STORE_PORT}/v2/"
}

source "$ROOT/scripts/gate-traces.sh"

# load_local_settings reads the gitignored .envrc.local when one of the given variables is unset.
# direnv loads the file after direnv allow, so this matters only without direnv. POC_ENVRC_LOCAL
# names another file, for the tests.
load_local_settings() {
  local file="${POC_ENVRC_LOCAL:-$ROOT/.envrc.local}" name
  for name in "$@"; do
    if [[ -z "${!name:-}" ]]; then
      [[ -f "$file" ]] || return 0
      # shellcheck source=/dev/null
      source "$file"
      log "read the settings from $file"
      return 0
    fi
  done
}

# SECRET_STORE is the name of the SecretStore that secrets:connect applies in each namespace of
# SECRET_STORE_NAMESPACES.
SECRET_STORE=poc-secrets

# store_gaps prints one line for each namespace of SECRET_STORE_NAMESPACES whose SecretStore is not
# Ready, and for each missing target Secret of an ExternalSecret that uses the store. It prints
# nothing when secrets:connect has nothing to do.
store_gaps() {
  local ns list target
  for ns in ${SECRET_STORE_NAMESPACES:-}; do
    k -n "$ns" get secretstore "$SECRET_STORE" -o json 2>/dev/null \
      | jq -e 'any(.status.conditions[]?; .type == "Ready" and .status == "True")' >/dev/null 2>&1 \
      || echo "SecretStore $ns/$SECRET_STORE is not Ready"
    list="$(k -n "$ns" get externalsecrets.external-secrets.io -o json 2>/dev/null)" || continue
    for target in $(jq -r --arg store "$SECRET_STORE" '.items[]
        | select(.spec.secretStoreRef.kind == "SecretStore" and .spec.secretStoreRef.name == $store)
        | .spec.target.name // .metadata.name' <<<"$list"); do
      k -n "$ns" get secret "$target" >/dev/null 2>&1 || echo "Secret $ns/$target is missing"
    done
  done
}

# lgtm_curl <user:password> <method> <path> [json body] sends one request to Grafana from inside the
# lgtm pod of $LGTM_CLUSTER (default $CELL_NAME), where Grafana listens on 127.0.0.1:3000. It prints the response body, then
# a last line with the HTTP status code. The credentials and the body go into a curl config on the
# standard input of curl, so no password reaches an argument list, and no file holds it. Pass the
# password in a variable of the caller, not on a command line of this Mac either.
lgtm_curl() {
  local creds="$1" method="$2" path="$3" body="${4:-}" esc
  # The credentials go into a curl config, where a quote or a newline would add a directive.
  [[ "$creds" =~ ^[A-Za-z0-9]+:[A-Za-z0-9]+$ ]] || { echo "lgtm_curl: the credentials are not user:password with letters and digits" >&2; return 1; }
  {
    printf 'user = "%s"\n' "$creds"
    printf 'request = "%s"\n' "$method"
    printf 'url = "http://127.0.0.1:3000%s"\n' "$path"
    if [[ -n "$body" ]]; then
      esc="${body//\\/\\\\}"; esc="${esc//\"/\\\"}"
      printf 'header = "Content-Type: application/json"\n'
      printf 'data = "%s"\n' "$esc"
    fi
    printf 'silent\nshow-error\nmax-time = 30\nwrite-out = "\\n%%{http_code}"\n'
  } | kubectl --context "kind-${LGTM_CLUSTER:-$CELL_NAME}" -n observability-system exec -i lgtm-0 -c lgtm -- curl -K -
}

# live_image_mismatches <cluster> <namespace> <kind/name> prints one line for each local image of the
# workload that differs from build/images.env, and prints nothing when all match.
live_image_mismatches() {
  local cluster="$1" ns="$2" workload="$3" json images image name want
  json="$(kubectl --context "kind-$cluster" -n "$ns" get "$workload" -o json)" || return 1
  images="$(jq -r '.spec.template.spec | ((.initContainers // []) + .containers)[].image | select(startswith("localhost:5001/"))' <<<"$json")" || return 1
  for image in $images; do
    name="${image#localhost:5001/}"
    name="${name%%@*}"
    want="$(sed -n "s/^IMAGE_$(tr 'a-z-' 'A-Z_' <<<"$name")=//p" "$BUILD_ROOT/images.env" 2>/dev/null)"
    [[ -n "$want" && "$image" == "$want" ]] || echo "$workload in $cluster runs $image, and build/images.env has '${want:-nothing}' for $name"
  done
}

# applications_json <kubectl command...> prints the Applications of argocd as one object: root (the
# Application root), children (every other Application) and items (all of them). The kubectl
# command is the part before -n, for example: applications_json k. Its errors reach standard error.
applications_json() {
  "$@" -n argocd get applications -o json \
    | jq '{root: [.items[] | select(.metadata.name == "root")], children: [.items[] | select(.metadata.name != "root")], items}'
}

# apps_json prints the Applications of the cluster CELL_NAME as a list: {items: [...]}.
apps_json() {
  applications_json k | jq '{items}'
}

# apps_match_published reads the object of applications_json and the published digests as JSON from
# standard input, one document after the other. It succeeds when argocd holds the root and exactly the
# published components, and each Application is Synced and Healthy at its digest.
apps_match_published() {
  jq -s -e '.[0] as $a | .[1] as $pub
    | ($a.root | map(.metadata.name)) == ["root"]
      and ($a.children | map(.metadata.name) | sort) == ($pub | del(.root) | keys | sort)
      and all($a.root[], $a.children[]; .status.sync.status == "Synced" and .status.health.status == "Healthy"
        and ((.status.sync.revision // "") != "") and .status.sync.revision == $pub[.metadata.name])' >/dev/null
}

# apps_at_published succeeds when Argo CD reports every Application of the cluster Synced and
# Healthy at the revision that publish.sh pushed. A check that runs before Argo CD reads the new
# root bundle cannot pass.
apps_at_published() {
  local published_json apps
  published_json="$(jq -Rn '[inputs | select(length > 0) | split("=") | {(.[0]): .[1]}] | add' <"$PUBLISHED")" || return 1
  apps="$(applications_json k)" || return 1
  printf '%s\n%s\n' "$apps" "$published_json" | apps_match_published
}

# apps_blockers prints one line for each reason that apps_at_published fails.
apps_blockers() {
  local published_json apps
  published_json="$(jq -Rn '[inputs | select(length > 0) | split("=") | {(.[0]): .[1]}] | add' <"$PUBLISHED")" || return 1
  apps="$(applications_json k)" || return 1
  printf '%s\n%s\n' "$apps" "$published_json" | jq -s -r '.[0] as $a | .[1] as $pub
    | (($pub | del(.root) | keys) - ($a.children | map(.metadata.name))) as $missing
    | (($a.children | map(.metadata.name)) - ($pub | del(.root) | keys)) as $unknown
    | (if ($a.root | length) == 0 then "argocd has no root Application" else empty end),
      (if ($missing | length) > 0 then "argocd lacks \($missing | join(", "))" else empty end),
      (if ($unknown | length) > 0 then "argocd holds Applications that were not published: \($unknown | join(", "))" else empty end),
      ($a.items[] | select(.status.sync.status != "Synced" or .status.health.status != "Healthy"
          or .status.sync.revision != $pub[.metadata.name])
        | "\(.metadata.namespace)/\(.metadata.name) is \(.status.sync.status // "unknown")/\(.status.health.status // "unknown") at \(.status.sync.revision // "no revision"), published \($pub[.metadata.name] // "nothing")")'
}

# check_apps_namespace succeeds when every Application lives in argocd, and argocd has the root
# Application. In a cluster with VIEW_CELLS, the principal of the central view also mirrors the
# Applications of each cell into its agent namespace <POC_ENV>-<cell>.
check_apps_namespace() {
  local found cell mirrors=()
  for cell in ${VIEW_CELLS:-}; do mirrors+=("$POC_ENV-$cell"); done
  found="$(k get applications -A -o json | jq -r --argjson mirrors "$(printf '%s\n' ${mirrors[@]+"${mirrors[@]}"} | jq -Rcn '[inputs | select(length > 0)]')" '.items[]
    | select(.metadata.namespace == "argocd" or (.metadata.namespace as $ns | $mirrors | index($ns)) != null | not)
    | "\(.metadata.namespace)/\(.metadata.name)"')" || return 1
  [[ -z "$found" ]] || {
    echo "Applications outside argocd: ${found//$'\n'/ }. Run: CELL=$CELL_NAME mise run cell:up. If one stays, list them with kubectl --context kind-$CELL_NAME get applications -A, then delete it with kubectl --context kind-$CELL_NAME -n <namespace> delete application <name>"
    return 1
  }
  k -n argocd get application root >/dev/null 2>&1 || { echo "argocd has no root Application. Run: CELL=$CELL_NAME mise run cell:up"; return 1; }
}

# check_argocd_projects succeeds when argocd holds exactly the AppProjects cell and default, and
# default allows no source, no destination and no kind. The server of argocd admin dashboard
# creates a permissive default when none exists.
check_argocd_projects() {
  local json
  json="$(k -n argocd get appprojects -o json)" || return 1
  jq -e '(.items | map(.metadata.name) | sort) == ["cell", "default"]' >/dev/null <<<"$json" \
    || { echo "AppProjects in argocd: $(jq -r '[.items[].metadata.name] | join(" ")' <<<"$json"), want cell and default. Run: CELL=$CELL_NAME mise run cell:ui:clean"; return 1; }
  jq -e '.items[] | select(.metadata.name == "default") | .spec
    | ((.sourceRepos // []) | length) == 0 and ((.destinations // []) | length) == 0
      and ((.clusterResourceWhitelist // []) | length) == 0 and ((.namespaceResourceWhitelist // []) | length) == 0' >/dev/null <<<"$json" \
    || { echo "AppProject default allows a source, a destination or a kind. Run: CELL=$CELL_NAME mise run cell:up, then CELL=$CELL_NAME mise run cell:ui:clean"; return 1; }
}

# check_no_admin_credentials succeeds when argocd holds no admin password. The server of argocd admin
# dashboard writes one when admin.enabled is not false.
check_no_admin_credentials() {
  local secret
  if k -n argocd get secret argocd-initial-admin-secret >/dev/null 2>&1; then
    echo "argocd holds the Secret argocd-initial-admin-secret. Run: CELL=$CELL_NAME mise run cell:ui:clean"
    return 1
  fi
  secret="$(k -n argocd get secret argocd-secret -o json)" || return 1
  jq -e '(.data // {}) | has("admin.password") or has("admin.passwordMtime") | not' >/dev/null <<<"$secret" \
    || { echo "argocd-secret holds admin.password. Run: CELL=$CELL_NAME mise run cell:ui:clean"; return 1; }
}

# ARGOCD_SECRETS is the closed set of Secrets that argocd may hold. components/argocd/guards.yaml
# enforces the same set at admission.
ARGOCD_SECRETS=(argocd-redis argocd-secret bundle-store)

# check_argocd_secrets succeeds when every Secret in argocd is in ARGOCD_SECRETS, the Argo CD Agent
# cannot get a Secret there, and the policy and the binding that keep the set closed exist with
# their effect.
check_argocd_secrets() {
  local secrets name verb extra=() allowed policy
  secrets="$(k -n argocd get secrets -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}')" || return 1
  for name in $secrets; do
    [[ " ${ARGOCD_SECRETS[*]} " == *" $name "* ]] || extra+=("$name")
  done
  ((${#extra[@]} == 0)) || { echo "argocd holds Secrets outside the allowed set (${ARGOCD_SECRETS[*]}): ${extra[*]}"; return 1; }
  for verb in get create update patch delete; do
    allowed="$(k auth can-i "$verb" secrets -n argocd --as=system:serviceaccount:argocd:argocd-agent)" || true
    [[ "$allowed" == no ]] || { echo "the ServiceAccount argocd-agent can $verb Secrets in argocd (can-i says '$allowed')"; return 1; }
  done
  policy="$(printf '%s\n' "${ARGOCD_SECRETS[@]}" | jq -Rcn '[inputs]')"
  k get validatingadmissionpolicy argocd-secrets-allowed -o json | jq -e --argjson names "$policy" '
    .spec.failurePolicy == "Fail" and (.spec.validations | length) == 1
      and .spec.validations[0].expression == "object.metadata.name in [\($names | map("\u0027" + . + "\u0027") | join(", "))]"
      and (.spec.matchConstraints.resourceRules | length) == 1
      and .spec.matchConstraints.resourceRules[0].operations == ["CREATE", "UPDATE"]' >/dev/null \
    || { echo "ValidatingAdmissionPolicy argocd-secrets-allowed is missing, or it does not allow exactly ${ARGOCD_SECRETS[*]}"; return 1; }
  k get validatingadmissionpolicybinding argocd-secrets-allowed -o json | jq -e '
    .spec.policyName == "argocd-secrets-allowed" and .spec.validationActions == ["Deny"]
      and .spec.matchResources.namespaceSelector.matchLabels["kubernetes.io/metadata.name"] == "argocd"' >/dev/null \
    || { echo "ValidatingAdmissionPolicyBinding argocd-secrets-allowed is missing or does not deny in argocd"; return 1; }
}

# GUARD_TEST_LABEL marks each object that gate:m3 makes, and GUARD_TEST_GROUP is the group that the
# temporary Role of the guard test binds. The test impersonates the agent ServiceAccount with that
# group, so the real agent never holds the grant.
GUARD_TEST_LABEL=poc.internal/test
GUARD_TEST_GROUP=poc:guard-test

# check_agent_unmanaged succeeds when the ServiceAccount argocd-agent has no annotation or label that
# makes Argo CD count it as managed, and no owner reference. The agent resource proxy of the view
# forwards a POST to a subresource of a managed object, and the guard admits one such POST: the
# bound token request of the agent itself. Only this check of "managed" keeps the view away from it.
check_agent_unmanaged() {
  local sa key found
  sa="$(k -n argocd get serviceaccount argocd-agent -o json)" || { echo "no ServiceAccount argocd-agent in argocd"; return 1; }
  key="$(k -n argocd get configmap argocd-cm -o jsonpath='{.data.application\.instanceLabelKey}' 2>/dev/null)" || key=""
  key="${key:-app.kubernetes.io/instance}"
  found="$(jq -r --arg key "$key" '[
      (if (.metadata.annotations // {}) | has("argocd.argoproj.io/tracking-id") then "the annotation argocd.argoproj.io/tracking-id" else empty end),
      (if (.metadata.labels // {}) | has($key) then "the label \($key)" else empty end),
      (if ((.metadata.ownerReferences // []) | length) > 0 then "an owner reference" else empty end)] | join(", ")' <<<"$sa")" || return 1
  [[ -z "$found" ]] && return 0
  echo "the ServiceAccount argocd-agent has $found, so Argo CD counts it as managed and the resource proxy of the view can reach its token subresource"
  return 1
}

# check_agent_grants succeeds when no object has the label GUARD_TEST_LABEL, and no RoleBinding or
# ClusterRoleBinding that grants the ServiceAccount argocd-agent, or the group GUARD_TEST_GROUP,
# lacks the harness label of argocd-agent. check_harness_objects compares each labelled binding with
# the render.
check_agent_grants() {
  local left extra
  left="$(k get roles,rolebindings,clusterroles,clusterrolebindings,namespaces,serviceaccounts -A -l "$GUARD_TEST_LABEL" -o json \
    | jq -r '.items[] | "\(.kind) \(.metadata.namespace // "-")/\(.metadata.name)"')" || { echo "could not list the objects with the label $GUARD_TEST_LABEL"; return 1; }
  extra="$(k get rolebindings,clusterrolebindings -A -o json | jq -r --arg label "$HARNESS_LABEL" --arg group "$GUARD_TEST_GROUP" '.items[]
    | select(any(.subjects[]?; (.kind == "ServiceAccount" and .name == "argocd-agent" and .namespace == "argocd") or (.kind == "Group" and .name == $group)))
    | select((.metadata.labels[$label] // "") != "argocd-agent")
    | "\(.kind) \(.metadata.namespace // "-")/\(.metadata.name)"')" || { echo "could not list the bindings"; return 1; }
  if [[ -n "$left" || -n "$extra" ]]; then
    [[ -z "$left" ]] || printf 'objects of a gate run: %s\n' "$(tr '\n' ',' <<<"$left")"
    [[ -z "$extra" ]] || printf 'bindings for the agent ServiceAccount or the test group that the render does not hold: %s\n' "$(tr '\n' ',' <<<"$extra")"
    echo "Run: mise run gate:m3:repair"
    return 1
  fi
}

# The relay copies the node address of RELAY_TARGET into its routes and its egress policy, and the
# node addresses of SPIRE_AGENT_CELLS into its ingress policy. Docker can give a rebuilt node a new
# address, and the relay then sends the streams of the cells to the wrong node.
# check_relay_current needs the function node_ip <cluster>, which verify.sh defines.
check_relay_current() {
  local target cell ip name json hosts cidrs want_cells stale=() cell_cidrs=()
  target="$(node_ip "$RELAY_TARGET")" || { echo "$target"; echo "Run: CELL=$CELL_NAME mise run cell:up"; return 1; }
  for cell in $SPIRE_AGENT_CELLS; do
    ip="$(node_ip "$cell")" || { echo "$ip"; echo "Run: CELL=$CELL_NAME mise run cell:up"; return 1; }
    cell_cidrs+=("$ip/32")
  done
  want_cells="$(printf '%s\n' "${cell_cidrs[@]}" | jq -Rrs 'split("\n") | map(select(length > 0)) | sort | join(" ")')"
  for name in relay-view relay-telemetry relay-bind; do
    json="$(k -n relay-system get deployment "$name" -o json)" || { echo "cannot read Deployment relay-system/$name"; echo "Run: CELL=$CELL_NAME mise run cell:up"; return 1; }
    hosts="$(jq -r '.spec.template.spec.containers[0].args as $a | [range(0; $a | length) | select($a[.] == "--route") | $a[. + 1] | split("=")[1] | split(":")[0]] | unique | join(" ")' <<<"$json")"
    [[ "$hosts" == "$target" ]] || stale+=("$name routes to '$hosts', but the node of $RELAY_TARGET is $target")
    json="$(k -n relay-system get networkpolicy "$name" -o json)" || { echo "cannot read NetworkPolicy relay-system/$name"; echo "Run: CELL=$CELL_NAME mise run cell:up"; return 1; }
    cidrs="$(jq -r '[.spec.egress[0].to[].ipBlock.cidr] | sort | join(" ")' <<<"$json")"
    [[ "$cidrs" == "$target/32" ]] || stale+=("the egress policy of $name admits '$cidrs', but the node of $RELAY_TARGET is $target/32")
    cidrs="$(jq -r '[.spec.ingress[0].from[].ipBlock.cidr] | sort | join(" ")' <<<"$json")"
    [[ "$cidrs" == "$want_cells" ]] || stale+=("the ingress policy of $name admits '$cidrs', but the nodes of $SPIRE_AGENT_CELLS are '$want_cells'")
  done
  if ((${#stale[@]} > 0)); then
    printf '%s\n' "${stale[@]}"
    echo "Run: CELL=$CELL_NAME mise run cell:up"
    return 1
  fi
}

# clean_dashboard_leftovers removes what the server of argocd admin dashboard wrote into argocd:
# the initial admin Secret, and the admin keys and the signing key of argocd-secret.
clean_dashboard_leftovers() {
  local keys key patch=()
  k -n argocd delete secret argocd-initial-admin-secret --ignore-not-found >/dev/null || return 1
  keys="$(k -n argocd get secret argocd-secret -o json 2>/dev/null | jq -r '(.data // {}) | keys[]
    | select(. == "admin.password" or . == "admin.passwordMtime" or . == "server.secretkey")')" || return 1
  for key in $keys; do
    patch+=("{\"op\":\"remove\",\"path\":\"/data/$key\"}")
  done
  if ((${#patch[@]} > 0)); then
    k -n argocd patch secret argocd-secret --type=json -p "[$(IFS=,; echo "${patch[*]}")]" >/dev/null || return 1
    log "removed ${keys//$'\n'/, } from argocd-secret"
  fi
}

# eso_controller_rolled_out succeeds when the operator Deployment runs only pods of its current
# spec, and that spec scopes the controller to the store namespace. Until then a controller of an
# older bundle, which ignores SecretStore objects, can still serve.
eso_controller_rolled_out() {
  local store_ns
  read -r store_ns _ <<<"${SECRET_STORE_NAMESPACES:-}"
  [[ -n "$store_ns" ]] || return 1
  k -n external-secrets get deployment external-secrets -o json 2>/dev/null | jq -e --arg arg "--namespace=$store_ns" '
    (.spec.replicas // 1) as $want
    | (.status.observedGeneration // 0) == .metadata.generation
      and (.status.replicas // 0) == $want and (.status.updatedReplicas // 0) == $want
      and (.status.availableReplicas // 0) == $want
      and any(.spec.template.spec.containers[].args[]?; . == $arg)' >/dev/null
}

# eso_published_synced succeeds when Argo CD reports the Application external-secrets Synced and
# Healthy at the digest that the last cell:publish recorded in build/<cluster>/published.env.
eso_published_synced() {
  local want
  want="$(sed -n 's/^external-secrets=//p' "$PUBLISHED" 2>/dev/null)"
  [[ -n "$want" ]] || return 1
  k -n argocd get application external-secrets -o json 2>/dev/null | jq -e --arg want "$want" '
    .status.sync.status == "Synced" and .status.health.status == "Healthy" and .status.sync.revision == $want' >/dev/null
}

# connect_store_step <secrets:connect script> waits until the published operator bundle is synced
# and its scoped controller has rolled out. Then it runs secrets:connect once when the secret store
# has a gap and POC_SECRET_TOKEN_CMD is set. Without that setting, it asks for secrets:connect in a
# second shell, once a minute. It sets store_done when the store has no gap.
connect_store_step() {
  local gaps
  eso_published_synced && eso_controller_rolled_out || return 0
  gaps="$(store_gaps)"
  if [[ -z "$gaps" ]]; then
    store_done=1
    log "the secret store of $CELL_NAME is connected"
    return 0
  fi
  if [[ -n "${POC_SECRET_TOKEN_CMD:-}" ]]; then
    log "running secrets:connect, because: ${gaps//$'\n'/; }"
    "$1" || die "secrets:connect failed. Fix the cause, then run: CELL=$CELL_NAME mise run secrets:connect"
    store_done=1
  elif ((SECONDS - last_hint >= 60)); then
    log "${gaps//$'\n'/; }. Run in a second shell: CELL=$CELL_NAME mise run secrets:connect"
    last_hint=$SECONDS
  fi
}

# Harness and link objects carry this label, with the name of their component as the value.
HARNESS_LABEL=cell.poc.internal/harness

# fix_command <component> prints the command that renders and applies a component again: cell:link
# for a link component, cell:up for every other one.
fix_command() {
  local entry
  for entry in ${LINK_COMPONENTS[@]+"${LINK_COMPONENTS[@]}"}; do
    [[ "${entry%%:*}" == "$1" ]] && { echo "CELL=$CELL_NAME mise run cell:link"; return; }
  done
  echo "CELL=$CELL_NAME mise run cell:up"
}

# link_entries prints the link components that the link phase handles, one <component>:<namespace>
# entry on each line: every entry of LINK_COMPONENTS, or only the one that LINK_ONLY names. An unknown
# name stops the caller with the known names. The output of die ends only a command substitution, so
# call it as: entries="$(link_entries)" || exit 1
link_entries() {
  local entry
  if [[ -z "${LINK_ONLY:-}" ]]; then
    printf '%s\n' ${LINK_COMPONENTS[@]+"${LINK_COMPONENTS[@]}"}
    return
  fi
  for entry in ${LINK_COMPONENTS[@]+"${LINK_COMPONENTS[@]}"}; do
    [[ "${entry%%:*}" == "$LINK_ONLY" ]] && { echo "$entry"; return; }
  done
  die "LINK_ONLY '$LINK_ONLY' is not a link component of $CELL_NAME. Known: $(printf '%s ' ${LINK_COMPONENTS[@]+"${LINK_COMPONENTS[@]%%:*}"})"
}

# link_preflight prints one line for each cluster that the link phase of $CELL needs and that does
# not answer: the environment control plane VIEW_CONTROL_PLANE with its SPIRE server, and each cell
# of VIEW_CELLS. It prints nothing when the link phase can run, or when the cluster has none.
link_preflight() {
  local c
  ((${#LINK_COMPONENTS[@]} > 0)) || return 0
  # mgmt-api reads the other clusters only when they exist, so it runs before them.
  [[ "${LINK_ONLY:-}" != mgmt-api ]] || return 0
  for c in ${VIEW_CONTROL_PLANE:-} ${VIEW_CELLS:-}; do
    if ! (cd "$ROOT" && mise run hostsvc -- facts --cluster "$c" >/dev/null 2>&1); then
      echo "cluster $c does not exist. Create it: CELL=$c mise run cell:up"
    elif [[ "$c" == "${VIEW_CONTROL_PLANE:-}" ]] \
      && ! kubectl --context "kind-$c" -n spire-system get pod spire-server-0 -o jsonpath='{.status.phase}' 2>/dev/null | grep -qx Running; then
      echo "the SPIRE server of $c does not run. Run: CELL=$c mise run cell:up"
    fi
  done
}

# blackhole_present <node container> prints each firewall rule that TestM3KeepaliveBlackhole put in the FORWARD
# chain of the dev-cp node, as arguments for iptables -D. The test tags every rule with a comment that starts
# with gate-m3-blackhole-, so the match needs no address. It fails when the node does not answer.
blackhole_present() {
  local rules
  rules="$(docker exec "$1" iptables -S FORWARD)" || return 1
  grep -- '--comment "\{0,1\}gate-m3-blackhole-' <<<"$rules" | sed 's/^-A /-D /' || true
}

# hub_cell_up <cell> reads the log of the hub on standard input and succeeds when the hub holds an open
# tunnel of the cell. A tunnel is open when its tunnel_up line has no tunnel_down line with the same
# conn_id. The test works on conn_id, because the new tunnel of a cell can log tunnel_up before the older
# one logs tunnel_down with replaced true.
hub_cell_up() {
  CELL_ARG="$1" jq -Rn '[inputs | fromjson? | select(.cell == env.CELL_ARG and (.msg == "tunnel_up" or .msg == "tunnel_down"))]
    | ([.[] | select(.msg == "tunnel_up") | .conn_id] - [.[] | select(.msg == "tunnel_down") | .conn_id]) | length > 0' \
    | grep -qx true
}

# hub_status prints the tunnel state that the hub process serves, one JSON object. It fails when the pod does
# not answer, and the caller then reads the log of the hub.
hub_status() {
  k --request-timeout=20s -n mesh-view-system exec deploy/mesh-view-hub -c cell-proxy -- /ko-app/cell-proxy tunnel-status 2>/dev/null
}

# hub_cell_state <cell> succeeds when the tunnel of the cell is up. It reads the state of the hub process
# (hub_status), and falls back to the log of the hub (hub_cell_up) when the process does not answer.
hub_cell_state() {
  local status
  if status="$(hub_status)" && [[ -n "$status" ]]; then
    CELL_ARG="$1" jq -e '.cells[env.CELL_ARG].up == true' <<<"$status" >/dev/null
    return
  fi
  k --request-timeout=20s -n mesh-view-system logs deploy/mesh-view-hub -c cell-proxy 2>/dev/null | hub_cell_up "$1"
}

# new_ready_pods <namespace> <selector> <old UIDs> prints the UIDs of the Ready pods that are not old.
new_ready_pods() {
  k -n "$1" get pods -l "$2" -o json | jq -r --arg old " $3 " '
    [.items[] | .metadata.uid as $uid | select(($old | contains(" " + $uid + " ")) | not)
      | select(any(.status.conditions[]?; .type == "Ready" and .status == "True")) | .metadata.uid] | join(" ")'
}

# restart_deployment_pods <namespace> <deployment> deletes the pods of a Deployment and waits for a
# new Ready pod. It changes no field of the Deployment, so its field managers stay the same.
restart_deployment_pods() {
  local ns="$1" name="$2" selector old uids end
  selector="$(k -n "$ns" get deployment "$name" -o json | jq -r '.spec.selector.matchLabels | to_entries | map("\(.key)=\(.value)") | join(",")')"
  [[ -n "$selector" ]] || die "deployment/$name in $ns has no label selector"
  old="$(k -n "$ns" get pods -l "$selector" -o jsonpath='{.items[*].metadata.uid}')"
  k -n "$ns" delete pods -l "$selector" --wait=true --timeout=120s >/dev/null || die "could not delete the pods of deployment/$name in $ns"
  end=$((SECONDS + 300))
  until uids="$(new_ready_pods "$ns" "$selector" "$old")" && [[ -n "$uids" ]]; do
    if ((SECONDS >= end)); then
      log "read the events: mise x -- kubectl --context kind-$CELL_NAME -n $ns describe deployment/$name"
      die "deployment/$name in $ns has no new Ready pod after 300s"
    fi
    sleep 2
  done
}

# harness_workloads <component> <namespace> prints the Deployments and StatefulSets of a harness
# component, as <kind>.apps/<name>. Other workloads in the namespace belong to a bundle. The live
# workloads with the harness label must be exactly the ones that the bundle of the component
# renders in the namespace, so a lost label or a failed API call stops the caller. The output of
# die ends only a command substitution, so call it as: list="$(harness_workloads c ns)" || exit 1
harness_workloads() {
  local comp="$1" ns="$2" bundle="$BUNDLES/$1/manifests.yaml" live want
  [[ -f "$bundle" ]] || die "no $bundle. Run: $(fix_command "$comp")"
  live="$(k -n "$ns" get deployments,statefulsets -l "$HARNESS_LABEL=$comp" -o name)" \
    || die "could not list the Deployments and StatefulSets of $comp in $ns"
  live="$(sed '/^$/d' <<<"$live" | sort)"
  want="$(NS="$ns" yq -N 'select((.kind == "Deployment" or .kind == "StatefulSet") and .metadata.namespace == strenv(NS))
    | (.kind | downcase) + ".apps/" + .metadata.name' "$bundle" | sed '/^$/d' | sort)"
  [[ "$live" == "$want" ]] || die "$ns holds the workloads '${live//$'\n'/ }' with the label $HARNESS_LABEL=$comp, and the bundle $comp renders '${want//$'\n'/ }'. Run: $(fix_command "$comp")"
  printf '%s\n' "$live"
}

# harness_rollout_wait <component> <namespace> waits for the rollout of each Deployment and
# StatefulSet of a harness component.
harness_rollout_wait() {
  local workload workloads
  workloads="$(harness_workloads "$1" "$2")" || exit 1
  for workload in $workloads; do
    if ! k -n "$2" rollout status "$workload" --timeout=300s >/dev/null; then
      log "read the events: mise x -- kubectl --context kind-$CELL_NAME -n $2 describe $workload"
      log "read the logs: mise x -- kubectl --context kind-$CELL_NAME -n $2 logs $workload --all-containers"
      die "$workload in $2 did not finish its rollout in 300s"
    fi
  done
}

apply_bundle() {
  local file="$BUNDLES/$1/manifests.yaml"
  if ! k apply --server-side --force-conflicts -f "$file" >/dev/null 2>&1; then
    # A bundle can hold a CRD and an object of that kind. The first apply fails for that object.
    # Wait for the CRD, then apply again. The second apply shows any real error.
    k wait --for=condition=Established crd --all --timeout=120s >/dev/null
    k apply --server-side --force-conflicts -f "$file" >/dev/null
  fi
  log "applied bundle $1"
}

# release_from_argocd <bundle> removes what Argo CD left on the objects of a bundle that an Argo CD
# Application managed before: the tracking annotation and the argocd-controller field manager.
# The harness apply then owns every field. Objects without these leftovers stay unchanged.
# harness_conflicts runs first, so a tracking annotation here names an Application that the
# current root no longer holds.
release_from_argocd() {
  local obj kind name ns live patch scope
  while read -r obj; do
    kind="$(jq -r .kind <<<"$obj")" name="$(jq -r .name <<<"$obj")" ns="$(jq -r .ns <<<"$obj")"
    scope=()
    [[ -n "$ns" ]] && scope=(-n "$ns")
    live="$(k "${scope[@]}" get "$kind/$name" -o json --show-managed-fields 2>/dev/null)" || continue
    if jq -e '.metadata.annotations["argocd.argoproj.io/tracking-id"] != null' <<<"$live" >/dev/null; then
      k "${scope[@]}" annotate "$kind/$name" argocd.argoproj.io/tracking-id- >/dev/null
      log "removed the Argo CD tracking annotation from $kind/$name"
    fi
    if jq -e 'any(.metadata.managedFields[]?; .manager == "argocd-controller")' <<<"$live" >/dev/null; then
      patch="$(jq -c '[{op: "replace", path: "/metadata/managedFields",
        value: [.metadata.managedFields[] | select(.manager != "argocd-controller")]}]' <<<"$live")"
      k "${scope[@]}" patch "$kind/$name" --type=json -p "$patch" >/dev/null
      log "removed the argocd-controller field manager from $kind/$name"
    fi
  done < <(yq -o=json -I=0 'select(.kind != null) | {"kind": .kind, "name": .metadata.name, "ns": (.metadata.namespace // "")}' "$1")
}

# harness_conflicts <component> prints one line for each live object of the bundle of a harness
# component that another owner holds: an Argo CD Application of the current root, another harness
# or link component, or an owner reference. It prints nothing when the harness may apply the bundle.
harness_conflicts() {
  local comp="$1" bundle="$BUNDLES/$1/manifests.yaml" live apps
  [[ -f "$bundle" ]] || { echo "no $bundle. Run: $(fix_command "$comp")"; return 1; }
  live="$(k get -f "$bundle" -o json --ignore-not-found)" || { echo "could not read the live objects of the bundle $comp"; return 1; }
  apps="$(printf '%s\n' root ${COMPONENTS[@]+"${COMPONENTS[@]%%:*}"} | jq -Rn '[inputs]')"
  jq -r --arg comp "$comp" --arg label "$HARNESS_LABEL" --argjson apps "$apps" '
    (if .kind == "List" then .items[] else . end)
    | ((.metadata.annotations["argocd.argoproj.io/tracking-id"] // "") | split(":")[0]) as $app
    | (.metadata.labels[$label] // "") as $owner
    | ([(.metadata.ownerReferences // [])[] | "\(.kind)/\(.name)"] | join(", ")) as $refs
    | "\(.kind)/\(.metadata.name)\(if .metadata.namespace then " in " + .metadata.namespace else "" end)" as $o
    | if $app != "" and ($apps | index($app)) != null then "\($o) belongs to the Argo CD Application \($app)"
      elif $owner != "" and $owner != $comp then "\($o) carries the label \($label)=\($owner)"
      elif $refs != "" then "\($o) has the owner \($refs)"
      else empty end' <<<"$live"
}

# harness_apply <component> applies the bundle of a harness component. It stops before the apply
# when another owner holds one of its objects, because a server-side apply with force would take
# that object, and its owner would then take it back on each sync.
harness_apply() {
  local conflicts
  conflicts="$(harness_conflicts "$1")" || die "$conflicts"
  [[ -z "$conflicts" ]] || die "the harness component $1 renders objects that another owner holds:"$'\n'"$conflicts"$'\n'"Rename the object in the harness render or remove it from the other owner, so that one owner holds it. Then run: $(fix_command "$1")"
  apply_bundle "$1"
  release_from_argocd "$BUNDLES/$1/manifests.yaml"
}

# has_component_entry <component> <namespace> succeeds when the cluster has that harness or link
# component in that namespace.
has_component_entry() {
  local entry
  for entry in ${HARNESS_COMPONENTS[@]+"${HARNESS_COMPONENTS[@]}"} ${LINK_COMPONENTS[@]+"${LINK_COMPONENTS[@]}"}; do
    [[ "$entry" == "$1:$2" ]] && return 0
  done
  return 1
}

# check_plane_pods checks each pod that runs as a ServiceAccount of SPIRE_LOCAL_WORKLOADS. k8s_psat
# gives such a pod the plane SVID, and a pod label is not an identity. So the pod must carry the
# harness label of a harness or link component in its namespace, and its controller (through its
# ReplicaSet) must be a Deployment or StatefulSet that the bundle of that component renders there.
check_plane_pods() {
  local w sub ns sa pods sets pod comp kind name problems=()
  for w in ${SPIRE_LOCAL_WORKLOADS:-}; do
    sub="${w#*=}" ns="${sub%%/*}" sa="${sub#*/}"
    pods="$(k -n "$ns" get pods -o json 2>/dev/null)" || pods='{"items":[]}'
    sets="$(k -n "$ns" get replicasets -o json 2>/dev/null)" || sets='{"items":[]}'
    while IFS='|' read -r pod comp kind name; do
      [[ -n "$pod" ]] || continue
      if [[ -z "$comp" ]] || ! has_component_entry "$comp" "$ns"; then
        problems+=("pod $ns/$pod runs as $sa, and carries no $HARNESS_LABEL of a harness or link component in $ns (label '${comp}')")
      elif [[ "$kind" != Deployment && "$kind" != StatefulSet ]] \
        || ! KIND="$kind" NAME="$name" NS="$ns" yq -e 'select(.kind == strenv(KIND) and .metadata.name == strenv(NAME) and .metadata.namespace == strenv(NS))' \
          "$BUNDLES/$comp/manifests.yaml" >/dev/null 2>&1; then
        problems+=("pod $ns/$pod runs as $sa, and its controller '${kind}/${name}' is no workload of the bundle $comp in $ns")
      fi
    done < <(jq -r --arg sa "$sa" --arg label "$HARNESS_LABEL" --argjson sets "$sets" '
      ($sets.items | map({key: .metadata.name,
        value: ([(.metadata.ownerReferences // [])[] | select(.controller == true)][0] // {kind: "", name: ""})}) | from_entries) as $owners
      | .items[] | select(.spec.serviceAccountName == $sa)
      | ([(.metadata.ownerReferences // [])[] | select(.controller == true)][0] // {kind: "", name: ""}) as $o
      | (if $o.kind == "ReplicaSet" then ($owners[$o.name] // {kind: "", name: ""}) else $o end) as $w
      | [.metadata.name, (.metadata.labels[$label] // ""), $w.kind, $w.name] | join("|")' <<<"$pods")
  done
  if ((${#problems[@]} > 0)); then
    printf '%s\n' "${problems[@]}"
    echo "Delete each pod above and the workload that made it. Only the harness may run a plane ServiceAccount."
    return 1
  fi
}

# check_harness_objects <component> <namespace> compares the namespace with the bundle of a harness
# or link component. The harness apply does not prune, and kubectl diff sees only the fields of
# its own field manager. Each object of the bundle must have only the field manager kubectl,
# kube-controller-manager for status, and validatingadmissionpolicy-status for the status of a
# ValidatingAdmissionPolicy, which the API server writes for its type check.
#   - When the bundle holds the Namespace, the component owns it: for each namespaced kind that the bundle
#     holds, the namespace must hold exactly the objects of the bundle in it, apart from
#     objects that only system controllers write, for example kube-root-ca.crt. The Namespace must
#     have only kubectl.
#   - Otherwise the namespace is shared with a bundle, whose Application owns the Namespace and its
#     own objects. For each kind, the objects with the harness label of the component must be
#     exactly the objects of the bundle in the namespace.
#   - For each cluster-scoped kind of the bundle, Namespace included, the objects with the harness
#     label of the component must be exactly the objects of the bundle. A list of a cluster-scoped
#     kind holds the objects of every owner, so only the label tells them apart.
# runtime_objects <component> <namespace> <kind> prints a JSON object {names, managers, labels} for
# the objects of one kind that a workload of the component writes at run time, or null. The bundle
# cannot hold them, so check_harness_objects skips each one whose name matches names, whose field
# managers are all in managers, and whose harness label is absent or in labels. The one case: the
# principal of central-view stores the AppProjects of each autonomous agent in central-view-system
# as <agent>-<project>, for each agent <POC_ENV>-<cell> of VIEW_CELLS. The principal creates them
# with the field manager foo and updates them as argocd-agent (v0.10.0
# internal/backend/kubernetes/appproject/kubernetes.go lines 88 and 123). Each one keeps the labels
# of the copy in the cell, so it carries the harness label argocd-agent.
# The second case: mgmtd publishes ConfigMap mgmt-system/mgmt-signing-pub with the field manager
# mgmtd, the harness label mgmt-api and the marker label poc.internal/made-by=mgmtd. A listed
# object counts as a runtime object only when it carries the marker, so a person cannot add an
# object of that name without it.
runtime_objects() {
  local cell agents=()
  if [[ "$1" == mgmt-api && "$2" == mgmt-system && "$3" == ConfigMap ]]; then
    jq -cn '{names: "^mgmt-signing-pub$", managers: ["mgmtd"], labels: ["mgmt-api"], marker: {key: "poc.internal/made-by", value: "mgmtd"}}'
    return
  fi
  if [[ "$1" == central-view && "$2" == central-view-system && "$3" == AppProject ]]; then
    for cell in ${VIEW_CELLS:-}; do agents+=("$POC_ENV-$cell"); done
    ((${#agents[@]} > 0)) || { echo null; return; }
    jq -cn --arg re "^($(IFS='|'; echo "${agents[*]}"))-[a-z0-9]([a-z0-9-]*[a-z0-9])?$" \
      '{names: $re, managers: ["foo", "argocd-agent"], labels: ["argocd-agent"]}'
    return
  fi
  echo null
}

check_harness_objects() {
  local comp="$1" ns="$2" bundle="$BUNDLES/$1/manifests.yaml" kind want got live bad owned runtime problems=()
  [[ -f "$bundle" ]] || { echo "no $bundle. Run: $(fix_command "$comp")"; return 1; }
  owned="$(NS="$ns" yq -N 'select(.kind == "Namespace" and .metadata.name == strenv(NS)) | .metadata.name' "$bundle")"
  # managers_of <live list> <names> prints each field manager of the named objects other than
  # kubectl Apply and the status writes named above. The manager harness-replicas (scripts/harness-replicas.sh)
  # is allowed on a StatefulSet or Deployment, as an Update of the scale subresource that owns exactly spec.replicas.
  managers_of() {
    jq -r --arg want " $2 " '.items[] | .metadata.name as $name | select($want | contains(" " + $name + " "))
      | . as $o | $o.metadata.managedFields[]? | select((.manager == "kubectl" and .operation == "Apply")
        or (.manager == "kube-controller-manager" and .subresource == "status")
        or (.manager == "validatingadmissionpolicy-status" and .subresource == "status" and $o.kind == "ValidatingAdmissionPolicy")
        or (.manager == "harness-replicas" and .operation == "Update" and .subresource == "scale"
          and (["StatefulSet", "Deployment"] | index($o.kind) != null) and .fieldsV1 == {"f:spec": {"f:replicas": {}}}) | not)
      | "\($o.kind)/\($name) has the field manager \(.manager) (\(.operation) \(.subresource // "object"))"' <<<"$1"
  }
  # The kinds are those that the bundle holds in any namespace, so a bundle that spans two namespaces (envd:
  # its Deployment in envd-system, its Role in spire-system) also finds a stray object of such a kind here.
  for kind in $(yq -N -r 'select(.kind != null and (.metadata.namespace // "") != "") | .kind' "$bundle" | sort -u); do
    want="$(KIND="$kind" NS="$ns" yq -o=json -I=0 'select(.kind == strenv(KIND) and .metadata.namespace == strenv(NS)) | .metadata.name' "$bundle" | jq -rs 'sort | join(" ")')"
    live="$(k -n "$ns" get "$kind" -o json --show-managed-fields)" || { echo "could not list $kind in $ns"; return 1; }
    runtime="$(runtime_objects "$comp" "$ns" "$kind")"
    if [[ -n "$owned" ]]; then
      got="$(jq -r --arg label "$HARNESS_LABEL" --argjson runtime "$runtime" '[.items[]
        | select(($runtime == null) or ((((.metadata.labels[$label] // "") as $l | $l == "" or ($runtime.labels | index($l)) != null)
            and (.metadata.name | test($runtime.names))
            and (($runtime.marker // null) == null or .metadata.labels[$runtime.marker.key] == $runtime.marker.value)
            and ((.metadata.managedFields // []) | length) > 0
            and all(.metadata.managedFields[]; .manager as $m | $runtime.managers | index($m) != null)) | not))
        | select((.metadata.labels[$label] // "") != ""
          or any(.metadata.managedFields[]?; .manager != "kube-controller-manager" and .manager != "pilot-discovery"))
        | .metadata.name] | sort | join(" ")' <<<"$live")" || { echo "could not read the $kind objects in $ns"; return 1; }
      [[ "$got" == "$want" ]] || problems+=("$ns has the $kind objects '$got' that the harness or a person wrote, and the bundle $comp has '$want'")
    else
      got="$(jq -r --arg label "$HARNESS_LABEL" --arg comp "$comp" '[.items[]
        | select(.metadata.labels[$label] == $comp) | .metadata.name] | sort | join(" ")' <<<"$live")" \
        || { echo "could not read the $kind objects in $ns"; return 1; }
      [[ "$got" == "$want" ]] || problems+=("$ns has the $kind objects '$got' with the label $HARNESS_LABEL=$comp, and the bundle $comp has '$want'")
    fi
    bad="$(managers_of "$live" "$want")" || { echo "could not read the field managers of $kind in $ns"; return 1; }
    [[ -z "$bad" ]] || problems+=("$bad")
  done
  for kind in $(yq -N -r 'select(.kind != null and (.metadata.namespace // "") == "") | .kind' "$bundle" | sort -u); do
    want="$(KIND="$kind" yq -o=json -I=0 'select(.kind == strenv(KIND) and (.metadata.namespace // "") == "") | .metadata.name' "$bundle" | jq -rs 'sort | join(" ")')"
    live="$(k get "$kind" -l "$HARNESS_LABEL=$comp" -o json --show-managed-fields)" || { echo "could not list $kind with the label $HARNESS_LABEL=$comp"; return 1; }
    got="$(jq -r '[.items[].metadata.name] | sort | join(" ")' <<<"$live")" || { echo "could not read the $kind objects"; return 1; }
    [[ "$got" == "$want" ]] || problems+=("the cluster has the $kind objects '$got' with the label $HARNESS_LABEL=$comp, and the bundle $comp has '$want'")
    bad="$(managers_of "$live" "$want")" || { echo "could not read the field managers of $kind"; return 1; }
    [[ -z "$bad" ]] || problems+=("$bad")
  done
  if [[ -n "$owned" ]]; then
    live="$(k get namespace "$ns" -o json --show-managed-fields)" || { echo "no namespace $ns"; return 1; }
    bad="$(jq -r --arg ns "$ns" '.metadata.managedFields[]? | select(.manager == "kubectl" and .operation == "Apply" | not)
      | "Namespace/\($ns) has the field manager \(.manager)"' <<<"$live")" \
      || { echo "could not read the field managers of $ns"; return 1; }
    [[ -z "$bad" ]] || problems+=("$bad")
  fi
  if ((${#problems[@]} > 0)); then
    printf '%s\n' "${problems[@]}"
    echo "Delete each extra object, and each field that another manager added. Then run: $(fix_command "$comp")"
    return 1
  fi
}

# check_no_last_applied_secret succeeds when no Secret in observability-system carries the annotation
# kubectl.kubernetes.io/last-applied-configuration. A client-side kubectl apply writes the whole Secret,
# password included, into it, and kubectl describe prints annotations.
check_no_last_applied_secret() {
  local found
  found="$(k -n observability-system get secrets -o json | jq -r '.items[]
    | select(.metadata.annotations["kubectl.kubernetes.io/last-applied-configuration"] != null) | .metadata.name')" \
    || { echo "could not list the Secrets of observability-system"; return 1; }
  [[ -z "$found" ]] || {
    echo "the Secrets ${found//$'\n'/, } carry the annotation last-applied-configuration, which can hold a password."
    echo "Run: CELL=$CELL_NAME mise run obs:rotate-password, which removes it from grafana-admin. Delete it from another Secret with: kubectl annotate secret <name> kubectl.kubernetes.io/last-applied-configuration-"
    return 1
  }
}

# pem_der_sha256 reads PEM certificates on standard input and prints the SHA-256 of their DER bytes, in
# file order, one after the other. hostsvc prints the same value as root_sha256 for its client roots.
pem_der_sha256() {
  local decode=-d line
  printf 'AA==' | base64 -d >/dev/null 2>&1 || decode=-D
  awk '/-----BEGIN CERTIFICATE-----/ { b = ""; next } /-----END CERTIFICATE-----/ { print b; next } { b = b $0 }' \
    | while read -r line; do printf '%s' "$line" | base64 "$decode"; done \
    | if command -v sha256sum >/dev/null; then sha256sum | cut -d' ' -f1; else shasum -a 256 | cut -d' ' -f1; fi
}

# dependents_of <name> prints the commands that bring the copies of a change up to date, one command on each
# line, in the order to run them. The name is a cluster that was rebuilt (management, dev-cp or a cell), or
# hostsvc for a restart of the host service. The README section "Rebuild one cluster" holds the same table.
# No step waits until every cell is bound: a cell binds on its own once its cell:up has run.
dependents_of() {
  local cell cells
  # The cells are the clusters that dev-cp lists in SPIRE_AGENT_CELLS.
  cells="$(sed -n 's/^SPIRE_AGENT_CELLS="\(.*\)"$/\1/p' "$ROOT/cells/dev-cp.env")"
  case "$1" in
    hostsvc) echo "mise run hostsvc:serve -- restart" ;;
    management)
      echo "mise run hostsvc -- up --only management"
      echo "CELL_UP_SKIP_LINK=1 CELL=management mise run cell:up"
      echo "CELL=management LINK_ONLY=mgmt-api mise run cell:link"
      echo "CELL=dev-cp mise run cell:up"
      for cell in $cells; do echo "CELL=$cell mise run cell:up"; done
      echo "CELL=management mise run cell:link" ;;
    dev-cp)
      echo "CELL=dev-cp mise run cell:up"
      for cell in $cells; do echo "CELL=$cell mise run cell:up"; done
      for cell in $cells; do echo "CELL=$cell mise run cell:restart"; done
      echo "CELL=management mise run cell:link" ;;
    *)
      for cell in $cells; do
        [[ "$cell" == "$1" ]] || continue
        echo "CELL=dev-cp mise run cell:up"
        echo "CELL=$cell mise run cell:up"
        return
      done
      die "dependents_of knows management, dev-cp, hostsvc and $cells, not '$1'" ;;
  esac
}

# gate_test_timeout <budget minutes> prints the go test timeout of a gate in minutes: twice the budget,
# and never below 30. An empty budget gives 30.
gate_test_timeout() {
  local budget="${1:-}" timeout=30
  [[ -z "$budget" ]] || ((budget * 2 <= timeout)) || timeout=$((budget * 2))
  printf '%s\n' "$timeout"
}
