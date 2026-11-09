# Shared helpers. Source this file; do not run it.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# POC_BUILD_ROOT names another build directory, for the tests.
BUILD_ROOT="${POC_BUILD_ROOT:-$ROOT/build}"

log() { printf '==> %s\n' "$*" >&2; }

die() { printf 'error: %s\n' "$*" >&2; exit 1; }

# CELL names the cluster. cells/common.env and cells/$CELL.env hold its settings.
CELL="${CELL:-dev-cell-1}"
[[ -f "$ROOT/cells/$CELL.env" ]] || die "unknown cell '$CELL'. Known cells: $(cd "$ROOT/cells" && ls *.env | sed -e 's/\.env$//' -e '/^common$/d' | paste -sd' ' -)"
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

# Read the component sets of $CELL from the topology. An unknown set name is an error.
COMPONENTS=()
HARNESS_COMPONENTS=()
set_names="$(yq -r ".clusters[] | select(.name == \"$CELL\") | .components[]" "$ROOT/harness/topology.yaml")"
for set_name in $set_names; do
  case "$set_name" in
    base-cell) COMPONENTS+=("${BASE_CELL_COMPONENTS[@]}") ;;
    external-secrets) COMPONENTS+=("${EXTERNAL_SECRETS_COMPONENTS[@]}") ;;
    spire-server) COMPONENTS+=("${SPIRE_SERVER_COMPONENTS[@]}") ;;
    cell-identity) HARNESS_COMPONENTS+=("${CELL_IDENTITY_HARNESS[@]}") ;;
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

# apps_at_published succeeds when Argo CD reports every Application of the cluster Synced and
# Healthy at the revision that publish.sh pushed. A check that runs before Argo CD reads the new
# root bundle cannot pass.
apps_at_published() {
  local published_json
  published_json="$(jq -Rn '[inputs | select(length > 0) | split("=") | {(.[0]): .[1]}] | add' <"$PUBLISHED")" || return 1
  k -n argocd get applications -o json | jq -e --argjson n "$((${#COMPONENTS[@]} + 1))" --argjson pub "$published_json" '
    (.items | length) == $n and
    all(.items[]; .status.sync.status == "Synced" and .status.health.status == "Healthy"
      and .status.sync.revision == $pub[.metadata.name])'
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

# harness_deployments <component> <namespace> prints the Deployments of a harness component, as
# deployment.apps/<name>. Other Deployments in the namespace belong to a bundle.
harness_deployments() {
  k -n "$2" get deployments -l "$HARNESS_LABEL=$1" -o name
}

# harness_rollout_wait <component> <namespace> waits for the rollout of each Deployment of a
# harness component.
harness_rollout_wait() {
  local deployment
  for deployment in $(harness_deployments "$1" "$2"); do
    if ! k -n "$2" rollout status "$deployment" --timeout=300s >/dev/null; then
      log "read the events: mise x -- kubectl --context kind-$CELL_NAME -n $2 describe $deployment"
      log "read the logs: mise x -- kubectl --context kind-$CELL_NAME -n $2 logs $deployment --all-containers"
      die "$deployment in $2 did not finish its rollout in 300s"
    fi
  done
}

# check_harness_objects <component> <namespace> compares the namespace with the bundle of a harness
# component. The harness apply does not prune, and kubectl diff sees only the fields of its own
# field manager. Each object of the bundle must have only the field manager kubectl, and
# kube-controller-manager for status.
#   - When the bundle holds the Namespace, the component owns it: for each kind in the bundle, the
#     namespace must hold exactly the objects of the bundle, apart from objects that only system
#     controllers write, for example kube-root-ca.crt. The Namespace must have only kubectl.
#   - Otherwise the namespace is shared with a bundle, whose Application owns the Namespace and its
#     own objects. For each kind, the objects with the harness label of the component must be
#     exactly the objects of the bundle.
check_harness_objects() {
  local comp="$1" ns="$2" bundle="$BUNDLES/$1/manifests.yaml" kind want got live bad owned problems=()
  [[ -f "$bundle" ]] || { echo "no $bundle. Run: CELL=$CELL_NAME mise run cell:up"; return 1; }
  owned="$(NS="$ns" yq -N 'select(.kind == "Namespace" and .metadata.name == strenv(NS)) | .metadata.name' "$bundle")"
  for kind in $(yq -N -r 'select(.kind != null and .kind != "Namespace") | .kind' "$bundle" | sort -u); do
    want="$(KIND="$kind" yq -o=json -I=0 'select(.kind == strenv(KIND)) | .metadata.name' "$bundle" | jq -rs 'sort | join(" ")')"
    live="$(k -n "$ns" get "$kind" -o json --show-managed-fields)" || { echo "could not list $kind in $ns"; return 1; }
    if [[ -n "$owned" ]]; then
      got="$(jq -r --arg label "$HARNESS_LABEL" '[.items[]
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
    bad="$(jq -r --arg want " $want " '.items[] | .metadata.name as $name | select($want | contains(" " + $name + " "))
      | . as $o | $o.metadata.managedFields[]? | select((.manager == "kubectl" and .operation == "Apply")
        or (.manager == "kube-controller-manager" and .subresource == "status") | not)
      | "\($o.kind)/\($name) has the field manager \(.manager) (\(.operation) \(.subresource // "object"))"' <<<"$live")" \
      || { echo "could not read the field managers of $kind in $ns"; return 1; }
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
    echo "Delete each extra object, and each field that another manager added. Then run: CELL=$CELL_NAME mise run cell:up"
    return 1
  fi
}
