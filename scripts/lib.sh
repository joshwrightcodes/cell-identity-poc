# Shared helpers. Source this file; do not run it.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_ROOT="$ROOT/build"

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
# Each entry is <component>:<namespace>.
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
    die "port ${CELL_BUNDLE_STORE_PORT} already serves a bundle store. Stop the old port-forward first."
  fi
  # Call kubectl directly, not through k, so $! is the kubectl process that the trap kills.
  kubectl --context "kind-$CELL_NAME" -n cell-system port-forward svc/bundle-store "${CELL_BUNDLE_STORE_PORT}:5000" \
    >/dev/null 2>&1 &
  BUNDLE_STORE_PF_PID=$!
  trap 'kill "$BUNDLE_STORE_PF_PID" 2>/dev/null || true' EXIT
  wait_for "port-forward to the bundle store" 30 curl -fsS "http://127.0.0.1:${CELL_BUNDLE_STORE_PORT}/v2/"
}

# The M2 key rotation test edits the API server of one cell on its node. These paths name what it
# leaves behind when a run ends before its cleanup. scripts/gate-m2-repair.sh restores the node.
KEYTEST_MANIFEST=/etc/kubernetes/manifests/kube-apiserver.yaml
KEYTEST_SAVED=/root/m2-test-kube-apiserver.yaml
KEYTEST_KEY=/etc/kubernetes/pki/m2-test-sa

# keytest_leftover <cluster> prints one line for each trace of the key rotation test on the node of
# the cluster, and prints nothing when the node is clean. It fails when it cannot read the node.
keytest_leftover() {
  local node="$1-control-plane"
  docker exec "$node" sh -c "
    [ -e '$KEYTEST_SAVED' ] && echo 'the node holds the saved manifest $KEYTEST_SAVED'
    grep -q 'm2-test-sa' '$KEYTEST_MANIFEST' && echo '$KEYTEST_MANIFEST names the test key'
    for f in '$KEYTEST_KEY.key' '$KEYTEST_KEY.pub'; do [ -e \"\$f\" ] && echo \"the node holds \$f\"; done
    true"
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
