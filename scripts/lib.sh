# Shared helpers. Source this file; do not run it.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD="$ROOT/build"
BUNDLES="$BUILD/bundles"
FACTS="$BUILD/facts.env"

: "${CELL_NAME:?run through mise, which loads cell.env}"

# Bundle order. Each entry is <component>:<sync wave>:<destination namespace>.
COMPONENTS=(
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

# The bootstrap set. Bootstrap applies these bundles once, before Argo CD takes over.
BOOTSTRAP=(namespaces argocd cell-system)

BUNDLE_STORE_HOST="bundle-store.cell-system.svc.cluster.local:5000"

k() { kubectl --context "kind-$CELL_NAME" "$@"; }

log() { printf '==> %s\n' "$*" >&2; }

die() { printf 'error: %s\n' "$*" >&2; exit 1; }

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
