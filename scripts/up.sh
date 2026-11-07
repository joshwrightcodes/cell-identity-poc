#!/usr/bin/env bash
# Stand up the cell: cluster, bootstrap set, bundles, then wait until Argo CD reports every
# Application as Synced and Healthy.
source "$(dirname "$0")/lib.sh"

clusters="$(container cluster list)" || die "container cluster list failed. Is the container system running?"
if awk 'NR > 1 { print $1 }' <<<"$clusters" | grep -qx "$CELL_NAME"; then
  log "cluster $CELL_NAME exists"
else
  log "creating cluster $CELL_NAME"
  container cluster create --name "$CELL_NAME" --cpus "$CELL_CPUS" --memory "$CELL_MEMORY" \
    --node-image "$CELL_NODE_IMAGE"
fi
k wait --for=condition=Ready nodes --all --timeout=300s >/dev/null

"$ROOT/scripts/facts.sh"
"$ROOT/scripts/hydrate.sh"

apply_bundle() {
  local file="$BUNDLES/$1/manifests.yaml"
  if ! k apply --server-side --force-conflicts -f "$file" >/dev/null 2>&1; then
    # A bundle can hold a CRD and an object of that kind. The first apply fails for that object.
    # Wait for the CRD, then apply again. The second apply shows any real error.
    k wait --for=condition=Established crd --all --timeout=120s >/dev/null
    k apply --server-side --force-conflicts -f "$file" >/dev/null
  fi
  log "applied bootstrap bundle $1"
}

for c in "${BOOTSTRAP[@]}"; do
  apply_bundle "$c"
done
k -n cell-system rollout status deploy/registry --timeout=300s >/dev/null
k -n argocd rollout status deploy/argocd-repo-server --timeout=300s >/dev/null
k -n argocd rollout status statefulset/argocd-application-controller --timeout=300s >/dev/null
k apply --server-side -f "$ROOT/bootstrap/root.yaml" >/dev/null
log "applied the root Application"

"$ROOT/scripts/publish.sh"

expected=$((${#COMPONENTS[@]} + 1))
apps_ready() {
  k -n argocd get applications -o json | jq -e --argjson n "$expected" '
    (.items | length) == $n and
    all(.items[]; .status.sync.status == "Synced" and .status.health.status == "Healthy")'
}
log "waiting for $expected Applications to be Synced and Healthy"
end=$((SECONDS + 900))
until apps_ready >/dev/null 2>&1; do
  if ((SECONDS >= end)); then
    k -n argocd get applications
    die "Applications did not become Synced and Healthy in 900s"
  fi
  sleep 10
done
k -n argocd get applications
log "cell $CELL_NAME is up. Run mise run cell:verify."
