#!/usr/bin/env bash
# Set up the cell: create the cluster through the host service, apply the bootstrap set, publish
# the bundles, then wait until Argo CD reports every Application as Synced and Healthy at the
# published revision. In a cluster with SECRET_STORE_NAMESPACES, the wait also connects the secret
# store, or asks for secrets:connect in a second shell. Last, apply the harness components and wait
# for their rollouts.
source "$(dirname "$0")/lib.sh"

((${#COMPONENTS[@]} > 0)) || die "cell $CELL_NAME has no components in harness/topology.yaml"
log "creating cluster $CELL_NAME through the host service"
(cd "$ROOT" && mise run hostsvc -- up --only "$CELL_NAME")
k wait --for=condition=Ready nodes --all --timeout=300s >/dev/null \
  || die "the node of $CELL_NAME is not Ready after 300s. Read its state: mise x -- kubectl --context kind-$CELL_NAME describe nodes. Then run CELL=$CELL_NAME mise run cell:up again"

"$ROOT/scripts/facts.sh"
"$ROOT/scripts/hydrate.sh"

for c in "${BOOTSTRAP[@]}"; do
  apply_bundle "$c"
done
k -n cell-system rollout status statefulset/bundle-store --timeout=300s >/dev/null
k -n argocd rollout status deploy/argocd-repo-server --timeout=300s >/dev/null
k -n argocd rollout status statefulset/argocd-application-controller --timeout=300s >/dev/null
k apply --server-side -f "$ROOT/bootstrap/root.yaml" >/dev/null
log "applied the root Application"

"$ROOT/scripts/publish.sh"

expected=$((${#COMPONENTS[@]} + 1))
log "waiting for $expected Applications to be Synced and Healthy at the published revisions"
end=$((SECONDS + 900))
store_done=0
last_hint=-60
# Without direnv, the token command still comes from .envrc.local.
[[ -z "${SECRET_STORE_NAMESPACES:-}" ]] || load_local_settings POC_SECRET_TOKEN_CMD
until apps_at_published >/dev/null 2>&1; do
  if [[ -n "${SECRET_STORE_NAMESPACES:-}" ]] && ((!store_done)); then
    connect_store_step "$ROOT/scripts/secrets-connect.sh"
  fi
  if ((SECONDS >= end)); then
    k -n argocd get applications
    die "Applications did not reach the published revisions, Synced and Healthy, in 900s"
  fi
  sleep 10
done
k -n argocd get applications

# Harness components stay outside Argo CD. The harness applies them after the root bundle syncs,
# so no Application from an older root bundle still claims their objects. The apply does not
# prune: an object that leaves the bundle stays in the cluster. cell:verify reports a
# NetworkPolicy that the bundle does not hold. harness_apply stops before it takes an object that
# another owner holds.
for entry in ${HARNESS_COMPONENTS[@]+"${HARNESS_COMPONENTS[@]}"}; do
  harness_apply "${entry%%:*}"
done
for entry in ${HARNESS_COMPONENTS[@]+"${HARNESS_COMPONENTS[@]}"}; do
  harness_rollout_wait "${entry%%:*}" "${entry#*:}"
  log "harness component ${entry%%:*} is rolled out"
done
log "cell $CELL_NAME is up. Run mise run cell:verify."
