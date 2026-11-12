#!/usr/bin/env bash
# Set up the cell: create the cluster through the host service, apply the bootstrap set, publish
# the bundles, then wait until Argo CD reports every Application as Synced and Healthy at the
# published revision. In a cluster with SECRET_STORE_NAMESPACES, the wait also connects the secret
# store, or asks for secrets:connect in a second shell. Then apply the harness components and wait
# for their rollouts (scripts/attest-wait.sh for cell-identity). UP_WAIT sets the bound of the Application wait in seconds (default 900).
# Last, run the link phase (scripts/link.sh), unless CELL_UP_SKIP_LINK=1.
source "$(dirname "$0")/lib.sh"

((${#COMPONENTS[@]} > 0)) || die "cell $CELL_NAME has no components in harness/topology.yaml"
# The link phase comes last, and it needs other clusters. Check them before the first step, so a
# missing cluster stops cell:up in seconds and not after the base cell.
if [[ "${CELL_UP_SKIP_LINK:-}" != 1 ]]; then
  missing="$(link_preflight)"
  [[ -z "$missing" ]] || die "the link phase of $CELL_NAME needs other clusters:"$'\n'"$missing"$'\n'"Or set up the base cell alone now, and run the link phase later: CELL_UP_SKIP_LINK=1 CELL=$CELL_NAME mise run cell:up, then CELL=$CELL_NAME mise run cell:link"
fi
log "creating cluster $CELL_NAME through the host service"
(cd "$ROOT" && mise run hostsvc -- up --only "$CELL_NAME")
k wait --for=condition=Ready nodes --all --timeout=300s >/dev/null \
  || die "the node of $CELL_NAME is not Ready after 300s. Read its state: mise x -- kubectl --context kind-$CELL_NAME describe nodes. Then run CELL=$CELL_NAME mise run cell:up again"

"$ROOT/scripts/facts.sh"
# The link components render in the link phase, after every wave, because they read live facts.
CELL_UP_SKIP_LINK=1 CELL_UP_SKIP_LATE=1 "$ROOT/scripts/hydrate.sh"

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
up_wait="${UP_WAIT:-900}"
end=$((SECONDS + up_wait))
store_done=0
last_hint=-60
# Without direnv, the token command still comes from .envrc.local.
[[ -z "${SECRET_STORE_NAMESPACES:-}" ]] || load_local_settings POC_SECRET_TOKEN_CMD
until apps_at_published 2>/dev/null; do
  if [[ -n "${SECRET_STORE_NAMESPACES:-}" ]] && ((!store_done)); then
    connect_store_step "$ROOT/scripts/secrets-connect.sh"
  fi
  if ((SECONDS >= end)); then
    k get applications -A
    apps_at_published >/dev/null || true
    blockers="$(apps_blockers 2>&1)" || true
    die "Applications did not reach the published revisions, Synced and Healthy, in ${up_wait}s. Blocked by: ${blockers//$'\n'/; }"
  fi
  sleep 10
done
k get applications -A

# Harness components stay outside Argo CD. The harness applies them after the root bundle syncs,
# so no Application from an older root bundle still claims their objects. The apply does not
# prune: an object that leaves the bundle stays in the cluster. cell:verify reports a
# NetworkPolicy that the bundle does not hold. harness_apply stops before it takes an object that
# another owner holds.
# The components in LATE_HARNESS read the live SPIRE server of this cluster, which exists now.
HYDRATE_ONLY=late "$ROOT/scripts/hydrate.sh"
for entry in ${HARNESS_COMPONENTS[@]+"${HARNESS_COMPONENTS[@]}"}; do
  harness_apply "${entry%%:*}"
done
# celld cannot become Ready before its record reaches the SPIRE server, so attest-wait.sh waits for
# each stage of the first attestation and names the stage that fails. The other components keep the
# plain rollout wait.
for entry in ${HARNESS_COMPONENTS[@]+"${HARNESS_COMPONENTS[@]}"}; do
  if [[ "${entry%%:*}" == cell-identity ]]; then
    harness_workloads cell-identity "${entry#*:}" >/dev/null || exit 1
    "$ROOT/scripts/attest-wait.sh" "$CELL_NAME"
  else
    harness_rollout_wait "${entry%%:*}" "${entry#*:}"
  fi
  log "harness component ${entry%%:*} is rolled out"
done
if ((${#LINK_COMPONENTS[@]} > 0)); then
  if [[ "${CELL_UP_SKIP_LINK:-}" == 1 ]]; then
    log "skipping the link phase, because CELL_UP_SKIP_LINK=1. Run it later: CELL=$CELL_NAME mise run cell:link"
  else
    log "running the link phase of $CELL_NAME"
    "$ROOT/scripts/link.sh"
  fi
fi
log "cell $CELL_NAME is up. Run mise run cell:verify."
