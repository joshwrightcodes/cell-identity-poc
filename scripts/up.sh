#!/usr/bin/env bash
# Set up the cell: create the cluster through the host service, apply the bootstrap set, publish
# the bundles, then wait until Argo CD reports every Application as Synced and Healthy at the
# published revision. In a cluster with SECRET_STORE_NAMESPACES, the wait also connects the secret
# store, or asks for secrets:connect in a second shell. Then apply the harness components and wait
# for their rollouts (scripts/attest-wait.sh for cell-identity). UP_WAIT sets the bound of the Application wait in seconds (default 900).
# A cluster whose bundle state has source signed takes the signed path: no bootstrap apply and no root apply, and scripts/bundle.sh
# publish in place of scripts/publish.sh. After the harness apply, a cluster with a bundle role and no state gets the bootstrap state.
# Last, run the link phase (scripts/link.sh), unless CELL_UP_SKIP_LINK=1.
# The run takes the lock of the cluster (cluster_lock in scripts/lib.sh), and a step of the host service waits for it.
# A cell has no cluster until a signed step creates it, so cell:up of an absent cell stops with cell_needs_step and the
# portal command. A step creates the cluster first, and then this script runs.
# HARNESS_ONLY=<component> renders and applies only that harness component of an existing cluster, prunes what its bundle
# no longer holds, and waits for its rollout. It skips the host service, the bootstrap set, the publish and the Application wait.
source "$(dirname "$0")/lib.sh"

((${#COMPONENTS[@]} > 0)) || die "cell $CELL_NAME has no components in harness/topology.yaml"

# wait_component <component> <namespace> waits for the rollout of a harness component. The component cell-identity gets
# the stage by stage wait of scripts/attest-wait.sh, and the others the plain rollout wait.
wait_component() {
  local waited
  if [[ "$1" == cell-identity ]]; then
    harness_workloads cell-identity "$2" >/dev/null || exit 1
    # The script prints "skipped" on standard output when the management plane does not answer.
    waited="$("$ROOT/scripts/attest-wait.sh" "$CELL_NAME")"
    if [[ "$waited" == skipped ]]; then
      log "harness component cell-identity was not waited for, so it may not be Ready. Link management first, then run: CELL=$CELL_NAME mise run cell:up"
      return 0
    fi
  else
    harness_rollout_wait "$1" "$2"
  fi
  log "harness component $1 is rolled out"
}

cluster_lock "$CELL_NAME"

if [[ -n "${HARNESS_ONLY:-}" ]]; then
  entry="$(harness_only_entry)" || exit 1
  kind get clusters 2>/dev/null | grep -qx -- "$CELL_NAME" \
    || die "HARNESS_ONLY needs the cluster $CELL_NAME, and it does not exist. Run: CELL=$CELL_NAME mise run cell:up"
  log "applying only the harness component ${entry%%:*} of $CELL_NAME"
  "$ROOT/scripts/facts.sh"
  HARNESS_ONLY="${entry%%:*}" "$ROOT/scripts/hydrate.sh"
  harness_apply "${entry%%:*}"
  wait_component "${entry%%:*}" "${entry#*:}"
  log "cell $CELL_NAME has the harness component ${entry%%:*} up to date."
  exit 0
fi

# A cell of the catalog exists only through a signed step. cell:up of a cell that has no cluster says so, and it names the
# portal command. A re-apply to an existing cluster stays allowed: repairs and rotations use it.
if grep -qx -- "$CELL_NAME" <<<"$(catalog_cells)" && ! kind get clusters 2>/dev/null | grep -qx -- "$CELL_NAME"; then
  die "cell_needs_step: cell $CELL_NAME has no cluster, and only a signed step creates it. Run: mise run portal -- request --cell $CELL_NAME --wait"
fi
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

# A cluster whose bundle state has source signed takes its bundles only from signed sets: the bootstrap apply and the root
# Application would overwrite what Argo CD syncs, so this path runs scripts/bundle.sh publish and nothing of the bootstrap.
state_source="$(bundle_state_source)" || die "could not read the bundle state of $CELL_NAME, so cell:up cannot tell the bootstrap path from the signed path"
if [[ "$state_source" == signed ]]; then
  log "the bundle state of $CELL_NAME has source signed: publishing a signed set, with no bootstrap apply"
  log "running scripts/bundle.sh publish --target $CELL_NAME --wait"
  "$ROOT/scripts/bundle.sh" publish --target "$CELL_NAME" --wait
  # envd holds the harness plane policies of dev-cp, and the signed set no longer carries the rules that they replace. So a signed publish in
  # dev-cp ends with a new render of envd, which reads the live cells again: a cell that came or went changes plane-cells.
  if [[ "$(bundle_role)" == cp ]]; then
    HARNESS_ONLY=envd "$ROOT/scripts/hydrate.sh"
    harness_apply envd
  fi
else
  for c in "${BOOTSTRAP[@]}"; do
    apply_bundle "$c"
  done
  store_upgrade
  k -n cell-system rollout status statefulset/bundle-store --timeout=300s >/dev/null
  k -n argocd rollout status deploy/argocd-repo-server --timeout=300s >/dev/null
  k -n argocd rollout status statefulset/argocd-application-controller --timeout=300s >/dev/null
  k apply --server-side -f "$ROOT/bootstrap/root.yaml" >/dev/null
  log "applied the root Application"

  "$ROOT/scripts/publish.sh"
fi

expected=$((${#COMPONENTS[@]} + 1))
log "waiting for $expected Applications to be Synced and Healthy at the published revisions"
up_wait="${UP_WAIT:-900}"
end=$((SECONDS + up_wait))
store_done=0
last_hint=-60
# Without direnv, the token command still comes from .envrc.local.
[[ -z "${SECRET_STORE_NAMESPACES:-}" ]] || load_local_settings POC_SECRET_TOKEN_CMD
# A step of the host service runs with no secret manager command. The log line shows that, and never the value.
[[ -z "${POC_STEP_ID:-}" ]] || log "secret_token_cmd_set=$([[ -n "${POC_SECRET_TOKEN_CMD:-}" ]] && echo true || echo false)"
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
# so no Application from an older root bundle still claims their objects. After each apply,
# harness_prune deletes the objects that left the bundle (HARNESS_PRUNE_KINDS in scripts/lib.sh).
# harness_apply stops before it takes an object that another owner holds.
# The components in LATE_HARNESS read the live SPIRE server of this cluster, which exists now.
HYDRATE_ONLY=late "$ROOT/scripts/hydrate.sh"
for entry in ${HARNESS_COMPONENTS[@]+"${HARNESS_COMPONENTS[@]}"}; do
  harness_apply "${entry%%:*}"
done
# The harness apply made the namespace of the state. A cluster with a bundle role and no state gets the bootstrap state.
bundle_state_bootstrap
# celld cannot become Ready before its record reaches the SPIRE server, so attest-wait.sh waits for
# each stage of the first attestation and names the stage that fails. The other components keep the
# plain rollout wait.
for entry in ${HARNESS_COMPONENTS[@]+"${HARNESS_COMPONENTS[@]}"}; do
  wait_component "${entry%%:*}" "${entry#*:}"
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
