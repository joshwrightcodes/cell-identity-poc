#!/usr/bin/env bash
# The link phase of the cluster $CELL: render each link component with the live facts of the other
# clusters, apply it, run its Jobs to completion, and wait for its rollouts. cell:up runs it last,
# unless CELL_UP_SKIP_LINK=1. A link component follows the harness rules: harness_apply stops
# before it takes an object of another owner, and the apply does not prune.
source "$(dirname "$0")/lib.sh"

if ((${#LINK_COMPONENTS[@]} == 0)); then
  log "cluster $CELL_NAME has no link component in harness/topology.yaml"
  exit 0
fi
[[ -f "$FACTS" ]] || "$ROOT/scripts/facts.sh"
HYDRATE_ONLY=link "$ROOT/scripts/hydrate.sh"

for entry in "${LINK_COMPONENTS[@]}"; do
  comp="${entry%%:*}" ns="${entry#*:}"
  bundle="$BUNDLES/$comp/manifests.yaml"
  # The pod template of a Job cannot change, so each run replaces the Jobs of the bundle. Each Job
  # of a link component is safe to run again.
  jobs="$(NS="$ns" yq -N 'select(.kind == "Job" and .metadata.namespace == strenv(NS)) | .metadata.name' "$bundle")"
  for job in $jobs; do
    k -n "$ns" delete job "$job" --ignore-not-found --wait=true --timeout=120s >/dev/null \
      || die "could not delete Job $job in $ns"
  done
  harness_apply "$comp"
  for job in $jobs; do
    if ! k -n "$ns" wait --for=condition=Complete "job/$job" --timeout=300s >/dev/null; then
      log "read the logs: mise x -- kubectl --context kind-$CELL_NAME -n $ns logs job/$job"
      die "Job $job in $ns did not complete in 300s"
    fi
    log "Job $job in $ns completed"
  done
  harness_rollout_wait "$comp" "$ns"
  log "link component $comp is rolled out"
done
log "the link phase of $CELL_NAME is done. Run CELL=$CELL_NAME mise run cell:verify."
