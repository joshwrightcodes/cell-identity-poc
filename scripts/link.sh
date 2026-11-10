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
missing="$(link_preflight)"
[[ -z "$missing" ]] || die "the link phase of $CELL_NAME needs other clusters:"$'\n'"$missing"$'\n'"Then run: CELL=$CELL_NAME mise run cell:link"
# The node and API addresses of this cluster can change with a rebuild, so read them again.
"$ROOT/scripts/facts.sh"
HYDRATE_ONLY=link "$ROOT/scripts/hydrate.sh"

# job_state <namespace> <job> prints Complete, Failed or nothing.
job_state() {
  k -n "$1" get job "$2" -o json 2>/dev/null | jq -r '[.status.conditions[]? | select(.status == "True")
    | select(.type == "Complete" or .type == "Failed") | .type][0] // ""'
}

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
  new_ca=""
  for job in $jobs; do
    end=$((SECONDS + 300))
    until state="$(job_state "$ns" "$job")" && [[ -n "$state" ]]; do
      ((SECONDS < end)) || die "Job $job in $ns did not finish in 300s. Read the logs: mise x -- kubectl --context kind-$CELL_NAME -n $ns logs job/$job"
      sleep 3
    done
    out="$(k -n "$ns" logs "job/$job" --tail=1 2>/dev/null || true)"
    [[ "$state" == Complete ]] || die "Job $job in $ns failed: ${out:-no log line}"
    log "Job $job in $ns completed"
    # viewkeys names the reason when it made a new agent CA.
    reason="$(jq -r '.new_ca_reason // ""' <<<"$out" 2>/dev/null || true)"
    [[ -z "$reason" ]] || new_ca="$reason"
  done
  harness_rollout_wait "$comp" "$ns"
  if [[ -n "$new_ca" ]]; then
    # The principal and argocd-server read the certificates only at start.
    log "viewkeys made a new agent CA ($new_ca), so the principal and argocd-server start again"
    for d in argocd-agent-principal argocd-server; do
      restart_deployment_pods "$ns" "$d"
    done
  fi
  log "link component $comp is rolled out"
done
log "the link phase of $CELL_NAME is done. Run CELL=$CELL_NAME mise run cell:verify."
