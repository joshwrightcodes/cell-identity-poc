#!/usr/bin/env bash
# Restart the Deployments of every harness component of the cluster $CELL, and wait for each
# rollout. A restarted celld pod gets a new pod UID, so its SPIRE agent attests again.
source "$(dirname "$0")/lib.sh"

((${#HARNESS_COMPONENTS[@]} > 0)) || die "cell $CELL_NAME has no harness components in harness/topology.yaml"
for entry in "${HARNESS_COMPONENTS[@]}"; do
  ns="${entry#*:}"
  for deployment in $(k -n "$ns" get deployments -o name); do
    k -n "$ns" rollout restart "$deployment" >/dev/null || die "could not restart $deployment in $ns"
    k -n "$ns" rollout status "$deployment" --timeout=300s >/dev/null \
      || die "$deployment in $ns did not finish its rollout in 300s"
    log "restarted $deployment in $ns"
  done
done
