#!/usr/bin/env bash
# Restart the Deployments of every harness component of the cluster $CELL, and wait until each has
# new Ready pods. A restarted celld pod gets a new pod UID, so its SPIRE agent attests again.
# The script deletes the pods and lets the ReplicaSet replace them. It does not change the
# Deployment, so the harness apply stays the only field manager of the Deployment.
source "$(dirname "$0")/lib.sh"

((${#HARNESS_COMPONENTS[@]} > 0)) || die "cell $CELL_NAME has no harness components in harness/topology.yaml"

# rollout_hint <namespace> <deployment> prints the commands that show why a rollout failed.
rollout_hint() {
  printf 'Read the events: mise x -- kubectl --context kind-%s -n %s describe %s\n' "$CELL_NAME" "$1" "$2"
  printf 'Read the logs: mise x -- kubectl --context kind-%s -n %s logs %s --all-containers\n' "$CELL_NAME" "$1" "$2"
}

for entry in "${HARNESS_COMPONENTS[@]}"; do
  ns="${entry#*:}"
  for deployment in $(k -n "$ns" get deployments -o name); do
    selector="$(k -n "$ns" get "$deployment" -o json \
      | jq -r '.spec.selector.matchLabels | to_entries | map("\(.key)=\(.value)") | join(",")')"
    [[ -n "$selector" ]] || die "$deployment in $ns has no label selector"
    old="$(k -n "$ns" get pods -l "$selector" -o jsonpath='{.items[*].metadata.uid}')"
    k -n "$ns" delete pods -l "$selector" --wait=true --timeout=120s >/dev/null || die "could not delete the pods of $deployment in $ns"
    end=$((SECONDS + 300))
    until uids="$(k -n "$ns" get pods -l "$selector" -o json | jq -r --arg old " $old " '
        [.items[] | .metadata.uid as $uid | select(($old | contains(" " + $uid + " ")) | not)
          | select(any(.status.conditions[]?; .type == "Ready" and .status == "True")) | .metadata.uid] | join(" ")')" \
        && [[ -n "$uids" ]]; do
      if ((SECONDS >= end)); then
        rollout_hint "$ns" "$deployment" >&2
        die "$deployment in $ns has no new Ready pod after 300s"
      fi
      sleep 2
    done
    k -n "$ns" rollout status "$deployment" --timeout=300s >/dev/null || { rollout_hint "$ns" "$deployment" >&2; die "$deployment in $ns did not finish its rollout"; }
    log "restarted $deployment in $ns"
  done
done
