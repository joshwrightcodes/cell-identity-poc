#!/usr/bin/env bash
# Restart the Deployments and StatefulSets of every harness and link component of the cluster $CELL, and
# wait until each has new Ready pods. Only the workloads with the harness label of the component
# count, because a harness component can share its namespace with Argo CD objects. They must be
# exactly the workloads that the bundle of the component renders. A restarted celld pod gets a
# new pod UID, so its SPIRE agent attests again.
# In a cluster with the spire-server component set, restart the SPIRE server pod. It keeps its
# datastore. With an upstream authority (dev-cp), the new server signs a new CA through it. Without
# one (management), the server loads its CA key from the data volume, so the root stays the same
# and every peer copy of it stays valid.
# The script deletes the pods and lets the controller replace them. It does not change the
# Deployment or the StatefulSet, so their field managers stay the same.
source "$(dirname "$0")/lib.sh"

runs_spire_server=0
for entry in "${COMPONENTS[@]}"; do
  [[ "${entry%%:*}" == spire-server ]] && runs_spire_server=1
done
((${#HARNESS_COMPONENTS[@]} + ${#LINK_COMPONENTS[@]} > 0 || runs_spire_server)) \
  || die "cluster $CELL_NAME has no harness or link component and no SPIRE server in harness/topology.yaml, so cell:restart has nothing to restart"

# rollout_hint <namespace> <deployment> prints the commands that show why a rollout failed.
rollout_hint() {
  printf 'Read the events: mise x -- kubectl --context kind-%s -n %s describe %s\n' "$CELL_NAME" "$1" "$2"
  printf 'Read the logs: mise x -- kubectl --context kind-%s -n %s logs %s --all-containers\n' "$CELL_NAME" "$1" "$2"
}

if ((runs_spire_server)); then
  selector=app.kubernetes.io/name=spire-server
  old="$(k -n spire-system get pods -l "$selector" -o jsonpath='{.items[*].metadata.uid}')"
  stopped=$SECONDS
  k -n spire-system delete pods -l "$selector" --wait=true --timeout=120s >/dev/null || die "could not delete the SPIRE server pod in spire-system"
  end=$((SECONDS + 300))
  until uids="$(new_ready_pods spire-system "$selector" "$old")" && [[ -n "$uids" ]]; do
    if ((SECONDS >= end)); then
      rollout_hint spire-system statefulset/spire-server >&2
      die "statefulset/spire-server in spire-system has no new Ready pod after 300s"
    fi
    sleep 2
  done
  log "restarted the SPIRE server in spire-system. It answered no agent for $((SECONDS - stopped))s"
fi

for entry in ${HARNESS_COMPONENTS[@]+"${HARNESS_COMPONENTS[@]}"} ${LINK_COMPONENTS[@]+"${LINK_COMPONENTS[@]}"}; do
  ns="${entry#*:}"
  workloads="$(harness_workloads "${entry%%:*}" "$ns")" || exit 1
  for workload in $workloads; do
    selector="$(k -n "$ns" get "$workload" -o json \
      | jq -r '.spec.selector.matchLabels | to_entries | map("\(.key)=\(.value)") | join(",")')"
    [[ -n "$selector" ]] || die "$workload in $ns has no label selector"
    old="$(k -n "$ns" get pods -l "$selector" -o jsonpath='{.items[*].metadata.uid}')"
    k -n "$ns" delete pods -l "$selector" --wait=true --timeout=120s >/dev/null || die "could not delete the pods of $workload in $ns"
    end=$((SECONDS + 300))
    until uids="$(new_ready_pods "$ns" "$selector" "$old")" && [[ -n "$uids" ]]; do
      if ((SECONDS >= end)); then
        rollout_hint "$ns" "$workload" >&2
        die "$workload in $ns has no new Ready pod after 300s"
      fi
      sleep 2
    done
    k -n "$ns" rollout status "$workload" --timeout=300s >/dev/null || { rollout_hint "$ns" "$workload" >&2; die "$workload in $ns did not finish its rollout"; }
    log "restarted $workload in $ns"
  done
done
