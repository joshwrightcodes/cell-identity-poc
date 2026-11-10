#!/usr/bin/env bash
# Make new keys for the central view in management, then restart the pods that read them:
#   1. Run a copy of Job viewkeys with --rotate. It deletes the agent CA, the resource proxy
#      certificate, the agent JWT key, server.secretkey and each cluster Secret, and makes new ones.
#   2. Delete Secret argocd-redis. The secret-init container of argocd-redis makes a new password
#      when the pod starts again.
#   3. Restart argocd-redis, argocd-repo-server, the principal and argocd-server, in this order, and
#      wait for a new Ready pod of each.
# Standard output carries one JSON line with the restarted workloads. Agents in cells get new
# tokens when they connect again. Log lines go to standard error.
source "$(dirname "$0")/lib.sh"

ns=central-view-system
bundle="$BUNDLES/central-view/manifests.yaml"
[[ -f "$bundle" ]] || die "no $bundle. Run: CELL=$CELL_NAME mise run cell:link"
k -n "$ns" get job viewkeys >/dev/null 2>&1 || die "Job viewkeys is missing in $ns. Run: CELL=$CELL_NAME mise run cell:link"

job=viewkeys-rotate
k -n "$ns" delete job "$job" --ignore-not-found --wait=true --timeout=120s >/dev/null
JOB="$job" yq 'select(.kind == "Job" and .metadata.name == "viewkeys")
    | .metadata.name = strenv(JOB) | del(.metadata.labels["cell.poc.internal/harness"])
    | .spec.template.spec.containers[0].args += ["--rotate"]' "$bundle" \
  | k apply --server-side -f - >/dev/null || die "could not start Job $job"
if ! k -n "$ns" wait --for=condition=Complete "job/$job" --timeout=300s >/dev/null; then
  k -n "$ns" logs "job/$job" >&2 || true
  die "Job $job did not complete. Run mise run view:rotate-keys again"
fi
log "viewkeys: $(k -n "$ns" logs "job/$job")"
k -n "$ns" delete job "$job" --wait=true --timeout=120s >/dev/null || die "could not delete Job $job"

k -n "$ns" delete secret argocd-redis --ignore-not-found >/dev/null || die "could not delete Secret argocd-redis"
log "deleted Secret argocd-redis"

# new_ready_pods <selector> <old UIDs> prints the UIDs of the Ready pods that are not old.
new_ready_pods() {
  k -n "$ns" get pods -l "$1" -o json | jq -r --arg old " $2 " '
    [.items[] | .metadata.uid as $uid | select(($old | contains(" " + $uid + " ")) | not)
      | select(any(.status.conditions[]?; .type == "Ready" and .status == "True")) | .metadata.uid] | join(" ")'
}
restarted=()
for name in argocd-redis argocd-repo-server argocd-agent-principal argocd-server; do
  selector="app.kubernetes.io/name=$name"
  old="$(k -n "$ns" get pods -l "$selector" -o jsonpath='{.items[*].metadata.uid}')"
  k -n "$ns" delete pods -l "$selector" --wait=true --timeout=120s >/dev/null || die "could not delete the pods of $name"
  end=$((SECONDS + 300))
  until uids="$(new_ready_pods "$selector" "$old")" && [[ -n "$uids" ]]; do
    if ((SECONDS >= end)); then
      log "read the events: mise x -- kubectl --context kind-$CELL_NAME -n $ns describe deployment/$name"
      die "deployment/$name in $ns has no new Ready pod after 300s"
    fi
    sleep 2
  done
  k -n "$ns" get secret argocd-redis >/dev/null 2>&1 || die "Secret argocd-redis is still missing after the restart of $name"
  log "restarted deployment/$name"
  restarted+=("deployment/$name")
done
printf '%s\n' "${restarted[@]}" | jq -Rnc --arg ns "$ns" '{namespace: $ns, restarted: [inputs]}'
