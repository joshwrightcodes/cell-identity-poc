#!/usr/bin/env bash
# Make new keys for the central view in management, then restart the pods that read them:
#   1. Run a copy of Job viewkeys with --rotate. It deletes the agent CA, the resource proxy
#      certificate, the agent JWT key, server.secretkey and each cluster Secret, and makes new ones.
#   2. Delete Secret argocd-redis. The secret-init container of argocd-redis makes a new password
#      when the pod starts again.
#   3. Restart argocd-redis, argocd-repo-server, the principal and argocd-server, in this order, and
#      wait for a new Ready pod of each.
# Standard output carries one JSON line with the restarted workloads. Agents in cells get new
# tokens when they connect again. Log lines go to standard error. One run may go at a time, and a
# run that stops goes on when it runs again.
source "$(dirname "$0")/lib.sh"

mkdir -p "$BUILD"
lock="$BUILD/.view-rotate.lock"
mkdir "$lock" 2>/dev/null || die "another view:rotate-keys runs, or one stopped and left $lock. When no run goes on, remove that directory and run the task again"
finished=0
on_exit() {
  rmdir "$lock" 2>/dev/null || true
  ((finished)) || log "view:rotate-keys stopped before its end. Run it again: mise run view:rotate-keys"
}
trap on_exit EXIT

ns=central-view-system
bundle="$BUNDLES/central-view/manifests.yaml"
[[ -f "$bundle" ]] || die "no $bundle. Run: CELL=$CELL_NAME mise run cell:link"
k -n "$ns" get job viewkeys >/dev/null 2>&1 || die "Job viewkeys is missing in $ns. Run: CELL=$CELL_NAME mise run cell:link"

job=viewkeys-rotate
k -n "$ns" delete job "$job" --ignore-not-found --wait=true --timeout=120s >/dev/null || die "could not delete the old Job $job in $ns"
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

restarted=()
for name in argocd-redis argocd-repo-server argocd-agent-principal argocd-server; do
  restart_deployment_pods "$ns" "$name"
  k -n "$ns" get secret argocd-redis >/dev/null 2>&1 || die "Secret argocd-redis is still missing after the restart of $name"
  log "restarted deployment/$name"
  restarted+=("deployment/$name")
done
finished=1
printf '%s\n' "${restarted[@]}" | jq -Rnc --arg ns "$ns" '{namespace: $ns, restarted: [inputs]}'
