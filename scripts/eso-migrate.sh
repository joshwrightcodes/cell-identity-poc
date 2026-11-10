#!/usr/bin/env bash
# Move a live dev-cp from the cluster-scoped External Secrets Operator, with ClusterSecretStore
# poc-secrets, to the operator that works only in the store namespace, with SecretStore poc-secrets.
# The script is safe to run again. A run on a migrated cluster only checks and cleans up.
#   1. Preflight: the settings of secrets:connect, and the UIDs of the store namespace and of the
#      SPIRE datastore volume.
#   2. Guard the namespace: Prune=false,Delete=false through kubectl annotate, its own field
#      manager, read back before any other change. Without it, the spire-server Application can
#      prune the namespace, which it no longer holds, with the SPIRE server and its datastore.
#   3. Render and publish the bundles, then wait until Argo CD runs the published external-secrets
#      bundle and the scoped controller has rolled out. secrets:connect waits until then.
#   4. Run secrets:connect, then wait until every Application is at its published revision.
#   5. Check the result. 6. Delete what the old operator left: the token copy in external-secrets,
#      the ClusterSecretStore and its CRD. Argo CD prunes no CRD, because no CRD carries a tracking ID.
# On a failure after step 2 the script prints the commands that roll back.
# ESO_MIGRATE_SCRIPTS names another directory for hydrate, publish and secrets:connect, for the tests.
source "$(dirname "$0")/lib.sh"

scripts="${ESO_MIGRATE_SCRIPTS:-$ROOT/scripts}"
pvc=data-spire-server-0
annotation_key=argocd.argoproj.io/sync-options
annotation_value=Prune=false,Delete=false
read -r store_ns _ <<<"${SECRET_STORE_NAMESPACES:-}"
[[ -n "${store_ns:-}" ]] || die "cells/$CELL.env sets no SECRET_STORE_NAMESPACES, so $CELL has no secret store. Run: CELL=dev-cp mise run eso:migrate"

changed=0
rollback() {
  local status=$? pre
  ((status != 0)) || return 0
  if ((!changed)); then
    printf 'eso:migrate changed nothing. Fix the cause, then run: CELL=%s mise run eso:migrate\n' "$CELL_NAME" >&2
    return 0
  fi
  pre="$(git -C "$ROOT" log --format=%H -1 --grep='^Scope the secret operator to spire-system' 2>/dev/null)"
  pre="${pre:+$pre^}"
  cat >&2 <<EOF

To roll back to the cluster-scoped operator, keep the annotation on Namespace $store_ns and run:
  git -C "$ROOT" worktree add --detach "$ROOT-eso-rollback" ${pre:-<the parent of the commit "Scope the secret operator to spire-system">}
  cp "$ROOT/.envrc.local" "$ROOT-eso-rollback/.envrc.local"
  cd "$ROOT-eso-rollback" && mise trust && mise run images
  CELL=$CELL_NAME mise run cell:up
  CELL=$CELL_NAME mise run secrets:connect
  mise x -- kubectl --context kind-$CELL_NAME -n $store_ns delete secretstore $SECRET_STORE --ignore-not-found
  mise x -- kubectl --context kind-$CELL_NAME -n $store_ns delete secret poc-secrets-token --ignore-not-found
  CELL=$CELL_NAME mise run cell:verify
To try the migration again instead, fix the cause and run: CELL=$CELL_NAME mise run eso:migrate
EOF
}
trap rollback EXIT

# Step 1: preflight.
kubectl config get-contexts "kind-$CELL_NAME" -o name >/dev/null 2>&1 \
  || die "kubeconfig has no context kind-$CELL_NAME. A new cluster needs no migration. Run: CELL=$CELL_NAME mise run cell:up"
load_local_settings POC_SECRET_TOKEN_CMD POC_SECRET_STORE_PROVIDER
[[ -n "${POC_SECRET_TOKEN_CMD:-}" && -n "${POC_SECRET_STORE_PROVIDER:-}" ]] \
  || die "POC_SECRET_TOKEN_CMD and POC_SECRET_STORE_PROVIDER must be set, because the migration runs secrets:connect. Copy .envrc.local.example to .envrc.local and complete it. direnv loads .envrc.local after you run direnv allow, and this script reads it when a setting is unset"
ns_uid="$(k get namespace "$store_ns" -o jsonpath='{.metadata.uid}')" && [[ -n "$ns_uid" ]] \
  || die "the cluster has no Namespace $store_ns. A new cluster needs no migration. Run: CELL=$CELL_NAME mise run cell:up"
pvc_uid="$(k -n "$store_ns" get pvc "$pvc" -o jsonpath='{.metadata.uid}')" && [[ -n "$pvc_uid" ]] \
  || die "Namespace $store_ns has no PersistentVolumeClaim $pvc"
log "Namespace $store_ns has the UID $ns_uid, and PersistentVolumeClaim $pvc has the UID $pvc_uid"

# migrated succeeds when the ExternalSecret uses the namespaced store and is Ready, and the scoped
# controller runs.
migrated() {
  k -n "$store_ns" get externalsecret spire-upstream -o json 2>/dev/null | jq -e '
    .spec.secretStoreRef.kind == "SecretStore"
    and any(.status.conditions[]?; .type == "Ready" and .status == "True")' >/dev/null && eso_controller_rolled_out
}

# post_checks prints one line for each check that fails.
post_checks() {
  local got tracking roles
  got="$(k get namespace "$store_ns" -o jsonpath='{.metadata.uid}' 2>/dev/null)"
  [[ "$got" == "$ns_uid" ]] || echo "Namespace $store_ns has the UID '$got', not $ns_uid: it was deleted and created again"
  got="$(k -n "$store_ns" get pvc "$pvc" -o jsonpath='{.metadata.uid}' 2>/dev/null)"
  [[ "$got" == "$pvc_uid" ]] || echo "PersistentVolumeClaim $pvc has the UID '$got', not $pvc_uid: the SPIRE datastore is new"
  tracking="$(k get namespace "$store_ns" -o jsonpath='{.metadata.annotations.argocd\.argoproj\.io/tracking-id}' 2>/dev/null)"
  [[ "$tracking" == external-secrets:* ]] || echo "the tracking ID of Namespace $store_ns is '$tracking', not one of the Application external-secrets"
  k -n "$store_ns" get externalsecret spire-upstream -o json 2>/dev/null | jq -e '
    .spec.secretStoreRef.kind == "SecretStore" and any(.status.conditions[]?; .type == "Ready" and .status == "True")' >/dev/null \
    || echo "ExternalSecret $store_ns/spire-upstream does not use a SecretStore, or it is not Ready"
  roles="$(k get clusterroles,clusterrolebindings -o name 2>/dev/null | grep '/external-secrets' || true)"
  [[ -z "$roles" ]] || echo "the cluster still holds ${roles//$'\n'/ }"
  [[ "$(k auth can-i list secrets -A --as=system:serviceaccount:external-secrets:external-secrets 2>/dev/null)" == no ]] \
    || echo "the operator service account can still list Secrets in every namespace"
  [[ "$(k auth can-i get secrets -n "$store_ns" --as=system:serviceaccount:external-secrets:external-secrets 2>/dev/null)" == yes ]] \
    || echo "the operator service account cannot read Secrets in $store_ns"
  got="$(k -n "$store_ns" get pod spire-server-0 -o jsonpath='{.status.phase}' 2>/dev/null)"
  [[ "$got" == Running ]] || echo "pod $store_ns/spire-server-0 is '${got:-missing}', not Running"
}

# wait_until <seconds> <what> <command...>
wait_until() {
  local bound="$1" what="$2" end
  shift 2
  end=$((SECONDS + bound))
  log "waiting up to ${bound}s until $what"
  until "$@" >/dev/null 2>&1; do
    ((SECONDS < end)) || die "$what: not true after ${bound}s"
    sleep 5
  done
}

if migrated; then
  log "the cluster runs the scoped operator already. Only the checks and the cleanup run"
else
  # Step 2: the guard comes before every other change, and it must read back exactly.
  k annotate namespace "$store_ns" "$annotation_key=$annotation_value" --overwrite >/dev/null \
    || die "could not annotate Namespace $store_ns"
  got="$(k get namespace "$store_ns" -o jsonpath='{.metadata.annotations.argocd\.argoproj\.io/sync-options}')"
  [[ "$got" == "$annotation_value" ]] \
    || die "Namespace $store_ns has $annotation_key '$got' after the annotate, not '$annotation_value'. The migration stops before any other change"
  log "Namespace $store_ns carries $annotation_key=$annotation_value"
  changed=1

  # Step 3: publish, and wait for the scoped controller.
  "$scripts/hydrate.sh" || die "the render failed"
  "$scripts/publish.sh" || die "the publish failed"
  scoped_ready() { eso_published_synced && eso_controller_rolled_out; }
  wait_until 600 "Argo CD runs the published external-secrets bundle, and the controller scoped to $store_ns has rolled out" scoped_ready

  # Step 4: connect the namespaced store, then wait for every Application.
  "$scripts/secrets-connect.sh" || die "secrets:connect failed"
  wait_until 900 "every Application of $CELL_NAME is Synced and Healthy at its published revision" apps_at_published
fi

# Step 5: check the result.
problems="$(post_checks)"
if [[ -n "$problems" ]]; then
  printf '%s\n' "$problems" >&2
  changed=1
  die "the migration checks failed"
fi
log "Namespace and datastore kept their UIDs, the namespaced store serves spire-upstream, and the operator reads Secrets only in $store_ns"

# Step 6: clean up what the cluster-scoped operator used.
k -n external-secrets delete secret poc-secrets-token --ignore-not-found >/dev/null || die "could not delete Secret external-secrets/poc-secrets-token"
if k get crd clustersecretstores.external-secrets.io >/dev/null 2>&1; then
  k delete clustersecretstore "$SECRET_STORE" --ignore-not-found >/dev/null || die "could not delete ClusterSecretStore $SECRET_STORE"
  k delete crd clustersecretstores.external-secrets.io --ignore-not-found >/dev/null || die "could not delete the ClusterSecretStore CRD"
fi
log "deleted the token copy in external-secrets, ClusterSecretStore $SECRET_STORE and its CRD"
log "eso:migrate is complete. Run: mise run harness:verify"
