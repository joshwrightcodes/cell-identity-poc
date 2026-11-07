#!/usr/bin/env bash
# Push each hydrated bundle to the in-cluster bundle store, then push a root bundle with one
# Argo CD Application per component. Each Application pins its bundle by digest.
# This script stands in for the worker, which publishes bundles in later milestones.
source "$(dirname "$0")/lib.sh"

[[ -d "$BUNDLES" ]] || die "no hydrated bundles: run mise run cell:hydrate first"
bundle_store_forward
local_store="127.0.0.1:${CELL_BUNDLE_STORE_PORT}"

root_dir="$BUILD/root"
rm -rf "$root_dir"
mkdir -p "$root_dir"

for entry in "${COMPONENTS[@]}"; do
  IFS=: read -r c wave ns <<<"$entry"
  digest="$(cd "$BUNDLES/$c" && oras push --plain-http --format json "$local_store/bundles/$c:current" . | jq -r .digest)"
  [[ "$digest" == sha256:* ]] || die "push of $c returned no digest"
  log "$c: $digest"

  app="$root_dir/$c.yaml"
  cat >"$app" <<EOF
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: $c
  namespace: argocd
  annotations:
    argocd.argoproj.io/sync-wave: "$wave"
spec:
  project: cell
  source:
    repoURL: oci://$BUNDLE_STORE_HOST/bundles/$c
    targetRevision: $digest
    path: .
  destination:
    server: https://kubernetes.default.svc
    namespace: $ns
  syncPolicy:
    automated:
      prune: true
      selfHeal: true
    syncOptions:
      - ServerSideApply=true
      - RespectIgnoreDifferences=true
EOF
  # A component can add fields to its Application spec, for example ignoreDifferences.
  extra="$ROOT/components/$c/application.yaml"
  if [[ -f "$extra" ]]; then
    yq -i ". *+ load(\"$extra\")" "$app"
  fi
done

digest="$(cd "$root_dir" && oras push --plain-http --format json "$local_store/bundles/root:current" . | jq -r .digest)"
log "root: $digest"
k -n argocd annotate application root argocd.argoproj.io/refresh=hard --overwrite >/dev/null
log "asked Argo CD to refresh the root Application"
