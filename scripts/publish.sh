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
published="$(mktemp "$BUILD/.published.env.XXXXXX")"
trap 'rm -f "$published"; kill "$BUNDLE_STORE_PF_PID" 2>/dev/null || true' EXIT

for entry in "${COMPONENTS[@]}"; do
  IFS=: read -r c wave ns <<<"$entry"
  digest="$(cd "$BUNDLES/$c" && oras push --plain-http --format json "$local_store/bundles/$c:current" . | jq -r .digest)"
  [[ "$digest" == sha256:* ]] || die "push of $c returned no digest"
  log "$c: $digest"
  printf '%s=%s\n' "$c" "$digest" >>"$published"

  app="$root_dir/$c.yaml"
  cat >"$app" <<EOF
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: $c
  namespace: argocd-apps
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

# A harness component has no bundle in the store. The store may still hold one from a time when
# an Application managed the component. Delete its tagged manifests, so that no older root bundle
# can bring that Application back. The store frees the blobs only at a garbage collection.
for entry in ${HARNESS_COMPONENTS[@]+"${HARNESS_COMPONENTS[@]}"}; do
  repo="$local_store/bundles/${entry%%:*}"
  for tag in $(oras repo tags --plain-http "$repo" 2>/dev/null); do
    old="$(oras resolve --plain-http "$repo:$tag")" || die "could not resolve $repo:$tag"
    oras manifest delete --plain-http --force "$repo@$old" >/dev/null || die "could not delete $repo@$old"
    log "deleted the old bundle ${entry%%:*}:$tag ($old) from the store"
  done
done

digest="$(cd "$root_dir" && oras push --plain-http --format json "$local_store/bundles/root:current" . | jq -r .digest)"
[[ "$digest" == sha256:* ]] || die "push of root returned no digest"
log "root: $digest"
printf 'root=%s\n' "$digest" >>"$published"
mv "$published" "$PUBLISHED"
k -n argocd annotate application root argocd.argoproj.io/refresh=hard --overwrite >/dev/null
log "asked Argo CD to refresh the root Application"
