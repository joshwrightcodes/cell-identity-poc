#!/usr/bin/env bash
# Push each hydrated bundle to the in-cluster bundle store, then push a root bundle with one
# Argo CD Application per component. Each Application pins its bundle by digest, and reads it from
# the token client in the repo server pod (oci://127.0.0.1:5000).
# This script stands in for the worker, which publishes signed bundle sets in the clusters with role cell
# or cp. It pushes to the registry through a port-forward to the loopback port of the pod, behind the token
# proxy, so it needs no token. A cluster with role cell or cp gets its bundles and its root from
# `bundlectl bootstrap`, which writes the result to build/<cluster>/root.json. A cluster with role open
# (management) gets the same objects from oras and the Application files below, and no root.json.
source "$(dirname "$0")/lib.sh"

[[ -d "$BUNDLES" ]] || die "no hydrated bundles: run mise run cell:hydrate first"
role="$(bundle_role)" || exit 1
bundle_store_forward
local_store="127.0.0.1:${CELL_BUNDLE_STORE_PORT}"

published="$(mktemp "$BUILD/.published.env.XXXXXX")"
trap 'rm -f "$published"; kill "$BUNDLE_STORE_PF_PID" 2>/dev/null || true' EXIT

# publish_signed_role pushes the bundles and the root through bundlectl, and sets digest to the digest of the root.
publish_signed_role() {
  local result entry c d
  result="$(mise run bundlectl -- bootstrap --role "$role" --target "$CELL_NAME" --registry "$local_store" \
    --build "$BUILD_ROOT" --root "$ROOT" "${COMPONENTS[@]}")" || die "bundlectl bootstrap failed: $result"
  digest="$(jq -er '.digest' <<<"$result")" || die "bundlectl bootstrap returned no root digest"
  [[ "$digest" == sha256:* ]] || die "bundlectl bootstrap returned the root digest '$digest'"
  # The result holds the digests and the root manifest.
  printf '%s\n' "$result" >"$BUILD/root.json"
  for entry in "${COMPONENTS[@]}"; do
    c="${entry%%:*}"
    d="$(jq -er --arg c "$c" '.components[$c]' <<<"$result")" || die "bundlectl bootstrap returned no digest for $c"
    log "$c: $d"
    printf '%s=%s\n' "$c" "$d" >>"$published"
  done
}

# publish_open_role pushes the bundles with oras, writes one Application for each, and sets digest to the digest of the root.
publish_open_role() {
  local entry c wave ns d app extra root_dir="$BUILD/root"
  rm -rf "$root_dir"
  mkdir -p "$root_dir"
  for entry in "${COMPONENTS[@]}"; do
    IFS=: read -r c wave ns <<<"$entry"
    d="$(cd "$BUNDLES/$c" && oras push --plain-http --format json "$local_store/bundles/$c:current" . | jq -r .digest)"
    [[ "$d" == sha256:* ]] || die "push of $c returned no digest"
    log "$c: $d"
    printf '%s=%s\n' "$c" "$d" >>"$published"

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
    targetRevision: $d
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
  [[ "$digest" == sha256:* ]] || die "push of root returned no digest"
}

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

digest=""
if [[ "$role" == open ]]; then publish_open_role; else publish_signed_role; fi
log "root: $digest"
printf 'root=%s\n' "$digest" >>"$published"
mv "$published" "$PUBLISHED"
k -n argocd annotate application root argocd.argoproj.io/refresh=hard --overwrite >/dev/null
log "asked Argo CD to refresh the root Application"
