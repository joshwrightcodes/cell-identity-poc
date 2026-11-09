#!/usr/bin/env bash
# Set up the cell: create the cluster through the host service, apply the bootstrap set, publish
# the bundles, then wait until Argo CD reports every Application as Synced and Healthy at the
# published revision. In a cluster with SECRET_STORE_NAMESPACES, the wait also connects the secret
# store, or asks for secrets:connect in a second shell. Last, apply the harness components and wait
# for their rollouts.
source "$(dirname "$0")/lib.sh"

((${#COMPONENTS[@]} > 0)) || die "cell $CELL_NAME has no components in harness/topology.yaml"
log "creating cluster $CELL_NAME through the host service"
(cd "$ROOT" && mise run hostsvc -- up --only "$CELL_NAME")
k wait --for=condition=Ready nodes --all --timeout=300s >/dev/null \
  || die "the node of $CELL_NAME is not Ready after 300s. Read its state: mise x -- kubectl --context kind-$CELL_NAME describe nodes. Then run CELL=$CELL_NAME mise run cell:up again"

"$ROOT/scripts/facts.sh"
"$ROOT/scripts/hydrate.sh"

apply_bundle() {
  local file="$BUNDLES/$1/manifests.yaml"
  if ! k apply --server-side --force-conflicts -f "$file" >/dev/null 2>&1; then
    # A bundle can hold a CRD and an object of that kind. The first apply fails for that object.
    # Wait for the CRD, then apply again. The second apply shows any real error.
    k wait --for=condition=Established crd --all --timeout=120s >/dev/null
    k apply --server-side --force-conflicts -f "$file" >/dev/null
  fi
  log "applied bundle $1"
}

for c in "${BOOTSTRAP[@]}"; do
  apply_bundle "$c"
done
k -n cell-system rollout status statefulset/bundle-store --timeout=300s >/dev/null
k -n argocd rollout status deploy/argocd-repo-server --timeout=300s >/dev/null
k -n argocd rollout status statefulset/argocd-application-controller --timeout=300s >/dev/null
k apply --server-side -f "$ROOT/bootstrap/root.yaml" >/dev/null
log "applied the root Application"

"$ROOT/scripts/publish.sh"

# Every Application must report the revision that publish.sh pushed, so a check that runs before
# Argo CD reads the new root bundle cannot pass.
expected=$((${#COMPONENTS[@]} + 1))
published_json="$(jq -Rn '[inputs | select(length > 0) | split("=") | {(.[0]): .[1]}] | add' <"$PUBLISHED")"
apps_ready() {
  k -n argocd get applications -o json | jq -e --argjson n "$expected" --argjson pub "$published_json" '
    (.items | length) == $n and
    all(.items[]; .status.sync.status == "Synced" and .status.health.status == "Healthy"
      and .status.sync.revision == $pub[.metadata.name])'
}
log "waiting for $expected Applications to be Synced and Healthy at the published revisions"
end=$((SECONDS + 900))
store_done=0
last_hint=-60
until apps_ready >/dev/null 2>&1; do
  if [[ -n "${SECRET_STORE_NAMESPACES:-}" ]] && ((!store_done)) && app_healthy external-secrets; then
    connect_store_step "$ROOT/scripts/secrets-connect.sh"
  fi
  if ((SECONDS >= end)); then
    k -n argocd get applications
    die "Applications did not reach the published revisions, Synced and Healthy, in 900s"
  fi
  sleep 10
done
k -n argocd get applications

# release_from_argocd <bundle> removes what Argo CD left on the objects of a bundle that an Argo CD
# Application managed before: the tracking annotation and the argocd-controller field manager.
# The harness apply then owns every field. Objects without these leftovers stay unchanged.
release_from_argocd() {
  local obj kind name ns live patch scope
  while read -r obj; do
    kind="$(jq -r .kind <<<"$obj")" name="$(jq -r .name <<<"$obj")" ns="$(jq -r .ns <<<"$obj")"
    scope=()
    [[ -n "$ns" ]] && scope=(-n "$ns")
    live="$(k "${scope[@]}" get "$kind/$name" -o json --show-managed-fields 2>/dev/null)" || continue
    if jq -e '.metadata.annotations["argocd.argoproj.io/tracking-id"] != null' <<<"$live" >/dev/null; then
      k "${scope[@]}" annotate "$kind/$name" argocd.argoproj.io/tracking-id- >/dev/null
      log "removed the Argo CD tracking annotation from $kind/$name"
    fi
    if jq -e 'any(.metadata.managedFields[]?; .manager == "argocd-controller")' <<<"$live" >/dev/null; then
      patch="$(jq -c '[{op: "replace", path: "/metadata/managedFields",
        value: [.metadata.managedFields[] | select(.manager != "argocd-controller")]}]' <<<"$live")"
      k "${scope[@]}" patch "$kind/$name" --type=json -p "$patch" >/dev/null
      log "removed the argocd-controller field manager from $kind/$name"
    fi
  done < <(yq -o=json -I=0 'select(.kind != null) | {"kind": .kind, "name": .metadata.name, "ns": (.metadata.namespace // "")}' "$1")
}

# Harness components stay outside Argo CD. The harness applies them after the root bundle syncs,
# so no Application from an older root bundle still claims their objects. The apply does not
# prune: an object that leaves the bundle stays in the cluster. cell:verify reports a
# NetworkPolicy that the bundle does not hold.
for entry in ${HARNESS_COMPONENTS[@]+"${HARNESS_COMPONENTS[@]}"}; do
  apply_bundle "${entry%%:*}"
  release_from_argocd "$BUNDLES/${entry%%:*}/manifests.yaml"
done
for entry in ${HARNESS_COMPONENTS[@]+"${HARNESS_COMPONENTS[@]}"}; do
  ns="${entry#*:}"
  for deployment in $(k -n "$ns" get deployments -o name); do
    if ! k -n "$ns" rollout status "$deployment" --timeout=300s >/dev/null; then
      log "read the events: mise x -- kubectl --context kind-$CELL_NAME -n $ns describe $deployment"
      log "read the logs: mise x -- kubectl --context kind-$CELL_NAME -n $ns logs $deployment --all-containers"
      die "$deployment in $ns did not finish its rollout in 300s"
    fi
  done
  log "harness component ${entry%%:*} is rolled out"
done
log "cell $CELL_NAME is up. Run mise run cell:verify."
