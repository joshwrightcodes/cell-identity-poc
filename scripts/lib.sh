# Shared helpers. Source this file; do not run it.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# POC_BUILD_ROOT names another build directory, for the tests.
BUILD_ROOT="${POC_BUILD_ROOT:-$ROOT/build}"

log() { printf '==> %s\n' "$*" >&2; }

die() { printf 'error: %s\n' "$*" >&2; exit 1; }

# CELL names the cluster. cells/common.env and cells/$CELL.env hold its settings.
CELL="${CELL:-dev-cell-1}"
[[ -f "$ROOT/cells/$CELL.env" ]] || die "unknown cell '$CELL'. Known cells: $(cd "$ROOT/cells" && ls *.env | sed -e 's/\.env$//' -e '/^common$/d' | paste -sd' ' -)"
set -a
source "$ROOT/cells/common.env"
source "$ROOT/cells/$CELL.env"
set +a
[[ "$CELL_NAME" == "$CELL" ]] || die "cells/$CELL.env sets CELL_NAME=$CELL_NAME"

BUILD="$BUILD_ROOT/$CELL"
BUNDLES="$BUILD/bundles"
FACTS="$BUILD/facts.env"
# publish.sh writes the digest of each bundle that it pushed here, one <name>=<digest> line each.
PUBLISHED="$BUILD/published.env"

# Component sets. Each set name in harness/topology.yaml maps to a list of bundles.
# Each entry is <component>:<sync wave>:<destination namespace>.
BASE_CELL_COMPONENTS=(
  "namespaces:-2:default"
  "argocd:-1:argocd"
  "cell-system:-1:cell-system"
  "network-policy:0:default"
  "istio-base:1:istio-system"
  "istio-cni:2:istio-system"
  "istiod:3:istio-system"
  "observability-system:3:observability-system"
  "istio-egress:4:istio-egress"
  "mesh-policy:4:istio-system"
  "apps-demo:5:apps-demo"
)

# The External Secrets Operator. It must be healthy, with its CRDs, before a later wave applies an ExternalSecret.
EXTERNAL_SECRETS_COMPONENTS=(
  "external-secrets:6:external-secrets"
)

# The SPIRE server of the environment trust domain. It comes last, after the base cell is healthy.
SPIRE_SERVER_COMPONENTS=(
  "spire-server:7:spire-system"
)

# Harness components. The harness renders and applies them itself, like the bootstrap set. They stay
# out of the root bundle and out of every Argo CD Application. A bundle can still write to their
# namespace, as the residual limits in docs/design/poc-scope.md say.
# Each entry is <component>:<namespace>. A harness component can share its namespace with the
# objects of a bundle. Every harness object carries the label HARNESS_LABEL=<component>, and
# cell:up, cell:restart and cell:verify act only on the labelled objects there.
# celld with its SPIRE agent sidecar attests to the SPIRE server in SPIRE_SERVER_CLUSTER.
CELL_IDENTITY_HARNESS=(
  "cell-identity:cell-identity-system"
)

# Link components. scripts/link.sh renders and applies them in the link phase, after every wave
# and harness component, because their render reads the live roots and node addresses of other
# clusters. They follow the harness rules: no Argo CD Application holds them, every object carries
# HARNESS_LABEL=<component>, and cell:verify and cell:restart act on the labelled objects.
# Each entry is <component>:<namespace>.
CENTRAL_VIEW_LINK=(
  "central-view:central-view-system"
)

# Read the component sets of $CELL from the topology. An unknown set name is an error.
COMPONENTS=()
HARNESS_COMPONENTS=()
LINK_COMPONENTS=()
set_names="$(yq -r ".clusters[] | select(.name == \"$CELL\") | .components[]" "$ROOT/harness/topology.yaml")"
for set_name in $set_names; do
  case "$set_name" in
    base-cell) COMPONENTS+=("${BASE_CELL_COMPONENTS[@]}") ;;
    external-secrets) COMPONENTS+=("${EXTERNAL_SECRETS_COMPONENTS[@]}") ;;
    spire-server) COMPONENTS+=("${SPIRE_SERVER_COMPONENTS[@]}") ;;
    cell-identity) HARNESS_COMPONENTS+=("${CELL_IDENTITY_HARNESS[@]}") ;;
    central-view) LINK_COMPONENTS+=("${CENTRAL_VIEW_LINK[@]}") ;;
    *) die "unknown component set '$set_name' for cell $CELL in harness/topology.yaml" ;;
  esac
done

# The bootstrap set. Bootstrap applies these bundles once, before Argo CD takes over.
BOOTSTRAP=(namespaces argocd cell-system)

BUNDLE_STORE_HOST="bundle-store.cell-system.svc.cluster.local:5000"

k() { kubectl --context "kind-$CELL_NAME" "$@"; }

# wait_for <description> <timeout seconds> <command...>
wait_for() {
  local what="$1" timeout="$2"; shift 2
  local end=$((SECONDS + timeout))
  until "$@" >/dev/null 2>&1; do
    ((SECONDS < end)) || die "timed out after ${timeout}s: $what"
    sleep 5
  done
}

# Start a port-forward to the bundle store. Sets BUNDLE_BUNDLE_STORE_PF_PID.
bundle_store_forward() {
  if curl -fsS "http://127.0.0.1:${CELL_BUNDLE_STORE_PORT}/v2/" >/dev/null 2>&1; then
    die "port ${CELL_BUNDLE_STORE_PORT} already serves a bundle store, probably from an old port-forward. Find its process with: lsof -nP -iTCP:${CELL_BUNDLE_STORE_PORT} -sTCP:LISTEN. Stop that process, then run the command again."
  fi
  # Call kubectl directly, not through k, so $! is the kubectl process that the trap kills.
  kubectl --context "kind-$CELL_NAME" -n cell-system port-forward svc/bundle-store "${CELL_BUNDLE_STORE_PORT}:5000" \
    >/dev/null 2>&1 &
  BUNDLE_STORE_PF_PID=$!
  trap 'kill "$BUNDLE_STORE_PF_PID" 2>/dev/null || true' EXIT
  wait_for "port-forward to the bundle store" 30 curl -fsS "http://127.0.0.1:${CELL_BUNDLE_STORE_PORT}/v2/"
}

source "$ROOT/scripts/gate-traces.sh"

# load_local_settings reads the gitignored .envrc.local when one of the given variables is unset.
# direnv loads the file after direnv allow, so this matters only without direnv. POC_ENVRC_LOCAL
# names another file, for the tests.
load_local_settings() {
  local file="${POC_ENVRC_LOCAL:-$ROOT/.envrc.local}" name
  for name in "$@"; do
    if [[ -z "${!name:-}" ]]; then
      [[ -f "$file" ]] || return 0
      # shellcheck source=/dev/null
      source "$file"
      log "read the settings from $file"
      return 0
    fi
  done
}

# SECRET_STORE is the name of the SecretStore that secrets:connect applies in each namespace of
# SECRET_STORE_NAMESPACES.
SECRET_STORE=poc-secrets

# store_gaps prints one line for each namespace of SECRET_STORE_NAMESPACES whose SecretStore is not
# Ready, and for each missing target Secret of an ExternalSecret that uses the store. It prints
# nothing when secrets:connect has nothing to do.
store_gaps() {
  local ns list target
  for ns in ${SECRET_STORE_NAMESPACES:-}; do
    k -n "$ns" get secretstore "$SECRET_STORE" -o json 2>/dev/null \
      | jq -e 'any(.status.conditions[]?; .type == "Ready" and .status == "True")' >/dev/null 2>&1 \
      || echo "SecretStore $ns/$SECRET_STORE is not Ready"
    list="$(k -n "$ns" get externalsecrets.external-secrets.io -o json 2>/dev/null)" || continue
    for target in $(jq -r --arg store "$SECRET_STORE" '.items[]
        | select(.spec.secretStoreRef.kind == "SecretStore" and .spec.secretStoreRef.name == $store)
        | .spec.target.name // .metadata.name' <<<"$list"); do
      k -n "$ns" get secret "$target" >/dev/null 2>&1 || echo "Secret $ns/$target is missing"
    done
  done
}

# live_image_mismatches <cluster> <namespace> <kind/name> prints one line for each local image of the
# workload that differs from build/images.env, and prints nothing when all match.
live_image_mismatches() {
  local cluster="$1" ns="$2" workload="$3" json images image name want
  json="$(kubectl --context "kind-$cluster" -n "$ns" get "$workload" -o json)" || return 1
  images="$(jq -r '.spec.template.spec | ((.initContainers // []) + .containers)[].image | select(startswith("localhost:5001/"))' <<<"$json")" || return 1
  for image in $images; do
    name="${image#localhost:5001/}"
    name="${name%%@*}"
    want="$(sed -n "s/^IMAGE_$(tr 'a-z-' 'A-Z_' <<<"$name")=//p" "$BUILD_ROOT/images.env" 2>/dev/null)"
    [[ -n "$want" && "$image" == "$want" ]] || echo "$workload in $cluster runs $image, and build/images.env has '${want:-nothing}' for $name"
  done
}

# APPS_NAMESPACE holds every child Application. The root Application stays in argocd.
APPS_NAMESPACE=argocd-apps

# apps_json prints the root Application from argocd and the child Applications from argocd-apps as
# one List.
apps_json() {
  local root children
  root="$(k -n argocd get applications -o json)" || return 1
  children="$(k -n "$APPS_NAMESPACE" get applications -o json)" || return 1
  jq -n --argjson r "$root" --argjson c "$children" '{items: ($r.items + $c.items)}'
}

# apps_at_published succeeds when Argo CD reports every Application of the cluster Synced and
# Healthy at the revision that publish.sh pushed. The root Application is in argocd and has no
# sibling there. A check that runs before Argo CD reads the new root bundle cannot pass.
apps_at_published() {
  local published_json root children
  published_json="$(jq -Rn '[inputs | select(length > 0) | split("=") | {(.[0]): .[1]}] | add' <"$PUBLISHED")" || return 1
  root="$(k -n argocd get applications -o json)" || return 1
  children="$(k -n "$APPS_NAMESPACE" get applications -o json)" || return 1
  jq -n -e --argjson root "$root" --argjson children "$children" --argjson n "${#COMPONENTS[@]}" --argjson pub "$published_json" '
    ($root.items | map(.metadata.name)) == ["root"] and ($children.items | length) == $n and
    all($root.items[], $children.items[]; .status.sync.status == "Synced" and .status.health.status == "Healthy"
      and .status.sync.revision == $pub[.metadata.name])' >/dev/null
}

# eso_controller_rolled_out succeeds when the operator Deployment runs only pods of its current
# spec, and that spec scopes the controller to the store namespace. Until then a controller of an
# older bundle, which ignores SecretStore objects, can still serve.
eso_controller_rolled_out() {
  local store_ns
  read -r store_ns _ <<<"${SECRET_STORE_NAMESPACES:-}"
  [[ -n "$store_ns" ]] || return 1
  k -n external-secrets get deployment external-secrets -o json 2>/dev/null | jq -e --arg arg "--namespace=$store_ns" '
    (.spec.replicas // 1) as $want
    | (.status.observedGeneration // 0) == .metadata.generation
      and (.status.replicas // 0) == $want and (.status.updatedReplicas // 0) == $want
      and (.status.availableReplicas // 0) == $want
      and any(.spec.template.spec.containers[].args[]?; . == $arg)' >/dev/null
}

# eso_published_synced succeeds when Argo CD reports the Application external-secrets Synced and
# Healthy at the digest that the last cell:publish recorded in build/<cluster>/published.env.
eso_published_synced() {
  local want
  want="$(sed -n 's/^external-secrets=//p' "$PUBLISHED" 2>/dev/null)"
  [[ -n "$want" ]] || return 1
  k -n "$APPS_NAMESPACE" get application external-secrets -o json 2>/dev/null | jq -e --arg want "$want" '
    .status.sync.status == "Synced" and .status.health.status == "Healthy" and .status.sync.revision == $want' >/dev/null
}

# connect_store_step <secrets:connect script> waits until the published operator bundle is synced
# and its scoped controller has rolled out. Then it runs secrets:connect once when the secret store
# has a gap and POC_SECRET_TOKEN_CMD is set. Without that setting, it asks for secrets:connect in a
# second shell, once a minute. It sets store_done when the store has no gap.
connect_store_step() {
  local gaps
  eso_published_synced && eso_controller_rolled_out || return 0
  gaps="$(store_gaps)"
  if [[ -z "$gaps" ]]; then
    store_done=1
    log "the secret store of $CELL_NAME is connected"
    return 0
  fi
  if [[ -n "${POC_SECRET_TOKEN_CMD:-}" ]]; then
    log "running secrets:connect, because: ${gaps//$'\n'/; }"
    "$1" || die "secrets:connect failed. Fix the cause, then run: CELL=$CELL_NAME mise run secrets:connect"
    store_done=1
  elif ((SECONDS - last_hint >= 60)); then
    log "${gaps//$'\n'/; }. Run in a second shell: CELL=$CELL_NAME mise run secrets:connect"
    last_hint=$SECONDS
  fi
}

# Harness and link objects carry this label, with the name of their component as the value.
HARNESS_LABEL=cell.poc.internal/harness

# fix_command <component> prints the command that renders and applies a component again: cell:link
# for a link component, cell:up for every other one.
fix_command() {
  local entry
  for entry in ${LINK_COMPONENTS[@]+"${LINK_COMPONENTS[@]}"}; do
    [[ "${entry%%:*}" == "$1" ]] && { echo "CELL=$CELL_NAME mise run cell:link"; return; }
  done
  echo "CELL=$CELL_NAME mise run cell:up"
}

# link_preflight prints one line for each cluster that the link phase of $CELL needs and that does
# not answer: the environment control plane VIEW_CONTROL_PLANE with its SPIRE server, and each cell
# of VIEW_CELLS. It prints nothing when the link phase can run, or when the cluster has none.
link_preflight() {
  local c
  ((${#LINK_COMPONENTS[@]} > 0)) || return 0
  for c in ${VIEW_CONTROL_PLANE:-} ${VIEW_CELLS:-}; do
    if ! (cd "$ROOT" && mise run hostsvc -- facts --cluster "$c" >/dev/null 2>&1); then
      echo "cluster $c does not exist. Create it: CELL=$c mise run cell:up"
    elif [[ "$c" == "${VIEW_CONTROL_PLANE:-}" ]] \
      && ! kubectl --context "kind-$c" -n spire-system get pod spire-server-0 -o jsonpath='{.status.phase}' 2>/dev/null | grep -qx Running; then
      echo "the SPIRE server of $c does not run. Run: CELL=$c mise run cell:up"
    fi
  done
}

# restart_deployment_pods <namespace> <deployment> deletes the pods of a Deployment and waits for a
# new Ready pod. It changes no field of the Deployment, so its field managers stay the same.
restart_deployment_pods() {
  local ns="$1" name="$2" selector old uids end
  selector="$(k -n "$ns" get deployment "$name" -o json | jq -r '.spec.selector.matchLabels | to_entries | map("\(.key)=\(.value)") | join(",")')"
  [[ -n "$selector" ]] || die "deployment/$name in $ns has no label selector"
  old="$(k -n "$ns" get pods -l "$selector" -o jsonpath='{.items[*].metadata.uid}')"
  k -n "$ns" delete pods -l "$selector" --wait=true --timeout=120s >/dev/null || die "could not delete the pods of deployment/$name in $ns"
  end=$((SECONDS + 300))
  until uids="$(k -n "$ns" get pods -l "$selector" -o json | jq -r --arg old " $old " '
      [.items[] | .metadata.uid as $uid | select(($old | contains(" " + $uid + " ")) | not)
        | select(any(.status.conditions[]?; .type == "Ready" and .status == "True")) | .metadata.uid] | join(" ")')" \
      && [[ -n "$uids" ]]; do
    if ((SECONDS >= end)); then
      log "read the events: mise x -- kubectl --context kind-$CELL_NAME -n $ns describe deployment/$name"
      die "deployment/$name in $ns has no new Ready pod after 300s"
    fi
    sleep 2
  done
}

# harness_workloads <component> <namespace> prints the Deployments and StatefulSets of a harness
# component, as <kind>.apps/<name>. Other workloads in the namespace belong to a bundle. The live
# workloads with the harness label must be exactly the ones that the bundle of the component
# renders in the namespace, so a lost label or a failed API call stops the caller. The output of
# die ends only a command substitution, so call it as: list="$(harness_workloads c ns)" || exit 1
harness_workloads() {
  local comp="$1" ns="$2" bundle="$BUNDLES/$1/manifests.yaml" live want
  [[ -f "$bundle" ]] || die "no $bundle. Run: $(fix_command "$comp")"
  live="$(k -n "$ns" get deployments,statefulsets -l "$HARNESS_LABEL=$comp" -o name)" \
    || die "could not list the Deployments and StatefulSets of $comp in $ns"
  live="$(sed '/^$/d' <<<"$live" | sort)"
  want="$(NS="$ns" yq -N 'select((.kind == "Deployment" or .kind == "StatefulSet") and .metadata.namespace == strenv(NS))
    | (.kind | downcase) + ".apps/" + .metadata.name' "$bundle" | sed '/^$/d' | sort)"
  [[ "$live" == "$want" ]] || die "$ns holds the workloads '${live//$'\n'/ }' with the label $HARNESS_LABEL=$comp, and the bundle $comp renders '${want//$'\n'/ }'. Run: $(fix_command "$comp")"
  printf '%s\n' "$live"
}

# harness_rollout_wait <component> <namespace> waits for the rollout of each Deployment and
# StatefulSet of a harness component.
harness_rollout_wait() {
  local workload workloads
  workloads="$(harness_workloads "$1" "$2")" || exit 1
  for workload in $workloads; do
    if ! k -n "$2" rollout status "$workload" --timeout=300s >/dev/null; then
      log "read the events: mise x -- kubectl --context kind-$CELL_NAME -n $2 describe $workload"
      log "read the logs: mise x -- kubectl --context kind-$CELL_NAME -n $2 logs $workload --all-containers"
      die "$workload in $2 did not finish its rollout in 300s"
    fi
  done
}

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

# release_from_argocd <bundle> removes what Argo CD left on the objects of a bundle that an Argo CD
# Application managed before: the tracking annotation and the argocd-controller field manager.
# The harness apply then owns every field. Objects without these leftovers stay unchanged.
# harness_conflicts runs first, so a tracking annotation here names an Application that the
# current root no longer holds.
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

# harness_conflicts <component> prints one line for each live object of the bundle of a harness
# component that another owner holds: an Argo CD Application of the current root, another harness
# or link component, or an owner reference. It prints nothing when the harness may apply the bundle.
harness_conflicts() {
  local comp="$1" bundle="$BUNDLES/$1/manifests.yaml" live apps
  [[ -f "$bundle" ]] || { echo "no $bundle. Run: $(fix_command "$comp")"; return 1; }
  live="$(k get -f "$bundle" -o json --ignore-not-found)" || { echo "could not read the live objects of the bundle $comp"; return 1; }
  apps="$(printf '%s\n' root ${COMPONENTS[@]+"${COMPONENTS[@]%%:*}"} | jq -Rn '[inputs]')"
  jq -r --arg comp "$comp" --arg label "$HARNESS_LABEL" --argjson apps "$apps" '
    (if .kind == "List" then .items[] else . end)
    | ((.metadata.annotations["argocd.argoproj.io/tracking-id"] // "") | split(":")[0] // "" | sub("^argocd-apps_"; "")) as $app
    | (.metadata.labels[$label] // "") as $owner
    | ([(.metadata.ownerReferences // [])[] | "\(.kind)/\(.name)"] | join(", ")) as $refs
    | "\(.kind)/\(.metadata.name)\(if .metadata.namespace then " in " + .metadata.namespace else "" end)" as $o
    | if $app != "" and ($apps | index($app)) != null then "\($o) belongs to the Argo CD Application \($app)"
      elif $owner != "" and $owner != $comp then "\($o) carries the label \($label)=\($owner)"
      elif $refs != "" then "\($o) has the owner \($refs)"
      else empty end' <<<"$live"
}

# harness_apply <component> applies the bundle of a harness component. It stops before the apply
# when another owner holds one of its objects, because a server-side apply with force would take
# that object, and its owner would then take it back on each sync.
harness_apply() {
  local conflicts
  conflicts="$(harness_conflicts "$1")" || die "$conflicts"
  [[ -z "$conflicts" ]] || die "the harness component $1 renders objects that another owner holds:"$'\n'"$conflicts"$'\n'"Rename the object in the harness render or remove it from the other owner, so that one owner holds it. Then run: $(fix_command "$1")"
  apply_bundle "$1"
  release_from_argocd "$BUNDLES/$1/manifests.yaml"
}

# has_component_entry <component> <namespace> succeeds when the cluster has that harness or link
# component in that namespace.
has_component_entry() {
  local entry
  for entry in ${HARNESS_COMPONENTS[@]+"${HARNESS_COMPONENTS[@]}"} ${LINK_COMPONENTS[@]+"${LINK_COMPONENTS[@]}"}; do
    [[ "$entry" == "$1:$2" ]] && return 0
  done
  return 1
}

# check_plane_pods checks each pod that runs as a ServiceAccount of SPIRE_LOCAL_WORKLOADS. k8s_psat
# gives such a pod the plane SVID, and a pod label is not an identity. So the pod must carry the
# harness label of a harness or link component in its namespace, and its controller (through its
# ReplicaSet) must be a Deployment or StatefulSet that the bundle of that component renders there.
check_plane_pods() {
  local w sub ns sa pods sets pod comp kind name problems=()
  for w in ${SPIRE_LOCAL_WORKLOADS:-}; do
    sub="${w#*=}" ns="${sub%%/*}" sa="${sub#*/}"
    pods="$(k -n "$ns" get pods -o json 2>/dev/null)" || pods='{"items":[]}'
    sets="$(k -n "$ns" get replicasets -o json 2>/dev/null)" || sets='{"items":[]}'
    while IFS='|' read -r pod comp kind name; do
      [[ -n "$pod" ]] || continue
      if [[ -z "$comp" ]] || ! has_component_entry "$comp" "$ns"; then
        problems+=("pod $ns/$pod runs as $sa, and carries no $HARNESS_LABEL of a harness or link component in $ns (label '${comp}')")
      elif [[ "$kind" != Deployment && "$kind" != StatefulSet ]] \
        || ! KIND="$kind" NAME="$name" NS="$ns" yq -e 'select(.kind == strenv(KIND) and .metadata.name == strenv(NAME) and .metadata.namespace == strenv(NS))' \
          "$BUNDLES/$comp/manifests.yaml" >/dev/null 2>&1; then
        problems+=("pod $ns/$pod runs as $sa, and its controller '${kind}/${name}' is no workload of the bundle $comp in $ns")
      fi
    done < <(jq -r --arg sa "$sa" --arg label "$HARNESS_LABEL" --argjson sets "$sets" '
      ($sets.items | map({key: .metadata.name,
        value: ([(.metadata.ownerReferences // [])[] | select(.controller == true)][0] // {kind: "", name: ""})}) | from_entries) as $owners
      | .items[] | select(.spec.serviceAccountName == $sa)
      | ([(.metadata.ownerReferences // [])[] | select(.controller == true)][0] // {kind: "", name: ""}) as $o
      | (if $o.kind == "ReplicaSet" then ($owners[$o.name] // {kind: "", name: ""}) else $o end) as $w
      | [.metadata.name, (.metadata.labels[$label] // ""), $w.kind, $w.name] | join("|")' <<<"$pods")
  done
  if ((${#problems[@]} > 0)); then
    printf '%s\n' "${problems[@]}"
    echo "Delete each pod above and the workload that made it. Only the harness may run a plane ServiceAccount."
    return 1
  fi
}

# check_harness_objects <component> <namespace> compares the namespace with the bundle of a harness
# or link component. The harness apply does not prune, and kubectl diff sees only the fields of
# its own field manager. Each object of the bundle must have only the field manager kubectl, and
# kube-controller-manager for status.
#   - When the bundle holds the Namespace, the component owns it: for each kind that the bundle
#     holds in the namespace, the namespace must hold exactly the objects of the bundle, apart from
#     objects that only system controllers write, for example kube-root-ca.crt. The Namespace must
#     have only kubectl.
#   - Otherwise the namespace is shared with a bundle, whose Application owns the Namespace and its
#     own objects. For each kind, the objects with the harness label of the component must be
#     exactly the objects of the bundle in the namespace.
#   - For each cluster-scoped kind of the bundle, Namespace included, the objects with the harness
#     label of the component must be exactly the objects of the bundle. A list of a cluster-scoped
#     kind holds the objects of every owner, so only the label tells them apart.
check_harness_objects() {
  local comp="$1" ns="$2" bundle="$BUNDLES/$1/manifests.yaml" kind want got live bad owned problems=()
  [[ -f "$bundle" ]] || { echo "no $bundle. Run: $(fix_command "$comp")"; return 1; }
  owned="$(NS="$ns" yq -N 'select(.kind == "Namespace" and .metadata.name == strenv(NS)) | .metadata.name' "$bundle")"
  # managers_of <live list> <names> prints each field manager of the named objects other than
  # kubectl Apply and the status of kube-controller-manager.
  managers_of() {
    jq -r --arg want " $2 " '.items[] | .metadata.name as $name | select($want | contains(" " + $name + " "))
      | . as $o | $o.metadata.managedFields[]? | select((.manager == "kubectl" and .operation == "Apply")
        or (.manager == "kube-controller-manager" and .subresource == "status") | not)
      | "\($o.kind)/\($name) has the field manager \(.manager) (\(.operation) \(.subresource // "object"))"' <<<"$1"
  }
  for kind in $(NS="$ns" yq -N -r 'select(.kind != null and .metadata.namespace == strenv(NS)) | .kind' "$bundle" | sort -u); do
    want="$(KIND="$kind" NS="$ns" yq -o=json -I=0 'select(.kind == strenv(KIND) and .metadata.namespace == strenv(NS)) | .metadata.name' "$bundle" | jq -rs 'sort | join(" ")')"
    live="$(k -n "$ns" get "$kind" -o json --show-managed-fields)" || { echo "could not list $kind in $ns"; return 1; }
    if [[ -n "$owned" ]]; then
      got="$(jq -r --arg label "$HARNESS_LABEL" '[.items[]
        | select((.metadata.labels[$label] // "") != ""
          or any(.metadata.managedFields[]?; .manager != "kube-controller-manager" and .manager != "pilot-discovery"))
        | .metadata.name] | sort | join(" ")' <<<"$live")" || { echo "could not read the $kind objects in $ns"; return 1; }
      [[ "$got" == "$want" ]] || problems+=("$ns has the $kind objects '$got' that the harness or a person wrote, and the bundle $comp has '$want'")
    else
      got="$(jq -r --arg label "$HARNESS_LABEL" --arg comp "$comp" '[.items[]
        | select(.metadata.labels[$label] == $comp) | .metadata.name] | sort | join(" ")' <<<"$live")" \
        || { echo "could not read the $kind objects in $ns"; return 1; }
      [[ "$got" == "$want" ]] || problems+=("$ns has the $kind objects '$got' with the label $HARNESS_LABEL=$comp, and the bundle $comp has '$want'")
    fi
    bad="$(managers_of "$live" "$want")" || { echo "could not read the field managers of $kind in $ns"; return 1; }
    [[ -z "$bad" ]] || problems+=("$bad")
  done
  for kind in $(yq -N -r 'select(.kind != null and (.metadata.namespace // "") == "") | .kind' "$bundle" | sort -u); do
    want="$(KIND="$kind" yq -o=json -I=0 'select(.kind == strenv(KIND) and (.metadata.namespace // "") == "") | .metadata.name' "$bundle" | jq -rs 'sort | join(" ")')"
    live="$(k get "$kind" -l "$HARNESS_LABEL=$comp" -o json --show-managed-fields)" || { echo "could not list $kind with the label $HARNESS_LABEL=$comp"; return 1; }
    got="$(jq -r '[.items[].metadata.name] | sort | join(" ")' <<<"$live")" || { echo "could not read the $kind objects"; return 1; }
    [[ "$got" == "$want" ]] || problems+=("the cluster has the $kind objects '$got' with the label $HARNESS_LABEL=$comp, and the bundle $comp has '$want'")
    bad="$(managers_of "$live" "$want")" || { echo "could not read the field managers of $kind"; return 1; }
    [[ -z "$bad" ]] || problems+=("$bad")
  done
  if [[ -n "$owned" ]]; then
    live="$(k get namespace "$ns" -o json --show-managed-fields)" || { echo "no namespace $ns"; return 1; }
    bad="$(jq -r --arg ns "$ns" '.metadata.managedFields[]? | select(.manager == "kubectl" and .operation == "Apply" | not)
      | "Namespace/\($ns) has the field manager \(.manager)"' <<<"$live")" \
      || { echo "could not read the field managers of $ns"; return 1; }
    [[ -z "$bad" ]] || problems+=("$bad")
  fi
  if ((${#problems[@]} > 0)); then
    printf '%s\n' "${problems[@]}"
    echo "Delete each extra object, and each field that another manager added. Then run: $(fix_command "$comp")"
    return 1
  fi
}
