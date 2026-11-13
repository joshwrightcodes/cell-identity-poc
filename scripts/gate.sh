#!/usr/bin/env bash
# Run the end-to-end tests of one milestone. Usage: gate.sh m1|m2|m3|m4|m4-rotate|m5 [go test arguments]
# m4-rotate runs the one test that rotates the signing key of mgmtd, with the checks of m4.
# The run fails when it takes longer than GATE_<MILESTONE>_BUDGET_MINUTES in harness/versions.env.
source "$(dirname "$0")/lib.sh"

cd "$ROOT"
source "$ROOT/harness/versions.env"
milestone="${1:?usage: gate.sh m1|m2|m3|m4|m4-rotate|m5 [go test arguments]}"
shift
pattern="$(echo "$milestone" | tr '[:lower:]' '[:upper:]')"
budget_var="GATE_${pattern//-/_}_BUDGET_MINUTES"
[[ "$milestone" != m4-rotate ]] || pattern="^TestRotationSigningKey$"
budget_minutes="${!budget_var:-}"

# The live gates need the build output of the checkout that set up the clusters: build/images.env, and build/<cluster>/ with
# the bundles, published.env and facts.env. A new worktree has none of it, so a test would fail late with another message.
if [[ "$milestone" != m1 ]]; then
  [[ -f "$BUILD_ROOT/images.env" ]] \
    || die "$BUILD_ROOT/images.env is missing. Run: mise run images, or copy it from the checkout that set up the clusters: cp <that checkout>/build/images.env $BUILD_ROOT/"
  for cluster in $(yq -r '.clusters[] | select(.components | length > 0) | .name' "$ROOT/harness/topology.yaml"); do
    [[ -d "$BUILD_ROOT/$cluster" ]] \
      || die "$BUILD_ROOT/$cluster is missing. Copy it from the checkout that set up the clusters: cp -R <that checkout>/build/$cluster $BUILD_ROOT/"
  done
fi

# Build the test binary first, so that the budget covers only the test run.
build_start=$SECONDS
go test -tags e2e -count=1 -run '^$' ./test/e2e/ >/dev/null || die "the end-to-end tests do not build"
log "gate $milestone build took $((SECONDS - build_start))s"

# The M2 tests run against the deployed SPIRE server, plugins and celld. First, an earlier run must
# have left no trace, because a bind would take the test key into the record of the cell. Then the
# renewal tests need SVIDs of 1m, and each workload must run the image that `mise run images`
# recorded, or the gate tests old code.
if [[ "$milestone" == m2 ]]; then
  "$ROOT/scripts/gate-m2-repair.sh" --check || exit 1
  ttl="$(kubectl --context kind-dev-cp -n spire-system get configmap spire-server -o jsonpath='{.data.server\.conf}' \
    | sed -n 's/^ *agent_ttl = "\(.*\)"$/\1/p')" || die "could not read the server config of dev-cp"
  [[ "$ttl" == 1m ]] || die "the SPIRE server in dev-cp sets agent_ttl '$ttl', and the renewal tests need 1m. Set SPIRE_SVID_TTL=1m in cells/dev-cp.env, then run: CELL=dev-cp mise run cell:up"
  stale=""
  topology="$ROOT/harness/topology.yaml"
  targets=()
  for cluster in $(yq -r '.clusters[] | select(.components[] == "spire-server") | .name' "$topology"); do
    targets+=("$cluster:spire-system:statefulset/spire-server")
  done
  for cluster in $(yq -r '.clusters[] | select(.components[] == "cell-identity") | .name' "$topology"); do
    targets+=("$cluster:cell-identity-system:deployment/celld")
  done
  for target in "${targets[@]}"; do
    IFS=: read -r cluster ns workload <<<"$target"
    found="$(live_image_mismatches "$cluster" "$ns" "$workload")" || die "could not read $workload in $cluster"
    [[ -z "$found" ]] || stale+="$found"$'\n'"Run: CELL=$cluster mise run cell:up"$'\n'
  done
  [[ -z "$stale" ]] || die "the deployed images differ from build/images.env:"$'\n'"$stale"
fi

# The M3 tests run against the plane servers and the workloads of every cluster. Each Deployment or
# StatefulSet that runs a local image must run the one that `mise run images` recorded, or the gate
# tests old code.
if [[ "$milestone" == m3 ]]; then
  # An earlier run that stopped before its cleanups can leave a grant for the test group in a cell.
  "$ROOT/scripts/gate-m3-repair.sh" --check || exit 1
  stale=""
  for cluster in $(yq -r '.clusters[] | select(.components | length > 0) | .name' "$ROOT/harness/topology.yaml"); do
    workloads="$(kubectl --context "kind-$cluster" get deployments,statefulsets -A -o json | jq -r '.items[]
      | select(any(.spec.template.spec | ((.initContainers // []) + .containers)[]; .image | startswith("localhost:5001/")))
      | "\(.metadata.namespace) \(.kind | ascii_downcase)/\(.metadata.name)"')" || die "could not list the workloads of $cluster"
    while read -r ns workload; do
      [[ -n "$ns" ]] || continue
      found="$(live_image_mismatches "$cluster" "$ns" "$workload")" || die "could not read $workload in $cluster"
      [[ -z "$found" ]] || stale+="$found"$'\n'"Run: CELL=$cluster mise run cell:up"$'\n'
    done <<<"$workloads"
  done
  [[ -z "$stale" ]] || die "the deployed images differ from build/images.env:"$'\n'"$stale"
fi

# The M4 tests run against mgmtd, envd, the SPIRE server of dev-cp, celld and the host service. An earlier
# run can leave the host service with another pin or root, or mgmtd or envd with no replica. Each of these
# workloads must run the images that `mise run images` recorded: mgmtd, envd, celld (with its agent plugin
# cluster-jwt-agent) and the SPIRE server (with its plugin cluster-jwt-server). The other workloads keep the
# digests that the M3 gate checks.
if [[ "$milestone" == m4 || "$milestone" == m4-rotate ]]; then
  "$ROOT/scripts/gate-m4-repair.sh" --check || exit 1
  stale=""
  targets=("management:mgmt-system:statefulset/mgmtd:mise run images -- mgmtd, then CELL=management LINK_ONLY=mgmt-api mise run cell:link"
    "dev-cp:envd-system:deployment/envd:mise run images -- envd, then CELL=dev-cp mise run cell:up"
    "dev-cp:spire-system:statefulset/spire-server:mise run images -- cluster-jwt-server, then CELL=dev-cp mise run cell:up")
  for cluster in $(yq -r '.clusters[] | select(.components[] == "cell-identity") | .name' "$ROOT/harness/topology.yaml"); do
    targets+=("$cluster:cell-identity-system:deployment/celld:mise run images -- celld cluster-jwt-agent, then CELL=$cluster mise run cell:up")
  done
  for target in "${targets[@]}"; do
    IFS=: read -r cluster ns workload fix <<<"$target"
    found="$(live_image_mismatches "$cluster" "$ns" "$workload")" || die "could not read $workload in $cluster"
    [[ -z "$found" ]] || stale+="$found"$'\n'"Run: $fix"$'\n'
  done
  [[ -z "$stale" ]] || die "the deployed images differ from build/images.env:"$'\n'"$stale"
fi

# The M5 tests run against mgmtd, envd, the cell gateway and the cells. An earlier run can leave a workload with no
# replica, or a test namespace. Each of these workloads must run the images that `mise run images` recorded.
if [[ "$milestone" == m5 ]]; then
  "$ROOT/scripts/gate-m5-repair.sh" --check || exit 1
  stale=""
  targets=("management:mgmt-system:statefulset/mgmtd:mise run images -- mgmtd, then CELL=management LINK_ONLY=mgmt-api mise run cell:link"
    "dev-cp:envd-system:deployment/envd:mise run images -- envd, then CELL=dev-cp mise run cell:up"
    "dev-cp:gateway-system:statefulset/cell-gateway:mise run images -- cellgw, then CELL=dev-cp mise run cell:up")
  for target in "${targets[@]}"; do
    IFS=: read -r cluster ns workload fix <<<"$target"
    found="$(live_image_mismatches "$cluster" "$ns" "$workload")" || die "could not read $workload in $cluster"
    [[ -z "$found" ]] || stale+="$found"$'\n'"Run: $fix"$'\n'
  done
  [[ -z "$stale" ]] || die "the deployed images differ from build/images.env:"$'\n'"$stale"
fi

# go test -json gives each test its own duration. The raw events stay in build/gate-<milestone>.json,
# and the text of the run goes to standard output as it does without -json.
mkdir -p "$BUILD_ROOT"
events="$BUILD_ROOT/gate-$milestone.json"
durations="$BUILD_ROOT/gate-$milestone-durations.txt"
start=$SECONDS
status=0
# The test timeout is twice the budget, with a floor of 30 minutes, so the budget check reports a
# slow run and the Go timeout never ends the run first.
test_timeout="$(gate_test_timeout "$budget_minutes")"
go test -tags e2e -count=1 -timeout "${test_timeout}m" -json ./test/e2e/ -run "$pattern" "$@" \
  | tee "$events" | jq -Rrj 'fromjson? | select(.Output != null) | .Output' || status=$?
elapsed=$((SECONDS - start))
log "gate $milestone tests took ${elapsed}s"
# The duration of each top-level test, slowest first.
jq -Rrn '[inputs | fromjson? | select(.Test != null and (.Test | contains("/") | not) and (.Action == "pass" or .Action == "fail"))
    | {test: .Test, action: .Action, elapsed: .Elapsed}] | sort_by(-.elapsed)[] | "\(.elapsed)s \(.action) \(.test)"' "$events" >"$durations" || true
log "the slowest tests of gate $milestone (every test is in $durations):"
head -n 12 "$durations" >&2

if [[ -n "$budget_minutes" ]] && ((elapsed > budget_minutes * 60)); then
  printf 'FAIL: gate %s took %ss, over the budget of %s minutes\n' "$milestone" "$elapsed" "$budget_minutes" >&2
  exit 1
fi
exit "$status"
