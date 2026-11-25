#!/usr/bin/env bash
# Run the end-to-end tests of one milestone. Usage: gate.sh m1|m2|m3|m4|m4-rotate|m5|m5-soak|m5-drill|m6|m6-provision|m7|m8|m9|m15 [go test arguments]
# m4-rotate runs the one test that rotates the signing key of mgmtd, with the checks of m4.
# m5-soak runs the one test that applies an operation each minute for 30 minutes on the open streams.
# m5-drill runs the one test that loses the gateway volume with work in flight, and recovers it with gw:reset.
# m6 runs gate-m6-repair.sh --check and the image check of mgmtd, envd, the cell controller, the cell gateway and the SPIRE server first.
# m6-provision runs the one test that deletes both cells and creates them again through the portal, after the same checks. It is not
# part of m6, because it deletes the cells. An interrupted run leaves build/gate/m6-provision, and mise run gate:m6:repair restores the cells.
# m7 runs gate-m6-repair.sh --check, gate-m7-repair.sh --check and the image check of m6 with celld added, because M7 tests run the celld bind client and the cell-proxy images.
# m8 runs gate-m6-repair.sh --check, gate-m7-repair.sh --check, gate-m8-repair.sh --check and the image check of m7, with cell-proxy of bundle-store-0 and argocd-repo-server in
# dev-cp and in each live cell added, then the tests with -short, which skips the long tests, unless GATE_M8_LONG=1. A run whose tests pass removes
# build/gate/m8-bundles, the record of the targets that a test changed. A failed run keeps it, and gate-m8-repair.sh --check then fails.
# After the tests, m5, m5-soak, m5-drill, m6, m6-provision, m7 and m8 scan the logs of the M5 components since the start for a token (scripts/gate-token-scan.sh).
# Every gate runs under keep_awake, refuses battery power, and prints the Sleep and DarkWake lines of pmset -g log since its start.
# m15 runs the checks of m6 to m8, gate-m15-repair.sh --check (which runs gate-m9-repair.sh --check first) and the image check of m8 with the
# container agent-ban in spire-server-0 of dev-cp. The image check covers cluster-jwt-server.
# It then runs the tests that match ^TestM15, and scans the logs of the M5 components for a token afterwards.
# m9 runs the slow tier of "The slow tier" in the M9 plan. Phase 0: gate-m6-repair.sh, gate-m7-repair.sh,
# gate-m8-repair.sh and gate-m9-repair.sh with --check, the image check of m8 with agent-ban in spire-server-0 of dev-cp, cell-proxy of the
# mesh-view tunnel in each cell and the three cell-proxy servers of management added, svid-ttl.sh set at the slow-tier lifetime, and a token
# scan from the start of the gate. Then each M9 test in its own go test invocation with -failfast, its own events file build/gate-m9-<test>.json and a token scan from its own start. It
# stops at the first failure. With -run in the go test arguments, it runs one invocation with that pattern (events in build/gate-m9-run.json).
# Phase 7 runs from an EXIT trap, also after a failure or an interrupt: the token scan of a step that did not end, svid-ttl.sh restore when the
# switch ran or the marker or build/gate/m9-svid-ttl.restoring exists, and harness:status. The lifetime is GATE_M9_SVID_TTL from the environment when set, else from harness/versions.env. A lifetime equal to
# cells/dev-cp.env skips the switch and the restore. A run with -run, or at a lifetime other than the one in harness/versions.env, prints
# "not a slow-tier record". The -timeout of each invocation is GATE_M9_TEST_TIMEOUT_MINUTES as it stands, and the budget covers Phases 0 to 7.
# Every other milestone refuses while build/gate/m9-svid-ttl exists, or while the live agent_ttl of dev-cp differs from cells/dev-cp.env.
# The run fails when it takes longer than GATE_<MILESTONE>_BUDGET_MINUTES in harness/versions.env.
source "$(dirname "$0")/lib.sh"

# On macOS every gate runs again under keep_awake, and it does not start on battery power. A sleep of the Mac stops the VM and every cluster.
keep_awake "$@"
refuse_battery
gate_clock_start="$(date '+%Y-%m-%d %H:%M:%S')"
# gate_sleep_exit prints the sleeps that pmset recorded since the start, after a pass and after a failure.
gate_sleep_exit() {
  local rc=$?
  trap - EXIT
  sleep_report "$gate_clock_start"
  exit "$rc"
}
trap gate_sleep_exit EXIT

cd "$ROOT"
# A caller value of GATE_M9_SVID_TTL wins over harness/versions.env, and the value of the file stays the record value.
m9_ttl_env="${GATE_M9_SVID_TTL:-}"
source "$ROOT/harness/versions.env"
milestone="${1:?usage: gate.sh m1|m2|m3|m4|m4-rotate|m5|m5-soak|m5-drill|m6|m6-provision|m7|m8|m9|m15 [go test arguments]}"
# The waits of the M8 and M9 tests are longer than the floor of the Go timeout, and a timeout skips every cleanup, so their limits must be set.
if [[ "$milestone" == m8 ]]; then
  for _var in GATE_M8_BUDGET_MINUTES GATE_M8_TEST_TIMEOUT_MINUTES; do
    [[ -n "${!_var:-}" ]] || die "$_var is empty in harness/versions.env, and the M8 tests need it: a Go timeout of the default floor would skip the cleanups of a test that waits for a rollback. Set it, then run the gate again"
  done
fi
if [[ "$milestone" == m15 ]]; then
  for _var in GATE_M15_BUDGET_MINUTES GATE_M15_TEST_TIMEOUT_MINUTES; do
    [[ -n "${!_var:-}" ]] || die "$_var is empty in harness/versions.env, and the M15 tests need it: a Go timeout skips every cleanup of a test that rotates the API server key. Set it, then run the gate again"
  done
fi
if [[ "$milestone" == m9 ]]; then
  for _var in GATE_M9_SVID_TTL GATE_M9_BUDGET_MINUTES GATE_M9_TEST_TIMEOUT_MINUTES; do
    [[ -n "${!_var:-}" ]] || die "$_var is empty in harness/versions.env, and the slow tier needs it: a Go timeout skips every cleanup of an island test. Set it, then run the gate again"
  done
fi
# The kubelet compares --since-time with the clock of the VM, so the start time of the token scan comes from a node, not from the Mac.
gate_started="$(docker exec dev-cp-control-plane date -u +%Y-%m-%dT%H:%M:%SZ)" || die "cannot read the time of the node dev-cp-control-plane. Run: mise run harness:status"
shift
pattern="$(echo "$milestone" | tr '[:lower:]' '[:upper:]')"
budget_var="GATE_${pattern//-/_}_BUDGET_MINUTES"
timeout_var="GATE_${pattern//-/_}_TEST_TIMEOUT_MINUTES"
[[ "$milestone" != m4-rotate ]] || pattern="^TestRotationSigningKey$"
[[ "$milestone" != m5-soak ]] || pattern="^TestStreamSoakHalfHour$"
[[ "$milestone" != m5-drill ]] || pattern="^TestGatewayVolumeLostDrill$"
[[ "$milestone" != m6-provision ]] || pattern="^TestProvisionFromPortal$"
[[ "$milestone" != m7 ]] || pattern="^TestM7"
[[ "$milestone" != m8 ]] || pattern="^TestM8"
[[ "$milestone" != m15 ]] || pattern="^TestM15"
budget_minutes="${!budget_var:-}"

# The live gates need the build output of the checkout that set up the clusters: build/images.env, and build/<cluster>/ with
# the bundles, published.env and facts.env. A new worktree has none of it, so a test would fail late with another message.
if [[ "$milestone" != m1 ]]; then
  [[ -f "$BUILD_ROOT/images.env" ]] \
    || die "$BUILD_ROOT/images.env is missing. Run: mise run images, or copy it from the checkout that set up the clusters: cp <that checkout>/build/images.env $BUILD_ROOT/"
  # A cell has no build directory until its step creates it, so only the clusters that exist need one.
  for cluster in $(existing_clusters); do
    [[ -d "$BUILD_ROOT/$cluster" || -z "$(yq -r ".clusters[] | select(.name == \"$cluster\") | .components[]" "$ROOT/harness/topology.yaml")" ]] \
      || die "$BUILD_ROOT/$cluster is missing. Copy it from the checkout that set up the clusters: cp -R <that checkout>/build/$cluster $BUILD_ROOT/"
  done
fi

# A slow tier of gate:m9 sets a longer SVID lifetime in dev-cp. Every other gate needs the lifetime of cells/dev-cp.env, so it refuses while
# the marker exists, while a restore has not settled (build/gate/m9-svid-ttl.restoring), or while the live agent_ttl of dev-cp differs from that
# file.
if [[ "$milestone" != m9 ]]; then
  [[ ! -e "$SVID_TTL_MARKER" ]] \
    || die "the slow-tier marker build/gate/m9-svid-ttl exists, so a slow tier runs or stopped early, and dev-cp has another SVID lifetime. Repair it with: mise run gate:m9:repair"
  [[ ! -e "$SVID_TTL_MARKER.restoring" ]] \
    || die "build/gate/m9-svid-ttl.restoring exists, so a restore of the SVID lifetime did not settle, and some SVIDs can still have the slow-tier lifetime. Repair it with: mise run gate:m9:repair"
  live_ttl="$(svid_ttl_live)" || die "could not read agent_ttl of the SPIRE server config in dev-cp. Run: mise run harness:status"
  file_ttl="$(svid_ttl_file)"
  [[ "$live_ttl" == "$file_ttl" ]] \
    || die "the SPIRE server of dev-cp sets agent_ttl '$live_ttl', and cells/dev-cp.env sets SPIRE_SVID_TTL=$file_ttl, so a slow tier stopped early. Repair it with: mise run gate:m9:repair"
fi

# Build the test binary first, so that the budget covers only the test run.
build_start=$SECONDS
go test -tags e2e -count=1 -run '^$' ./test/e2e/ >/dev/null || die "the end-to-end tests do not build"
log "gate $milestone build took $((SECONDS - build_start))s"
# The elapsed time of m9 covers Phases 0 to 7, from the clock of the Mac.
[[ "$milestone" != m9 ]] || m9_start="$(date +%s)"

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
  for cluster in $(live_cells); do
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
  for cluster in $(existing_clusters); do
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
  for cluster in $(live_cells); do
    targets+=("$cluster:cell-identity-system:deployment/celld:mise run images -- celld cluster-jwt-agent, then CELL=$cluster mise run cell:up")
  done
  for target in "${targets[@]}"; do
    IFS=: read -r cluster ns workload fix <<<"$target"
    found="$(live_image_mismatches "$cluster" "$ns" "$workload")" || die "could not read $workload in $cluster"
    [[ -z "$found" ]] || stale+="$found"$'\n'"Run: $fix"$'\n'
  done
  [[ -z "$stale" ]] || die "the deployed images differ from build/images.env:"$'\n'"$stale"
fi

# The M5 tests run against mgmtd, envd, the cell gateway, the SPIRE server of dev-cp (its plugin writes the key hints) and
# the cells. An earlier run can leave a workload with no
# replica, or a test namespace. Each of these workloads must run the images that `mise run images` recorded, and so
# must celld in each cell and the three cell-proxy servers of management. The cell-proxy clients stay with the M3 check:
# a new image of the server changes the digest of every user of cell-proxy.
if [[ "$milestone" == m5 || "$milestone" == m5-soak || "$milestone" == m5-drill ]]; then
  "$ROOT/scripts/gate-m5-repair.sh" --check || exit 1
  stale=""
  targets=("management:mgmt-system:statefulset/mgmtd:mise run images -- mgmtd, then CELL=management LINK_ONLY=mgmt-api mise run cell:link"
    "dev-cp:envd-system:deployment/envd:mise run images -- envd, then CELL=dev-cp mise run cell:up"
    "dev-cp:gateway-system:statefulset/cell-gateway:mise run images -- cellgw, then CELL=dev-cp mise run cell:up"
    "dev-cp:spire-system:statefulset/spire-server:mise run images -- cluster-jwt-server, then CELL=dev-cp mise run cell:up"
    "management:central-view-system:deployment/argocd-agent-principal:mise run images -- cell-proxy, then CELL=management LINK_ONLY=central-view mise run cell:link"
    "management:observability-system:deployment/telemetry-gateway:mise run images -- cell-proxy, then CELL=management LINK_ONLY=telemetry-gateway mise run cell:link"
    "management:mesh-view-system:deployment/mesh-view-hub:mise run images -- cell-proxy, then CELL=management LINK_ONLY=mesh-view-hub mise run cell:link")
  for cluster in $(live_cells); do
    targets+=("$cluster:cell-identity-system:deployment/celld:mise run images -- celld cluster-jwt-agent, then CELL=$cluster mise run cell:up")
  done
  for target in "${targets[@]}"; do
    IFS=: read -r cluster ns workload fix <<<"$target"
    found="$(live_image_mismatches "$cluster" "$ns" "$workload")" || die "could not read $workload in $cluster"
    [[ -z "$found" ]] || stale+="$found"$'\n'"Run: $fix"$'\n'
  done
  [[ -z "$stale" ]] || die "the deployed images differ from build/images.env:"$'\n'"$stale"
fi

# The M6 tests run against mgmtd, the host service, envd, the cell controller, the cell gateway and the SPIRE server of dev-cp
# (its plugin checks the cells). Each of these workloads must run the image that `mise run images` recorded, so a test does not
# run old code, and a step does not end with bootstrap_mismatch because the images changed. gate-m6-repair.sh --check runs
# gate-m5-repair.sh, which runs the M4 and M2 repairs once. The provision gate checks the same, and the check fails while the marker
# of an earlier provision run exists.
if [[ "$milestone" == m6 || "$milestone" == m6-provision || "$milestone" == m7 || "$milestone" == m8 || "$milestone" == m9 || "$milestone" == m15 ]]; then
  "$ROOT/scripts/gate-m6-repair.sh" --check || exit 1
  if [[ "$milestone" == m7 || "$milestone" == m8 || "$milestone" == m9 || "$milestone" == m15 ]]; then
    "$ROOT/scripts/gate-m7-repair.sh" --check || exit 1
    [[ "$milestone" != m8 && "$milestone" != m9 && "$milestone" != m15 ]] || "$ROOT/scripts/gate-m8-repair.sh" --check || exit 1
    [[ "$milestone" != m9 ]] || "$ROOT/scripts/gate-m9-repair.sh" --check || exit 1
    [[ "$milestone" != m15 ]] || "$ROOT/scripts/gate-m15-repair.sh" --check || exit 1
  fi
  if [[ "$milestone" == m7 ]]; then
    # TestM7RegistryRefusesDelete sends a manifest delete. A mirror that still runs with deletes on would lose the image of netprobe.
    registry_env="$(docker inspect -f '{{json .Config.Env}}' registry-mirror)" \
      || die "could not read the container registry-mirror. Run: mise run harness:status"
    jq -e 'index("REGISTRY_STORAGE_DELETE_ENABLED=false") != null' >/dev/null <<<"$registry_env" \
      || die "the container registry-mirror runs with deletes on, so a test could delete a live image. Run: mise run hostsvc -- up, then run the gate again"
  fi
  stale=""
  targets=("management:mgmt-system:statefulset/mgmtd:mise run images -- mgmtd, then CELL=management LINK_ONLY=mgmt-api mise run cell:link"
    "dev-cp:envd-system:deployment/envd:mise run images -- envd, then CELL=dev-cp mise run cell:up"
    "dev-cp:cell-controller-system:deployment/cell-controller:mise run images -- cell-controller, then CELL=dev-cp mise run cell:up"
    "dev-cp:gateway-system:statefulset/cell-gateway:mise run images -- cellgw, then CELL=dev-cp mise run cell:up"
    "dev-cp:spire-system:statefulset/spire-server:mise run images -- cluster-jwt-server, then CELL=dev-cp mise run cell:up")
  if [[ "$milestone" == m7 || "$milestone" == m8 || "$milestone" == m9 || "$milestone" == m15 ]]; then
    cells="$(live_cells)" || die "$cells"
    for cluster in $cells; do
      targets+=("$cluster:cell-identity-system:deployment/celld:mise run images -- celld cluster-jwt-agent, then CELL=$cluster mise run cell:up")
    done
  fi
  # The bundle store proxy and the token client of the repo server run cell-proxy in dev-cp and in each live cell.
  if [[ "$milestone" == m8 || "$milestone" == m9 || "$milestone" == m15 ]]; then
    for cluster in dev-cp $cells; do
      targets+=("$cluster:cell-system:statefulset/bundle-store:mise run images -- cell-proxy, then CELL=$cluster mise run cell:up"
        "$cluster:argocd:deployment/argocd-repo-server:mise run images -- cell-proxy, then CELL=$cluster mise run cell:up")
    done
  fi
  # The M9 tests close revoked connections in the cell-proxy servers of management and of the mesh-view tunnel of each cell, and the
  # container agent-ban in spire-server-0 of dev-cp bans the agents of a revoked cell. The image check of spire-server covers agent-ban.
  if [[ "$milestone" == m9 ]]; then
    targets+=("management:central-view-system:deployment/argocd-agent-principal:mise run images -- cell-proxy, then CELL=management LINK_ONLY=central-view mise run cell:link"
      "management:observability-system:deployment/telemetry-gateway:mise run images -- cell-proxy, then CELL=management LINK_ONLY=telemetry-gateway mise run cell:link"
      "management:mesh-view-system:deployment/mesh-view-hub:mise run images -- cell-proxy, then CELL=management LINK_ONLY=mesh-view-hub mise run cell:link")
    for cluster in $cells; do
      targets+=("$cluster:mesh-view-system:deployment/mesh-view:mise run images -- cell-proxy, then CELL=$cluster mise run cell:up")
    done
  fi
  if [[ "$milestone" == m9 || "$milestone" == m15 ]]; then
    server="$(kubectl --context kind-dev-cp -n spire-system get statefulset/spire-server -o json)" || die "could not read statefulset/spire-server in dev-cp"
    jq -e 'any(.spec.template.spec.containers[]; .name == "agent-ban")' >/dev/null <<<"$server" \
      || die "statefulset/spire-server in dev-cp has no container agent-ban, so a revoked cell keeps its agents. Run: mise run images -- cluster-jwt-server, then CELL=dev-cp mise run cell:up"
  fi
  for target in "${targets[@]}"; do
    IFS=: read -r cluster ns workload fix <<<"$target"
    found="$(live_image_mismatches "$cluster" "$ns" "$workload")" || die "could not read $workload in $cluster"
    [[ -z "$found" ]] || stale+="$found"$'\n'"Run: $fix"$'\n'
  done
  [[ -z "$stale" ]] || die "the deployed images differ from build/images.env:"$'\n'"$stale"
fi

if [[ "$milestone" == m9 ]]; then
  m9_tests=(TestM9LocalRevocationDuringIsland TestM9ConnectedRevocation TestM9OneWayPartitions TestM9KeyRotatedDuringEnvironmentIsland
    TestM9StoreLostDuringCellIsland TestM9IslandsHold)
  record_ttl="$GATE_M9_SVID_TTL"
  svid_ttl="${m9_ttl_env:-$record_ttl}"
  run_given=0
  for _arg in "$@"; do
    [[ "$_arg" != -run && "$_arg" != -run=* && "$_arg" != --run && "$_arg" != --run=* ]] || run_given=1
  done
  not_record=""
  ((run_given == 0)) || not_record="the go test arguments name their own -run pattern"
  [[ "$svid_ttl" == "$record_ttl" ]] || not_record="the SVID lifetime is $svid_ttl, and harness/versions.env sets GATE_M9_SVID_TTL=$record_ttl"
  [[ -z "$not_record" ]] || log "this run is not a slow-tier record: $not_record"
  switched=0
  [[ "$svid_ttl" == "$(svid_ttl_file)" ]] || switched=1
  mkdir -p "$BUILD_ROOT"
  m9_status=0
  m9_scan_from=""
  m9_events=()

  # m9_finish is Phase 7. It runs from the EXIT trap, also after a failure or an interrupt, and ends the script with the result of the run.
  m9_finish() {
    local rc=$? elapsed
    trap - EXIT
    trap 'log "gate m9 runs Phase 7 to its end. After a failed step there, run: mise run gate:m9:repair"' INT TERM
    set +e
    ((rc == 0)) || m9_status=1
    log "gate m9 Phase 7: the token scan, the restore of the SVID lifetime and harness:status"
    # An invocation that did not end has not scanned the logs, and a restore restarts the pods whose logs it would scan.
    if [[ -n "$m9_scan_from" ]]; then
      "$ROOT/scripts/gate-token-scan.sh" "$m9_scan_from" || { printf 'FAIL: gate m9 found a token in a log\n' >&2; m9_status=1; }
    fi
    if ((switched)) || [[ -e "$SVID_TTL_MARKER" || -e "$SVID_TTL_MARKER.restoring" ]]; then
      "$ROOT/scripts/svid-ttl.sh" restore || { printf 'FAIL: gate m9 could not restore the SVID lifetime of dev-cp. Run: mise run gate:m9:repair\n' >&2; m9_status=1; }
    fi
    harness_status_settled || { printf 'FAIL: harness:status reports a bad value after gate m9. Read its problems, or run: mise run gate:m9:repair\n' >&2; m9_status=1; }
    for _f in ${m9_events[@]+"${m9_events[@]}"}; do
      [[ -f "$_f" ]] || log "the events file $_f is missing, so the durations leave out its test"
    done
    if ((${#m9_events[@]} > 0)); then
      jq -Rrn '[inputs | fromjson? | select(.Test != null and (.Test | contains("/") | not) and (.Action == "pass" or .Action == "fail"))
        | {test: .Test, action: .Action, elapsed: .Elapsed}] | sort_by(-.elapsed)[] | "\(.elapsed)s \(.action) \(.test)"' "${m9_events[@]}" \
        >"$BUILD_ROOT/gate-m9-durations.txt" 2>/dev/null || true
      log "the tests of gate m9 (every test is in $BUILD_ROOT/gate-m9-durations.txt):"
      cat "$BUILD_ROOT/gate-m9-durations.txt" >&2
    fi
    elapsed=$(($(date +%s) - m9_start))
    log "gate m9 took ${elapsed}s, from Phase 0 to the end of Phase 7"
    sleep_report "$gate_clock_start"
    [[ -z "$not_record" ]] || printf 'gate m9: not a slow-tier record: %s\n' "$not_record" >&2
    if ((elapsed > GATE_M9_BUDGET_MINUTES * 60)); then
      printf 'FAIL: gate m9 took %ss, over the budget of %s minutes\n' "$elapsed" "$GATE_M9_BUDGET_MINUTES" >&2
      m9_status=1
    fi
    exit "$m9_status"
  }

  # m9_invoke <name> <go test arguments...> runs one go test invocation with its own events file, then the token scan from its start.
  m9_invoke() {
    local name="$1" events rc=0
    shift
    events="$BUILD_ROOT/gate-m9-$name.json"
    m9_events+=("$events")
    m9_scan_from="$(docker exec dev-cp-control-plane date -u +%Y-%m-%dT%H:%M:%SZ)" || die "cannot read the time of the node dev-cp-control-plane. Run: mise run harness:status"
    log "gate m9 runs $name"
    go test -tags e2e -count=1 -failfast -timeout "${GATE_M9_TEST_TIMEOUT_MINUTES}m" -json ./test/e2e/ "$@" \
      | tee "$events" | jq --unbuffered -Rrj 'fromjson? | select(.Output != null) | .Output' || rc=$?
    "$ROOT/scripts/gate-token-scan.sh" "$m9_scan_from" || { printf 'FAIL: gate m9 found a token in a log during %s\n' "$name" >&2; rc=1; }
    m9_scan_from=""
    ((rc == 0)) && return 0
    m9_status=1
    return 1
  }

  # Bash runs a trap only after the foreground command ends. Ctrl-C reaches the whole process group, so go test ends at once. A signal to
  # this process alone, for example kill -TERM <pid>, waits until the current go test invocation ends.
  trap m9_finish EXIT
  trap 'exit 130' INT TERM
  # The events files of an earlier run would read as results of this run.
  rm -f "$BUILD_ROOT"/gate-m9-*.json "$BUILD_ROOT/gate-m9-durations.txt"
  # The token scan of Phase 0 covers the checks and the switch, which renders and rolls dev-cp. Phase 7 runs it when the switch fails.
  m9_scan_from="$gate_started"
  if ((switched)); then
    "$ROOT/scripts/svid-ttl.sh" set "$svid_ttl" || die "the switch of the SVID lifetime of dev-cp to $svid_ttl failed"
  else
    log "the SVID lifetime $svid_ttl is the one of cells/dev-cp.env, so the switch is skipped"
  fi
  "$ROOT/scripts/gate-token-scan.sh" "$m9_scan_from" || { m9_scan_from=""; die "gate m9 found a token in a log of Phase 0"; }
  m9_scan_from=""
  if ((run_given)); then
    m9_invoke run "$@" || true
  else
    for _test in "${m9_tests[@]}"; do
      m9_invoke "$_test" -run "^$_test\$" "$@" || break
    done
  fi
  exit "$m9_status"
fi

# go test -json gives each test its own duration. The raw events stay in build/gate-<milestone>.json,
# and the text of the run goes to standard output as it does without -json.
mkdir -p "$BUILD_ROOT"
events="$BUILD_ROOT/gate-$milestone.json"
durations="$BUILD_ROOT/gate-$milestone-durations.txt"
start=$SECONDS
status=0
# The test timeout is twice the budget, with a floor of 30 minutes or GATE_<MILESTONE>_TEST_TIMEOUT_MINUTES, so the budget check
# reports a slow run and the Go timeout never ends the run first.
test_timeout="$(gate_test_timeout "$budget_minutes" "${!timeout_var:-}")"
# The long tests of M8 run only with GATE_M8_LONG=1.
[[ "$milestone" != m8 || "${GATE_M8_LONG:-}" == 1 ]] || set -- -short "$@"
go test -tags e2e -count=1 -timeout "${test_timeout}m" -json ./test/e2e/ -run "$pattern" "$@" \
  | tee "$events" | jq --unbuffered -Rrj 'fromjson? | select(.Output != null) | .Output' || status=$?
elapsed=$((SECONDS - start))
log "gate $milestone tests took ${elapsed}s"
# Each test of M8 restored the targets that it changed, so a passing run leaves no record.
[[ "$milestone" != m8 || "$status" -ne 0 ]] || rm -f "$BUILD_ROOT/gate/m8-bundles"
# No token may reach a log of the M5 components. A hit fails the gate, like a failed test.
if [[ "$milestone" == m5 || "$milestone" == m5-soak || "$milestone" == m5-drill || "$milestone" == m6 || "$milestone" == m6-provision || "$milestone" == m7 || "$milestone" == m8 || "$milestone" == m15 ]]; then
  "$ROOT/scripts/gate-token-scan.sh" "$gate_started" || { printf 'FAIL: gate %s found a token in a log\n' "$milestone" >&2; status=1; }
fi
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
