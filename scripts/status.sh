#!/usr/bin/env bash
# Report the state of the whole PoC. Standard output holds one compact JSON object for each cluster that has
# components in harness/topology.yaml, in topology order. Progress lines go to standard error. The exit status
# is 1 when any value is bad. The shape of the objects is part of the interface of M4 and is described in the
# README under "Operator status".
#
# Every cluster object holds:
#   cluster       the cluster name
#   ok            true when every value below is good
#   applications  {total, bad}: the Applications of argocd, and the ones that are not Synced and Healthy
#   verify        {ok, failed}: the result of cell:verify, and the name of each failed check
#   telemetry     {ok, verdict}: the result of obs:uplink-status
#   problems      one sentence for each bad value, with the command to run
# The object of management also holds:
#   agents        {expected, connected, missing}: the Argo CD agents of VIEW_CELLS that the principal lists
#   samples       the age in seconds of the last Prometheus sample for each k8s_cluster_name
#   stale_samples the clusters with no sample, or one that is 5 minutes old or older
#   kiali         {ready, accessible, missing, down_cells, note}: the clusters that Kiali reaches
#   mesh          {ok, lines}: the result of mesh:status
# The checks of cell:verify, the hops of obs:uplink-status and the parts of mesh:status are read from those
# tasks and not repeated here. STATUS_SAMPLE_MAX_AGE (default 300) is the age limit for a sample.
export CELL="${CELL:-management}"
source "$(dirname "$0")/lib.sh"

cd "$ROOT"
clusters="$(yq -r '.clusters[] | select(.components | length > 0) | .name' "$ROOT/harness/topology.yaml")"
[[ -n "$clusters" ]] || die "no cluster in harness/topology.yaml has components"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
max_age="${STATUS_SAMPLE_MAX_AGE:-300}"

# applications <cluster> prints {total, bad} for the Applications of argocd.
applications() {
  local out
  if ! out="$(kubectl --context "kind-$1" -n argocd get applications -o json 2>&1)"; then
    jq -nc --arg error "$out" '{total: 0, bad: ["the Applications cannot be read: \($error)"]}'
    return
  fi
  jq -c '{total: (.items | length), bad: [.items[] | select(.status.sync.status != "Synced" or .status.health.status != "Healthy")
    | "\(.metadata.name): \(.status.sync.status // "no sync status") and \(.status.health.status // "no health status")"]}' <<<"$out"
}

# run_verify <cluster> prints {ok, failed}, from the FAIL lines of cell:verify.
run_verify() {
  local out rc=0
  out="$(CELL="$1" mise run cell:verify 2>/dev/null)" || rc=$?
  printf '%s\n' "$out" | jq -Rsc --argjson rc "$rc" '[split("\n")[] | select(startswith("FAIL  ")) | sub("^FAIL  "; "")] as $f
    | {failed: (if $rc != 0 and ($f | length) == 0 then ["cell:verify exited with status \($rc) and printed no FAIL line"] else $f end)}
    | .ok = (.failed | length == 0) | {ok, failed}'
}

# run_telemetry <cluster> prints {ok, verdict}, from obs:uplink-status.
run_telemetry() {
  local out rc=0
  out="$(mise run obs:uplink-status "$1" 2>/dev/null)" || rc=$?
  jq -Rsc --argjson rc "$rc" '(split("\n") | map(fromjson? | select(type == "object")) | .[0]) as $o
    | if $o == null then {ok: false, verdict: "obs:uplink-status printed no JSON object"}
      else {ok: ($rc == 0), verdict: ($o.verdict // $o.error // "no verdict")} end' <<<"$out"
}

# management_extras prints the fields of the management object, as one JSON object.
management_extras() {
  local logs agents samples kiali_json mesh_out mesh_rc=0 down="" entry cell ready conf expected

  # The principal lists an agent as connected until its last stream line closes the stream.
  logs="$(kubectl --context kind-management -n central-view-system logs deploy/argocd-agent-principal -c argocd-agent-principal 2>/dev/null || true)"
  expected="$(for cell in $VIEW_CELLS; do echo "$POC_ENV-$cell"; done | jq -Rsc 'split("\n") | map(select(length > 0))')"
  agents="$(jq -Rsc --argjson expected "$expected" '[split("\n")[] | fromjson? | select(type == "object" and .client != null
      and (.msg == "An agent connected to the subscription stream" or .msg == "Closing EventStream"))]
    | group_by(.client) | map({client: .[0].client, up: (.[-1].msg != "Closing EventStream")}) as $last
    | ([$last[] | select(.up) | .client] | sort) as $up
    | {expected: $expected, connected: ($expected - ($expected - $up)), missing: ($expected - $up)}' <<<"$logs")"

  # The age of the newest sample of each cluster in the Prometheus of lgtm.
  samples="$(kubectl --context kind-management -n observability-system exec lgtm-0 -c lgtm -- curl -s --max-time 20 \
    --data-urlencode 'query=time() - max by (k8s_cluster_name) (timestamp(up))' http://127.0.0.1:9090/api/v1/query 2>/dev/null \
    | jq -c '[.data.result[]? | select(.metric.k8s_cluster_name != null) | {key: .metric.k8s_cluster_name, value: (.value[1] | tonumber | floor)}] | from_entries' 2>/dev/null)" || samples=""
  [[ -n "$samples" ]] || samples='{}'
  samples="$(jq -c --arg clusters "$clusters" --argjson max "$max_age" '. as $s | {samples: ., stale: [$clusters | split("\n")[] | select(length > 0) | select(($s[.] == null) or $s[.] >= $max)]}' <<<"$samples")"

  # Kiali reads every cell once at start. While a cell is down, it stops in discovery and restarts until all answer.
  for entry in $MESH_VIEW_CELLS; do
    cell="${entry%%=*}"
    hub_cell_state "$cell" || down+="$cell "
  done
  ready="$(kubectl --context kind-management -n mesh-view-system get deployment kiali -o jsonpath='{.status.readyReplicas}' 2>/dev/null || true)"
  conf=""
  [[ "${ready:-0}" == 1 ]] && conf="$(kubectl --context kind-management --request-timeout=20s get --raw \
    /api/v1/namespaces/mesh-view-system/services/kiali:20001/proxy/kiali/api/config 2>/dev/null || true)"
  kiali_json="$(jq -Rsc --arg ready "${ready:-0}" --arg cells "$MESH_VIEW_CELLS" --arg down "$down" '
      (fromjson? // {}) as $c
      | ([$c.clusters // {} | to_entries[] | select(.value.accessible == true) | .key] | sort) as $acc
      | ($cells | split(" ") | map(select(length > 0) | split("=")[0])) as $want
      | ($down | split(" ") | map(select(length > 0))) as $dn
      | {ready: ($ready == "1"), accessible: $acc, missing: ($want - $acc), down_cells: $dn} as $k
      | $k + {note: (if ($k.ready and ($k.missing | length) == 0) then ""
          elif ($dn | length) > 0 then "Kiali cannot start while a cell is down. The cell \($dn | join(" and ")) is absent, so Kiali stops during discovery. It recovers about 5 minutes after the cell returns. Run: CELL=\($dn[0]) mise run cell:up"
          else "Kiali is not Ready or does not reach every cell, but every tunnel is up. Wait up to 5 minutes, then run: mise run mesh:status" end)}' <<<"$conf")"

  mesh_out="$(mise run mesh:status 2>/dev/null)" || mesh_rc=$?
  jq -nc --argjson agents "$agents" --argjson samples "$samples" --argjson kiali "$kiali_json" --argjson rc "$mesh_rc" --arg out "$mesh_out" \
    '{agents: $agents, samples: $samples.samples, stale_samples: $samples.stale, kiali: $kiali,
      mesh: {ok: ($rc == 0), lines: ($out | split("\n") | map(select(length > 0)))}}'
}

# collect <cluster> writes the JSON object of one cluster to $tmp/<cluster>.json.
collect() {
  local cluster="$1" apps verify telemetry extras='{}'
  apps="$(applications "$cluster")"
  verify="$(run_verify "$cluster")"
  telemetry="$(run_telemetry "$cluster")"
  [[ "$cluster" != management ]] || extras="$(management_extras)"
  jq -nc --arg cluster "$cluster" --argjson apps "$apps" --argjson verify "$verify" --argjson telemetry "$telemetry" --argjson extras "$extras" '
    ($apps.bad | map("Application " + .)) as $a
    | ([$verify.failed[] | "cell:verify failed: " + .] + (if $verify.ok then [] else ["Run: CELL=\($cluster) mise run cell:verify"] end)) as $v
    | ([if $telemetry.ok then empty else "telemetry: \($telemetry.verdict). Run: mise run obs:uplink-status \($cluster)" end]) as $t
    | ([if ($extras.agents.missing // []) | length > 0 then "the principal lists no stream from \($extras.agents.missing | join(" and ")). Run: CELL=<cell> mise run cell:verify" else empty end]
      + [if ($extras.stale_samples // []) | length > 0 then "no recent Prometheus sample for \($extras.stale_samples | join(" and ")). Run: mise run obs:uplink-status <cluster>" else empty end]
      + [if $extras.kiali != null and $extras.kiali.note != "" then "Kiali: " + $extras.kiali.note else empty end]
      + [if $extras.mesh != null and ($extras.mesh.ok | not) then "mesh:status reports a part that is not up. Run: mise run mesh:status" else empty end]) as $m
    | ($a + $v + $t + $m) as $problems
    | {cluster: $cluster, ok: ($problems | length == 0), applications: $apps, verify: $verify, telemetry: $telemetry}
      + $extras + {problems: $problems}' >"$tmp/$cluster.json"
}

for cluster in $clusters; do
  log "reading $cluster"
  collect "$cluster" &
done
wait

status=0
for cluster in $clusters; do
  if [[ -s "$tmp/$cluster.json" ]]; then
    cat "$tmp/$cluster.json"
    jq -e .ok "$tmp/$cluster.json" >/dev/null || status=1
  else
    jq -nc --arg cluster "$cluster" '{cluster: $cluster, ok: false, problems: ["the status script could not read the cluster"]}'
    status=1
  fi
done
((status == 0)) && log "every cluster is healthy" || log "at least one value is bad. Read the problems field of each object"
exit "$status"
