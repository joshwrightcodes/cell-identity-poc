#!/usr/bin/env bash
# Report the state of the whole PoC. Standard output holds one compact JSON object for each cluster that has
# components in harness/topology.yaml, in topology order. Progress lines go to standard error. The exit status
# is 1 when any value is bad. A failure of the task itself prints one JSON error line. The shape of the objects
# is part of the interface of M4 and is described in the README under "Operator status".
#
# Every cluster object holds:
#   cluster       the cluster name
#   ok            true when every value below is good
#   applications  {total, bad}: the Applications of argocd, and the ones that are not Synced and Healthy
#   verify        {ok, failed}: the result of cell:verify, and the name of each failed check
#   telemetry     {ok, wait, verdict}: the result of obs:uplink-status. wait is true when the only bad hop is the
#                 export of the collector and the store has a fresh sample, a state that clears by itself
#   problems      one sentence for each bad value, with the command to run
# The object of dev-cp also holds:
#   gateway       {epoch, epochChangedAt, syncedAt, outboxItems, oldestOutboxAt, dropped, droppedAt, recordOld, recordOldAt,
#                 queued, streams, mostClaimed, lastBindRefusal, storeError}: the status of the cell gateway. When it does not
#                 answer, the object holds only error
# The object of management also holds:
#   agents        {expected, connected, missing}: the Argo CD agents of VIEW_CELLS that the principal lists
#   samples       the age in seconds of the last Prometheus sample for each k8s_cluster_name
#   stale_samples the clusters with no sample, or one that is 5 minutes old or older
#   kiali         {ready, accessible, missing, down_cells, absent_cells, note}: the clusters that Kiali reaches.
#                 down_cells are the cells without a tunnel at the hub. absent_cells are the ones among them
#                 whose own API does not answer
#   mesh          {ok, lines}: the result of mesh:status
#   management    {env, signed, applied, appliedAt, lagSince, lastReportAt, lastRefusal, storeError, restoreActive,
#                 pendingDrops, cells, hostsvc}: the status of mgmtd, with the revisions as epoch and counter, and the
#                 cells as {name, bound, lastCheck, lastStatusAt, unreported, oldestUnreportedAt,
#                 records, openOps, expiredOps, forgedSeen, lastRefusal, lastHintCheck}. expiredOps lists the operations that expired with no final
#                 result, as {id, cell, expiredAt}. hostsvc is the status of hostsvc:serve and check, which holds
#                 the text of the first failed pin or root check and is empty when both pass. When mgmtd does not
#                 answer, the object holds only error
# The checks of cell:verify, the hops of obs:uplink-status and the parts of mesh:status are read from those
# tasks and not repeated here. STATUS_SAMPLE_MAX_AGE (default 300) is the age limit for a sample, and
# STATUS_VERIFY_TIMEOUT (default 900) is the time in seconds that the task waits for cell:verify of one cluster.
export CELL="${CELL:-management}"
source "$(dirname "$0")/lib.sh"
source "$ROOT/components/lib/peer-root.sh"
source "$ROOT/components/lib/hostsvc-pin.sh"
source "$ROOT/scripts/verify-lib.sh"

cd "$ROOT"
clusters="$(yq -r '.clusters[] | select(.components | length > 0) | .name' "$ROOT/harness/topology.yaml")"
[[ -n "$clusters" ]] || json_fail harness:status "no cluster in harness/topology.yaml has components"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
max_age="${STATUS_SAMPLE_MAX_AGE:-300}"
verify_limit="${STATUS_VERIFY_TIMEOUT:-900}"

# kubectl with a bound on each request, so that a hung API server gives a problem and no hang.
kubectl() { command kubectl --request-timeout=20s "$@"; }

# with_timeout <seconds> <command...> runs the command, and stops it with TERM after the time.
with_timeout() {
  local limit="$1" pid watchdog rc=0
  shift
  "$@" &
  pid=$!
  ( sleep "$limit"; kill "$pid" 2>/dev/null ) >/dev/null 2>&1 &
  watchdog=$!
  wait "$pid" || rc=$?
  kill "$watchdog" 2>/dev/null || true
  return "$rc"
}

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

# run_verify <cluster> prints {ok, failed}, from the FAIL lines of cell:verify. When the task prints no FAIL line
# and stops, the last line that starts with "error:" on its standard error is the reason.
run_verify() {
  local out rc=0 err=""
  out="$(with_timeout "$verify_limit" env CELL="$1" mise run cell:verify 2>"$tmp/verify-$1.err")" || rc=$?
  err="$(grep '^error:' "$tmp/verify-$1.err" | tail -n 1 || true)"
  printf '%s\n' "$out" | jq -Rsc --argjson rc "$rc" --arg err "$err" --arg limit "$verify_limit" '
    [split("\n")[] | select(startswith("FAIL  ")) | sub("^FAIL  "; "")] as $f
    | {failed: (if $rc == 143 then ["cell:verify did not finish in \($limit) s"]
        elif $rc != 0 and ($f | length) == 0 then [if $err != "" then $err else "cell:verify exited with status \($rc) and printed no FAIL line" end]
        else $f end)}
    | .ok = (.failed | length == 0) | {ok, failed}'
}

# run_telemetry <cluster> prints {ok, wait, verdict}, from obs:uplink-status.
run_telemetry() {
  local out rc=0
  out="$(mise run obs:uplink-status "$1" 2>/dev/null)" || rc=$?
  jq -Rsc --argjson rc "$rc" '(split("\n") | map(fromjson? | select(type == "object")) | .[0]) as $o
    | if $o == null then {ok: false, wait: false, verdict: "obs:uplink-status printed no JSON object"}
      else {ok: ($rc == 0), verdict: ($o.verdict // $o.error // "no verdict")}
        | .wait = (.ok == false and (.verdict | startswith("collector export:")) and ($o.store.ok == true)) end' <<<"$out"
}

# management_plane prints the field management: the status of mgmtd and of the host service. The pin and the root
# of the host service are checked with the functions of cell:verify, which print the reason and the command.
management_plane() {
  local st rc=0 serve hs check="" crc=0 ops
  st="$(mise run mgmt -- status 2>/dev/null)" || rc=$?
  if ((rc != 0)) || ! jq -e 'type == "object" and has("signed")' >/dev/null 2>&1 <<<"$st"; then
    jq -Rsc --argjson rc "$rc" '(split("\n") | map(fromjson? | select(type == "object")) | .[0]) as $o
      | {error: ($o.error // "mise run mgmt -- status exited with status \($rc) and printed no status. Run: mise run mgmt -- status")}' <<<"$st"
    return
  fi
  serve="$(hostsvc_serve_script)"
  hs="$("$serve" status 2>/dev/null)" || hs=""
  jq -e 'type == "object"' >/dev/null 2>&1 <<<"$hs" || hs='{"running":false}'
  if jq -e '.running == true and (.expires_soon | not)' >/dev/null <<<"$hs"; then
    check="$(check_mgmt_hostsvc_pin 2>&1)" || crc=$?
    if ((crc == 0)); then check="$(check_mgmt_hostsvc_root 2>&1)" || crc=$?; fi
    # A check that fails with no output still counts as a failure.
    if ((crc != 0)) && [[ -z "$check" ]]; then check="the host service check failed. Run: mise run hostsvc:serve -- status"; fi
  fi
  # The state of an operation is expired only while it has no final result. A list that fails gives no expired operations.
  ops="$(mise run mgmt -- op list 2>/dev/null)" || ops=""
  jq -e 'type == "object" and has("ops")' >/dev/null 2>&1 <<<"$ops" || ops='{"ops":[]}'
  jq -c --argjson hs "$hs" --arg check "$check" --argjson ops "$ops" '{env, signed, applied, appliedAt, lagSince, lastReportAt, lastRefusal, storeError,
    restoreActive, pendingDrops,
    cells: [.cells[]? | {name, bound, lastCheck, lastStatusAt, unreported, oldestUnreportedAt, records, openOps, expiredOps, forgedSeen, lastRefusal, lastHintCheck}],
    expiredOps: [$ops.ops[]? | select(.state == "expired") | {id, cell, expiredAt}],
    hostsvc: ($hs + {check: ($check | gsub("\n"; " "))})}' <<<"$st"
}

# management_problems <cell-identity cells> reads the field management on standard input and prints one problem
# for each bad value, as a JSON array of strings. Each problem ends with the command to run.
management_problems() {
  jq -c --arg bind "$1" 'def rev: "\(.epoch).\(.counter)";
    def ts: try (sub("\\.[0-9]+Z$"; "Z") | fromdateiso8601) catch 0;
    def cp: "CELL=dev-cp mise run cell:verify";
    if .error != null then ["mgmtd status failed: " + .error]
    else
      . as $m | ([.signed.epoch, .signed.counter]) as $sig | ([.applied.epoch, .applied.counter]) as $app
      | [
        (if $sig > $app and .lagSince != null and (now - (.lagSince | ts)) > 120
         then "signed revision \(.signed | rev) is above applied \(.applied | rev) for more than 2 minutes. Run: \(cp)" else empty end),
        (if .lastRefusal != null and ((.lastRefusal.at | ts) == 0 or (.lastRefusal.at | ts) > ((.appliedAt // "") | ts))
         then "envd refused a spec: \(.lastRefusal.reason) at revision \(.lastRefusal.revision | rev), after the last apply. Run: \(cp)" else empty end),
        (if (.storeError // "") != "" then "envd reports a store error: \(.storeError). Run: \(cp)" else empty end),
        (if .restoreActive then "a restore is active, so mgmtd serves an older revision. Run: mise run mgmt -- restore --revision latest" else empty end),
        (if .lastReportAt == null or (now - (.lastReportAt | ts)) > 60 then "no report from envd in the last 60 seconds. Run: \(cp)" else empty end),
        (.cells[] | select(.lastCheck == "keys_untrusted") | "the key check of \(.name) is keys_untrusted. Run: CELL=\(.name) mise run cell:restart"),
        (.cells[] | select(.lastCheck == "issuer_untrusted") | "the key check of \(.name) is issuer_untrusted. Run: mise run hostsvc:serve -- restart"),
        (.cells[] | select(.lastCheck == "issuer_unavailable") | "the key check of \(.name) is issuer_unavailable. Run: mise run hostsvc:serve -- status"),
        (.cells[] | select(.lastHintCheck == "keys_untrusted") | "the hint check of \(.name) is keys_untrusted. Run: CELL=\(.name) mise run cell:restart"),
        (.cells[] | select(.lastHintCheck == "issuer_untrusted") | "the hint check of \(.name) is issuer_untrusted. Run: mise run hostsvc:serve -- restart"),
        (.cells[] | select(.lastHintCheck == "issuer_unavailable") | "the hint check of \(.name) is issuer_unavailable. Run: mise run hostsvc:serve -- status"),
        (.cells[] | select(.lastHintCheck == "error") | "the hint check of \(.name) is error. Run: mise run mgmt -- keycheck --cell \(.name)"),
        (.cells[] | select(.bound and (now - ((.lastStatusAt // "") | ts)) > 120)
          | "no status from the celld of \(.name) in the last 2 minutes. Run: CELL=\(.name) mise run cell:verify"),
        (.cells[] | select((.unreported // 0) > 0 and ((.oldestUnreportedAt // "") | ts) > 1000000000 and (now - (.oldestUnreportedAt | ts)) > 300)
          | "\(.name) has \(.unreported) unreported items, the oldest from \(.oldestUnreportedAt), more than 5 minutes ago. Run: CELL=\(.name) mise run cell:verify"),
        (.cells[] | select((.records // 0) > 800) | "\(.name) holds \(.records) operation records, above 800. Run: CELL=\(.name) mise run cell:verify"),
        (.expiredOps[]? | select(((.expiredAt // "") | ts) > 1000000000 and (now - (.expiredAt | ts)) < 900)
          | "operation \(.id) for \(.cell) expired at \(.expiredAt) with no final result. Run: mise run ops -- close \(.id)"),
        ($bind | split(" ") | map(select(length > 0))[] as $c | select(any($m.cells[]; .name == $c and .bound) | not)
          | "\($c) is not bound. Run: CELL=\($c) mise run cell:up"),
        (if .hostsvc.running != true then "the host service is not running. Run: mise run hostsvc:serve -- start"
         elif .hostsvc.expires_soon then "the host service certificate expires soon. Run: mise run hostsvc:serve -- restart"
         elif .hostsvc.check != "" then "host service: " + .hostsvc.check else empty end)
      ] end'
}

# gateway_plane prints the field gateway, the cells that mgmtd reports as bound, and whether mgmtd answers, as one JSON
# object. When the gateway does not answer, the field gateway holds only error.
gateway_plane() {
  local gw rc=0 mg mrc=0 bound='[]' up=false
  gw="$(mise run gw -- status 2>/dev/null)" || rc=$?
  if ((rc != 0)) || ! jq -e 'type == "object" and has("epoch")' >/dev/null 2>&1 <<<"$gw"; then
    jq -Rsc --argjson rc "$rc" '{gateway: {error: ((split("\n") | map(fromjson? | select(type == "object")) | .[0]) as $o
      | $o.error // "mise run gw -- status exited with status \($rc) and printed no status. Run: CELL=dev-cp mise run cell:up")}, mgmt_up: false, bound: []}' <<<"$gw"
    return
  fi
  mg="$(mise run mgmt -- status 2>/dev/null)" || mrc=$?
  if ((mrc == 0)) && jq -e 'type == "object" and has("signed")' >/dev/null 2>&1 <<<"$mg"; then
    up=true
    bound="$(jq -c '[.cells[]? | select(.bound) | .name]' <<<"$mg")"
  fi
  jq -c --argjson up "$up" --argjson bound "$bound" '{gateway: {epoch, epochChangedAt, syncedAt, outboxItems, oldestOutboxAt, dropped, droppedAt,
    recordOld, recordOldAt, queued, streams, mostClaimed, lastBindRefusal, storeError}, mgmt_up: $up, bound: $bound}' <<<"$gw"
}

# gateway_problems reads the output of gateway_plane on standard input and prints one problem for each bad value, as a
# JSON array of strings. The sync and the store error follow check_gateway_synced of cell:verify, with the same 2 minutes.
gateway_problems() {
  jq -c 'def ts: try (sub("\\.[0-9]+Z$"; "Z") | fromdateiso8601) catch 0;
    def recent($t; $secs): ($t | ts) > 1000000000 and (now - ($t | ts)) < $secs;
    .gateway as $g | .bound as $bound | .mgmt_up as $up
    | if $g.error != null then ["gateway status failed: " + $g.error]
      else [
        (if ($g.storeError // "") != "" then "the cell gateway reports a store error: \($g.storeError). Run: mise run gw:reset" else empty end),
        (if ($g.syncedAt | ts) < 1000000000 or (now - ($g.syncedAt | ts)) > 120
         then "envd synced with the gateway at \($g.syncedAt // "never"), which is more than 2 minutes ago. Read the log of envd with: mise x -- kubectl --context kind-dev-cp -n envd-system logs deploy/envd -c envd. Then run: CELL=dev-cp mise run cell:up" else empty end),
        (if $up and ($g.outboxItems // 0) > 0 and (($g.oldestOutboxAt | ts) > 1000000000) and (now - ($g.oldestOutboxAt | ts)) > 120
         then "the oldest outbox item of the gateway is from \($g.oldestOutboxAt), more than 2 minutes ago, and mgmtd answers. Run: mise run gw -- outbox" else empty end),
        (if recent($g.droppedAt; 900) then "the gateway dropped an outbox item at \($g.droppedAt), within the last 15 minutes. Run: mise run gw -- outbox" else empty end),
        (if recent($g.recordOldAt; 900) then "the gateway refused an older record at \($g.recordOldAt), within the last 15 minutes. Run: CELL=dev-cp mise run cell:up" else empty end),
        ($bound[] as $c | select(($g.streams[$c] // 0) < 1) | "the gateway holds no stream of \($c). Run: CELL=\($c) mise run cell:up"),
        (($g.mostClaimed // {}) | to_entries[] | select(.value.count > 3)
          | "the cell \(.key) claimed operation \(.value.opId) \(.value.count) times. Run: mise run ops -- trace \(.value.opId)")
      ] end'
}

# management_extras prints the fields of the management object, as one JSON object.
management_extras() {
  local logs agents samples kiali_json mesh_out mesh_rc=0 down="" absent="" entry cell ready conf expected plane

  # The principal lists an agent as connected until its last stream line closes the stream. The kubelet rotates the log after
  # about 10 hours, and the connect line goes with it. An agent with no stream line in the log counts as connected when the
  # principal received an event from it in the last 5 minutes, because events arrive for as long as the stream is open.
  logs="$(kubectl --context kind-management -n central-view-system logs deploy/argocd-agent-principal -c argocd-agent-principal 2>/dev/null || true)"
  expected="$(for cell in $VIEW_CELLS; do echo "$POC_ENV-$cell"; done | jq -Rsc 'split("\n") | map(select(length > 0))')"
  agents="$(jq -Rsc --argjson expected "$expected" '
      def ts: try (sub("\\.[0-9]+Z$"; "Z") | fromdateiso8601) catch 0;
      [split("\n")[] | fromjson? | select(type == "object" and .client != null)] as $lines
      | [$lines[] | select(.msg == "An agent connected to the subscription stream" or .msg == "Closing EventStream")]
      | group_by(.client) | map({client: .[0].client, up: (.[-1].msg != "Closing EventStream")}) as $last
      | ([$last[].client]) as $seen
      | ([$lines[] | select((.msg // "" | startswith("Event received")) and ((.time // "") | ts) > (now - 300)) | .client] | unique) as $active
      | ([$last[] | select(.up) | .client] + ($active - $seen) | unique | sort) as $up
      | {expected: $expected, connected: ($expected - ($expected - $up)), missing: ($expected - $up)}' <<<"$logs")"

  # The age of the newest sample of each cluster in the Prometheus of lgtm.
  samples="$(kubectl --context kind-management -n observability-system exec lgtm-0 -c lgtm -- curl -s --max-time 20 \
    --data-urlencode 'query=time() - max by (k8s_cluster_name) (timestamp(up))' http://127.0.0.1:9090/api/v1/query 2>/dev/null \
    | jq -c '[.data.result[]? | select(.metric.k8s_cluster_name != null) | {key: .metric.k8s_cluster_name, value: (.value[1] | tonumber | floor)}] | from_entries' 2>/dev/null)" || samples=""
  [[ -n "$samples" ]] || samples='{}'
  samples="$(jq -c --arg clusters "$clusters" --argjson max "$max_age" '. as $s | {samples: ., stale: [$clusters | split("\n")[] | select(length > 0) | select(($s[.] == null) or $s[.] >= $max)]}' <<<"$samples")"

  # Kiali reads every cell once at start. While a cell is down, it stops in discovery and restarts until all answer.
  # A cell is absent only when its own API does not answer. A tunnel that is down while the API answers has another cause.
  for entry in $MESH_VIEW_CELLS; do
    cell="${entry%%=*}"
    if ! hub_cell_state "$cell"; then
      down+="$cell "
      kubectl --context "kind-$cell" --request-timeout=10s get --raw /readyz >/dev/null 2>&1 || absent+="$cell "
    fi
  done
  ready="$(kubectl --context kind-management -n mesh-view-system get deployment kiali -o jsonpath='{.status.readyReplicas}' 2>/dev/null || true)"
  conf=""
  [[ "${ready:-0}" == 1 ]] && conf="$(kubectl --context kind-management get --raw \
    /api/v1/namespaces/mesh-view-system/services/kiali:20001/proxy/kiali/api/config 2>/dev/null || true)"
  kiali_json="$(jq -Rsc --arg ready "${ready:-0}" --arg cells "$MESH_VIEW_CELLS" --arg down "$down" --arg absent "$absent" '
      def names: map(select(length > 0));
      (fromjson? // {}) as $c
      | ([$c.clusters // {} | to_entries[] | select(.value.accessible == true) | .key] | sort) as $acc
      | ($cells | split(" ") | map(select(length > 0) | split("=")[0])) as $want
      | ($down | split(" ") | names) as $dn
      | ($absent | split(" ") | names) as $ab
      | ($dn - $ab) as $tun
      | ({ready: ($ready == "1"), accessible: $acc, missing: ($want - $acc), down_cells: $dn, absent_cells: $ab}) as $k
      | (if ($tun | length) == 0 then ""
         else ($tun | join(" and ")) + (if ($tun | length) == 1 then " has" else " have" end) + " no tunnel at the hub, so Kiali cannot read it. "
           + (if ($tun | length) == ($want | length) then "Run: CELL=dev-cp mise run cell:verify, and then mise run mesh:status."
              else "Run: mise run mesh:status." end) end) as $tunnel_note
      | $k + {note: (if ($k.ready and ($k.missing | length) == 0) then ""
          elif ($ab | length) > 0 then "Kiali cannot start while a cell is down. "
            + (if ($ab | length) == 1 then "The cell \($ab[0]) is absent" else "The cells \($ab | join(" and ")) are absent" end)
            + ", so Kiali stops during discovery. It recovers about 5 minutes after the cell returns. Run: "
            + ($ab | map("CELL=\(.) mise run cell:up") | join(" and "))
            + (if $tunnel_note != "" then ". " + $tunnel_note else "" end)
          elif ($dn | length) > 0 then $tunnel_note
          else "Kiali is not Ready or does not reach every cell, but every tunnel is up. Wait up to 5 minutes, then run: mise run mesh:status" end)}' <<<"$conf")"

  mesh_out="$(mise run mesh:status 2>/dev/null)" || mesh_rc=$?
  plane="$(management_plane)"
  jq -nc --argjson plane "$plane" --argjson agents "$agents" --argjson samples "$samples" --argjson kiali "$kiali_json" --argjson rc "$mesh_rc" --arg out "$mesh_out" \
    '{management: $plane, agents: $agents, samples: $samples.samples, stale_samples: $samples.stale, kiali: $kiali,
      mesh: {ok: ($rc == 0), lines: ($out | split("\n") | map(select(length > 0)))}}'
}

# collect <cluster> writes the JSON object of one cluster to $tmp/<cluster>.json.
collect() {
  local cluster="$1" apps verify telemetry extras='{}' mp='[]' plane
  apps="$(applications "$cluster")"
  verify="$(run_verify "$cluster")"
  telemetry="$(run_telemetry "$cluster")"
  if [[ "$cluster" == management ]]; then
    extras="$(management_extras)"
    mp="$(jq -c .management <<<"$extras" | management_problems "$(yq -r '.clusters[] | select(.components | contains(["cell-identity"])) | .name' "$ROOT/harness/topology.yaml" | paste -sd' ' -)")"
  fi
  if [[ "$cluster" == dev-cp ]]; then
    plane="$(gateway_plane)"
    extras="$(jq -c '{gateway}' <<<"$plane")"
    mp="$(gateway_problems <<<"$plane")"
  fi
  jq -nc --argjson mp "$mp" --arg cluster "$cluster" --arg env "$POC_ENV" --argjson apps "$apps" --argjson verify "$verify" --argjson telemetry "$telemetry" --argjson extras "$extras" '
    ($apps.bad | map("Application " + .)) as $a
    | ([$verify.failed[] | "cell:verify failed: " + .] + (if $verify.ok then [] else ["Run: CELL=\($cluster) mise run cell:verify"] end)) as $v
    | ([if $telemetry.ok then empty
        elif $telemetry.wait then "telemetry: \($telemetry.verdict) This clears by itself. Wait up to 5 minutes, then run: mise run harness:status"
        else "telemetry: \($telemetry.verdict). Run: mise run obs:uplink-status \($cluster)" end]) as $t
    | ([if ($extras.agents.missing // []) | length > 0 then
          "the principal lists no stream from \($extras.agents.missing | join(" and ")). Run: "
          + ($extras.agents.missing | map("CELL=\(sub("^\($env)-"; "")) mise run cell:verify") | join(" and "))
        else empty end]
      + [if ($extras.stale_samples // []) | length > 0 then
          "no recent Prometheus sample for \($extras.stale_samples | join(" and ")). Run: "
          + ($extras.stale_samples | map("mise run obs:uplink-status \(.)") | join(" and "))
        else empty end]
      + [if $extras.kiali != null and $extras.kiali.note != "" then "Kiali: " + $extras.kiali.note else empty end]
      + [if $extras.mesh != null and ($extras.mesh.ok | not) then "mesh:status reports a part that is not up. Run: mise run mesh:status" else empty end]) as $m
    | ($a + $v + $t + $m + $mp) as $problems
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
    jq -nc --arg cluster "$cluster" '"the status script could not read the cluster" as $why
      | {cluster: $cluster, ok: false, applications: {total: 0, bad: [$why]}, verify: {ok: false, failed: [$why]},
        telemetry: {ok: false, wait: false, verdict: $why}, problems: [$why + ". Run: CELL=\($cluster) mise run cell:verify"]}'
    status=1
  fi
done
((status == 0)) && log "every cluster is healthy" || log "at least one value is bad. Read the problems field of each object"
exit "$status"
