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
# A cell with the cell-identity set exists only after its step creates it. For a cell that is not live, the object holds
# only cluster, ok, absent (true) and problems: the problems of provisioning that name the cell. It holds no applications,
# verify or telemetry, because there is no cluster to read.
# The problems of provisioning follow the steps of the host service on this Mac and the steps that mgmtd reports. They name a cell
# that is invalid for more than 5 minutes with no open step, an open step that is expired, failed or refused, a journal entry with an
# old heartbeat or a stage past its timeout, a cell controller that stopped to write step-status, a host error older than 2 minutes, a
# requested cell with no cluster, a live cell that is not requested, and a host service that does not hold the dev root, the keys or
# the spec revision of mgmtd. The times of the journal come from the clock of the Mac, and the times of the clusters from a node.
# The object of dev-cp also holds:
#   gateway       {epoch, epochChangedAt, syncedAt, outboxItems, oldestOutboxAt, dropped, droppedAt, recordOld, recordOldAt,
#                 queued, streams, mostClaimed, lastBindRefusal, storeError}: the status of the cell gateway. When it does not
#                 answer, the object holds only error
#   svidTTL       {file, marker, live}: the SVID lifetime of cells/dev-cp.env, of the slow-tier marker build/gate/m9-svid-ttl (null
#                 when it is absent) and of the live server config (null with error when it cannot be read), as svid-ttl -- show
#                 prints them. It is no problem by itself: cell:verify compares the live config with the lifetime in force
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
#                 result, as {id, cell, expiredAt}. An expired bundle.apply operation that was never served is no failure: unservedExpiredOps lists it
#                 (gate:m8:repair closes it). hostsvc is the status of hostsvc:serve and check, which holds
#                 the text of the first failed pin or root check and is empty when both pass. When mgmtd does not
#                 answer, the object holds only error
# The problems of the signed bundle sets name each cell and dev-cp with: a live cluster with no signed bundle state, the state rolled_back (with the
# command bundle -- publish, or bundle -- repair when the rollback itself failed with rollback_unhealthy), a state applying or rolling_back with an
# until more than 10 minutes in the past, an Application root at another digest than root.digest of a healthy state, an AppProject whose annotation
# poc.internal/allow-sha256 differs from the allowSHA256 that the applier reports, and, in dev-cp, a set that envd applied and mgmtd has not closed
# for more than 5 minutes.
# The checks of cell:verify, the hops of obs:uplink-status and the parts of mesh:status are read from those
# tasks and not repeated here. STATUS_SAMPLE_MAX_AGE (default 300) is the age limit for a sample, and
# STATUS_VERIFY_TIMEOUT (default 900) is the time in seconds that the task waits for cell:verify of one cluster.
# HOSTSVC_STEPS_DIR names another directory for the journal and the step logs, for the tests.
export CELL="${CELL:-management}"
source "$(dirname "$0")/lib.sh"
source "$ROOT/components/lib/peer-root.sh"
source "$ROOT/components/lib/hostsvc-pin.sh"
source "$ROOT/scripts/verify-lib.sh"
source "$ROOT/scripts/steps-lib.sh"

cd "$ROOT"
clusters="$(yq -r '.clusters[] | select(.components | length > 0) | .name' "$ROOT/harness/topology.yaml")"
[[ -n "$clusters" ]] || json_fail harness:status "no cluster in harness/topology.yaml has components"
# A cell exists only through its step. The cells that are not live get an object with absent: true, and no read of a cluster.
catalog="$(catalog_cells)" || json_fail harness:status "could not read the cells of harness/topology.yaml"
live="$(live_cells 2>&1)" || json_fail harness:status "could not tell which cells are live: $live. Run: docker ps"
live="$(paste -sd' ' - <<<"$live")"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
max_age="${STATUS_SAMPLE_MAX_AGE:-300}"
verify_limit="${STATUS_VERIFY_TIMEOUT:-900}"

# kubectl with a bound on each request, so that a hung API server gives a problem and no hang.
kubectl() { command kubectl --request-timeout=20s "$@"; }

# read_clock sets now to the time of the node dev-cp-control-plane in epoch seconds, and clock_problem to "". Every age in this script is a
# difference between now and a timestamp that a cluster wrote, so each check reads the clock again just before it compares, and the time
# of the verify steps never counts as age. When the node does not answer, now is the time of the Mac, and clock_problem names the cause.
read_clock() {
  clock_problem=""
  if now="$(node_now 2>/dev/null)" && [[ "$now" =~ ^[0-9]+$ ]]; then return 0; fi
  now="$(date +%s)"
  clock_problem="cannot read the time of the node dev-cp-control-plane, so the age checks use the clock of the Mac, which can differ from the clock of the VM. Run: docker ps"
}

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
  local st rc=0 serve hs check="" crc=0 ops opsFailed
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
  # The state of an operation is expired only while it has no final result. A list that fails gives opsFailed, and a problem.
  ops="$(mise run mgmt -- op list 2>/dev/null)" || ops=""
  opsFailed=false
  jq -e 'type == "object" and has("ops")' >/dev/null 2>&1 <<<"$ops" || { ops='{"ops":[]}'; opsFailed=true; }
  jq -c --argjson hs "$hs" --arg check "$check" --argjson ops "$ops" --argjson opsFailed "$opsFailed" '{env, signed, applied, appliedAt, lagSince, lastReportAt, lastRefusal, storeError,
    restoreActive, pendingDrops,
    cells: [.cells[]? | {name, bound, lastCheck, lastStatusAt, unreported, oldestUnreportedAt, records, openOps, expiredOps, forgedSeen, lastRefusal, lastHintCheck}],
    opsFailed: $opsFailed,
    expiredOps: [$ops.ops[]? | select(.state == "expired" and ((.kind == "bundle.apply" and .served == false) | not)) | {id, cell, expiredAt}],
    unservedExpiredOps: [$ops.ops[]? | select(.state == "expired" and .kind == "bundle.apply" and .served == false) | {id, cell, expiredAt}],
    hostsvc: ($hs + {check: ($check | gsub("\n"; " "))})}' <<<"$st"
}

# management_problems <cell-identity cells> reads the field management on standard input and prints one problem
# for each bad value, as a JSON array of strings. Each problem ends with the command to run.
management_problems() {
  local now clock_problem staged=""
  staged="$(stage_cells 2>/dev/null)" || staged=""
  read_clock
  jq -c --arg bind "$1" --arg staged "$staged" --argjson now "$now" --arg clockp "$clock_problem" 'def rev: "\(.epoch).\(.counter)";
    def ts: try (sub("\\.[0-9]+Z$"; "Z") | fromdateiso8601) catch 0;
    def cp: "CELL=dev-cp mise run cell:verify";
    if .error != null then ["mgmtd status failed: " + .error]
    else
      . as $m | ([.signed.epoch, .signed.counter]) as $sig | ([.applied.epoch, .applied.counter]) as $app
      | [
        (if $sig > $app and .lagSince != null and ($now - (.lagSince | ts)) > 120
         then "signed revision \(.signed | rev) is above applied \(.applied | rev) for more than 2 minutes. Run: \(cp)" else empty end),
        (if .lastRefusal != null and ((.lastRefusal.at | ts) == 0 or (.lastRefusal.at | ts) > ((.appliedAt // "") | ts))
         then "envd refused a spec: \(.lastRefusal.reason) at revision \(.lastRefusal.revision | rev), after the last apply. Run: \(cp)" else empty end),
        (if (.storeError // "") != "" then "envd reports a store error: \(.storeError). Run: \(cp)" else empty end),
        (if .restoreActive then "a restore is active, so mgmtd serves an older revision. Run: mise run mgmt -- restore --revision latest" else empty end),
        (if .lastReportAt == null or ($now - (.lastReportAt | ts)) > 60 then "no report from envd in the last 60 seconds. Run: \(cp)" else empty end),
        (.cells[] | select(.lastCheck == "keys_untrusted") | "the key check of \(.name) is keys_untrusted. Run: CELL=\(.name) mise run cell:restart"),
        (.cells[] | select(.lastCheck == "issuer_untrusted") | "the key check of \(.name) is issuer_untrusted. Run: mise run hostsvc:serve -- restart"),
        (.cells[] | select(.lastCheck == "issuer_unavailable") | "the key check of \(.name) is issuer_unavailable. Run: mise run hostsvc:serve -- status"),
        (.cells[] | select(.lastHintCheck == "keys_untrusted") | "the hint check of \(.name) is keys_untrusted. Run: CELL=\(.name) mise run cell:restart"),
        (.cells[] | select(.lastHintCheck == "issuer_untrusted") | "the hint check of \(.name) is issuer_untrusted. Run: mise run hostsvc:serve -- restart"),
        (.cells[] | select(.lastHintCheck == "issuer_unavailable") | "the hint check of \(.name) is issuer_unavailable. Run: mise run hostsvc:serve -- status"),
        (.cells[] | select(.lastHintCheck == "error") | "the hint check of \(.name) is error. Run: mise run mgmt -- keycheck --cell \(.name)"),
        (.cells[] | select(.bound and ($now - ((.lastStatusAt // "") | ts)) > 120)
          | "no status from the celld of \(.name) in the last 2 minutes. Run: CELL=\(.name) mise run cell:verify"),
        (.cells[] | select((.unreported // 0) > 0 and ((.oldestUnreportedAt // "") | ts) > 1000000000 and ($now - (.oldestUnreportedAt | ts)) > 300)
          | "\(.name) has \(.unreported) unreported items, the oldest from \(.oldestUnreportedAt), more than 5 minutes ago. Run: CELL=\(.name) mise run cell:verify"),
        (.cells[] | select((.records // 0) > 800) | "\(.name) holds \(.records) operation records, above 800. Run: CELL=\(.name) mise run cell:verify"),
        (if .opsFailed then "the list of operations failed, so expired operations are not checked. Run: mise run mgmt -- op list" else empty end),
        (.expiredOps[]? | select(((.expiredAt // "") | ts) > 1000000000 and ($now - (.expiredAt | ts)) < 900)
          | "operation \(.id) for \(.cell) expired at \(.expiredAt) with no final result. Run: mise run ops -- close \(.id)"),
        ($bind | split(" ") | map(select(length > 0))[] as $c | select(any($m.cells[]; .name == $c and .bound) | not)
          | ($staged | split(" ") | map(select(startswith($c + ":"))) | first // "") as $run
          | if $run != "" then "\($c) is not bound while its stage \($run | sub("^[^:]*:"; "")) runs. Wait for the stage" else "\($c) is not bound. Run: CELL=\($c) mise run cell:up" end),
        (if .hostsvc.running != true then "the host service is not running. Run: mise run hostsvc:serve -- start"
         elif .hostsvc.expires_soon then "the host service certificate expires soon. Run: mise run hostsvc:serve -- restart"
         elif .hostsvc.check != "" then "host service: " + .hostsvc.check else empty end)
      ] end | . + (if $clockp != "" then [$clockp] else [] end)'
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
  local now clock_problem
  read_clock
  jq -c --argjson now "$now" --arg clockp "$clock_problem" --argjson syncmax "$GATEWAY_SYNC_MAX_AGE" 'def ts: try (sub("\\.[0-9]+Z$"; "Z") | fromdateiso8601) catch 0;
    def recent($t; $secs): ($t | ts) > 1000000000 and ($now - ($t | ts)) < $secs;
    .gateway as $g | .bound as $bound | .mgmt_up as $up
    | if $g.error != null then ["gateway status failed: " + $g.error]
      else [
        (if ($g.storeError // "") != "" then "the cell gateway reports a store error: \($g.storeError). Run: mise run gw:reset" else empty end),
        (if ($g.syncedAt | ts) < 1000000000 or ($now - ($g.syncedAt | ts)) > $syncmax
         then "envd synced with the gateway at \($g.syncedAt // "never"), which is more than 2 minutes ago. Read the log of envd with: mise x -- kubectl --context kind-dev-cp -n envd-system logs deploy/envd -c envd. Then run: CELL=dev-cp mise run cell:up" else empty end),
        (if $up and ($g.outboxItems // 0) > 0 and (($g.oldestOutboxAt | ts) > 1000000000) and ($now - ($g.oldestOutboxAt | ts)) > 120
         then "the oldest outbox item of the gateway is from \($g.oldestOutboxAt), more than 2 minutes ago, and mgmtd answers. Run: mise run gw -- outbox" else empty end),
        (if recent($g.droppedAt; 900) then "the gateway dropped an outbox item at \($g.droppedAt), within the last 15 minutes. Run: mise run gw -- outbox" else empty end),
        (if recent($g.recordOldAt; 900) then "the gateway refused an older record at \($g.recordOldAt), within the last 15 minutes. Run: CELL=dev-cp mise run cell:up" else empty end),
        ($bound[] as $c | select(($g.streams[$c] // 0) < 1) | "the gateway holds no stream of \($c). Run: CELL=\($c) mise run cell:up"),
        (($g.mostClaimed // {}) | to_entries[] | select(.value.count > 3)
          | "the cell \(.key) claimed operation \(.value.opId) \(.value.count) times. Run: mise run ops -- trace \(.value.opId)")
      ] end | . + (if $clockp != "" then [$clockp] else [] end)'
}

# management_extras prints the fields of the management object, as one JSON object.
management_extras() {
  local now clock_problem logs agents samples kiali_json mesh_out mesh_rc=0 down="" absent="" entry cell ready conf expected plane

  # The principal lists an agent as connected until its last stream line closes the stream. The kubelet rotates the log after
  # about 10 hours, and the connect line goes with it. An agent with no stream line in the log counts as connected when the
  # principal received an event from it in the last 5 minutes, because events arrive for as long as the stream is open.
  logs="$(kubectl --context kind-management -n central-view-system logs deploy/argocd-agent-principal -c argocd-agent-principal 2>/dev/null || true)"
  # A cell with no cluster has no agent, sample or tunnel, so the lists hold only the cells that are live.
  view_live="" mesh_live="" clusters_live=""
  for cell in $VIEW_CELLS; do [[ " $live " != *" $cell "* ]] && grep -qx -- "$cell" <<<"$catalog" || view_live+="$cell "; done
  for entry in $MESH_VIEW_CELLS; do cell="${entry%%=*}"; [[ " $live " != *" $cell "* ]] && grep -qx -- "$cell" <<<"$catalog" || mesh_live+="$entry "; done
  for cell in $clusters; do [[ " $live " != *" $cell "* ]] && grep -qx -- "$cell" <<<"$catalog" || clusters_live+="$cell"$'\n'; done
  expected="$(for cell in $view_live; do echo "$POC_ENV-$cell"; done | jq -Rsc 'split("\n") | map(select(length > 0))')"
  read_clock
  agents="$(jq -Rsc --argjson now "$now" --argjson expected "$expected" '
      def ts: try (sub("\\.[0-9]+Z$"; "Z") | fromdateiso8601) catch 0;
      [split("\n")[] | fromjson? | select(type == "object" and .client != null)] as $lines
      | [$lines[] | select(.msg == "An agent connected to the subscription stream" or .msg == "Closing EventStream")]
      | group_by(.client) | map({client: .[0].client, up: (.[-1].msg != "Closing EventStream")}) as $last
      | ([$last[].client]) as $seen
      | ([$lines[] | select((.msg // "" | startswith("Event received")) and ((.time // "") | ts) > ($now - 300)) | .client] | unique) as $active
      | ([$last[] | select(.up) | .client] + ($active - $seen) | unique | sort) as $up
      | {expected: $expected, connected: ($expected - ($expected - $up)), missing: ($expected - $up)}' <<<"$logs")"

  # The age of the newest sample of each cluster in the Prometheus of lgtm.
  samples="$(kubectl --context kind-management -n observability-system exec lgtm-0 -c lgtm -- curl -s --max-time 20 \
    --data-urlencode 'query=time() - max by (k8s_cluster_name) (timestamp(up))' http://127.0.0.1:9090/api/v1/query 2>/dev/null \
    | jq -c '[.data.result[]? | select(.metric.k8s_cluster_name != null) | {key: .metric.k8s_cluster_name, value: (.value[1] | tonumber | floor)}] | from_entries' 2>/dev/null)" || samples=""
  [[ -n "$samples" ]] || samples='{}'
  samples="$(jq -c --arg clusters "$clusters_live" --argjson max "$max_age" '. as $s | {samples: ., stale: [$clusters | split("\n")[] | select(length > 0) | select(($s[.] == null) or $s[.] >= $max)]}' <<<"$samples")"

  # Kiali reads every cell once at start. While a cell is down, it stops in discovery and restarts until all answer.
  # A cell is absent only when its own API does not answer. A tunnel that is down while the API answers has another cause.
  for entry in $mesh_live; do
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
  kiali_json="$(jq -Rsc --arg ready "${ready:-0}" --arg cells "$mesh_live" --arg down "$down" --arg absent "$absent" '
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

# provisioning_problems prints the problems of provisioning as a JSON array of {cluster, problem}. A problem names the cluster whose
# object carries it. It reads mgmt -- status for the cells and their steps, the journal and the step logs of the host service, the
# ConfigMap step-status of dev-cp and the status of the host service. When mgmtd does not answer it prints [], because the object of
# management already reports that. The times of the journal come from the clock of the Mac and every other time from a node.
provisioning_problems() {
  local st now clock_problem mac_now states stuck id cell state kind secs limit hs serve pub staged wantkeys='null' sat="" jadmit=false admit_at=0
  local extra='[]' marker=false open_steps=false flag=-d
  st="$(mise run mgmt -- status 2>/dev/null)" || st=""
  if ! jq -e 'type == "object" and has("signed")' >/dev/null 2>&1 <<<"$st"; then
    echo '[]'
    return
  fi
  addp() { extra="$(jq -c --arg c "$1" --arg p "$2" '. + [{cluster: $c, problem: $p}]' <<<"$extra")"; }
  [[ ! -e "$BUILD_ROOT/gate/m6-provision" ]] || marker=true

  # The journal and the step logs hold the times of the Mac.
  mac_now="$(date +%s)"
  if states="$(journal_states 2>/dev/null)" && stuck="$(stuck_steps "$mac_now" 2>/dev/null)"; then
    ! grep -qx admitting <<<"$states" || jadmit=true
    admit_at="$(admit_end 2>/dev/null)" || admit_at=0
    [[ "$admit_at" =~ ^[0-9]+$ ]] || admit_at=0
    while read -r id cell state kind secs limit; do
      [[ -n "$id" ]] || continue
      if [[ "$kind" == heartbeat ]]; then
        addp "$cell" "the step $id of $cell is in the stage $state, and its heartbeat is $secs seconds old, which is more than 2 minutes. Run: mise run hostsvc:serve -- restart --force"
      else
        addp "$cell" "the step $id of $cell has run the stage $state for $((secs / 60)) minutes, which is more than its timeout of $(((limit - STEP_STAGE_GRACE) / 60)) minutes plus 5. Run: mise run hostsvc:serve -- restart --force"
      fi
    done <<<"$stuck"
  else
    addp management "the step journal of the host service does not parse. Run: mise run hostsvc:serve -- steps --reset"
  fi

  # step-status is the progress that the cell controller writes while a step is open, so its time is read only then.
  if jq -e '[.cells[]? | select(.step != null and ((.step.doneAt // "") == "" or (.step.doneAt | startswith("0001-"))))] | length > 0' >/dev/null <<<"$st"; then
    open_steps=true
  fi
  if [[ "$open_steps" == true ]] && grep -qx dev-cp <<<"$(existing_clusters 2>/dev/null)"; then
    sat="$(kubectl --context kind-dev-cp -n cell-controller-system get configmap step-status -o jsonpath='{.data.status\.json}' 2>/dev/null | jq -r '.at // ""' 2>/dev/null)" || sat=""
  fi

  # The keys that the host service must trust are the signing key of mgmtd and the staged key.
  serve="$(hostsvc_serve_script)"
  hs="$("$serve" status 2>/dev/null)" || hs=""
  jq -e 'type == "object"' >/dev/null 2>&1 <<<"$hs" || hs='{"running":false}'
  printf 'AA==' | base64 -d >/dev/null 2>&1 || flag=-D
  pub="$(mise run mgmt -- pubkey 2>/dev/null | jq -r '."spec.pub" // ""' 2>/dev/null)" || pub=""
  if [[ -n "$pub" ]]; then
    staged="$(jq -r '.stagedKey // ""' <<<"$st")"
    wantkeys="$({ printf '%s' "$pub" | base64 "$flag" | shasum -a 256 | cut -d' ' -f1; [[ -z "$staged" ]] || echo "$staged"; } | jq -Rcn '[inputs] | sort')"
  fi

  # retryAt and the journal times come from the clock of the Mac (macnow). Every other time comes from a node (now).
  read_clock
  jq -c --arg live "$live" --arg catalog "$(catalog_cells | paste -sd' ' -)" --argjson now "$now" --arg clockp "$clock_problem" \
    --argjson marker "$marker" --argjson jadmit "$jadmit" --argjson admitat "$admit_at" --argjson macnow "$mac_now" --arg sat "$sat" --argjson hs "$hs" --argjson wantkeys "$wantkeys" --argjson extra "$extra" '
    def ts: try (sub("\\.[0-9]+Z$"; "Z") | fromdateiso8601) catch 0;
    def isopen: . != null and .step != null and ((.step.doneAt // "") | (. == "" or startswith("0001-")));
    def words: split(" ") | map(select(length > 0));
    . as $m | ($live | words) as $lv | ($catalog | words) as $cat | .cells as $cells
    | (any($cells[]?; isopen and .step.host != null and .step.host.id == .step.id and .step.host.state == "admitting") or $jadmit) as $admitting
    | ([$cat[] as $c
        | ([$cells[]? | select(.name == $c)] | first // null) as $cs
        | ($lv | index($c) != null) as $islive
        | ($cs != null and $cs.requested == true) as $req
        | ($cs | isopen) as $open
        | ($cs.step.host // null) as $host
        | (if $host != null and $host.id == $cs.step.id then $host else null end) as $h
        | (
          (if $islive and $req and ($cs.invalidSince | ts) > 1000000000 and ($now - ([($cs.invalidSince | ts), $admitat] | max)) > 300 and ($open | not) and ($admitting | not)
           then {cluster: $c, problem: "the cell \($c) has been invalid since \($cs.invalidSince) (\($cs.validReason // "no reason")), which is more than 5 minutes, and no step is open. Run: CELL=\($c) mise run cell:verify"} else empty end),
          (if $open and ($cs.step.expiresAt | ts) > 1000000000 and ($cs.step.expiresAt | ts) < $now
           then {cluster: $c, problem: "the open step \($cs.step.id) of \($c) expired at \($cs.step.expiresAt). Run: mise run portal -- retry --cell \($c)"} else empty end),
          (if $open and $h != null and $h.state == "failed" and ($h.retryAt | ts) > 1000000000 and ($h.retryAt | ts) + 30 > $macnow
           then {cluster: $c, problem: "the open step \($cs.step.id) of \($c) is failed\(if ($h.reason // "") != "" then " (" + $h.reason + ")" else "" end), and the cell controller sends it again at \($h.retryAt). Wait until then"} else empty end),
          (if $open and $h != null and (($h.state == "failed" and (($h.retryAt | ts) + 30 <= $macnow)) or $h.state == "failed_final" or $h.state == "refused")
           then {cluster: $c, problem: "the open step \($cs.step.id) of \($c) is \($h.state)\(if ($h.reason // "") != "" then " (" + $h.reason + ")" else "" end). Run: mise run portal -- retry --cell \($c)"} else empty end),
          (if $open and $h != null and $h.lastHostError != null and ($h.lastHostError.at | ts) > 1000000000 and ($now - ($h.lastHostError.at | ts)) > 120
           then {cluster: $c, problem: (if $h.lastHostError.reason == "hostsvc_untrusted"
              then "the cell controller has not trusted the host service since \($h.lastHostError.at), for the step of \($c). Run: mise run hostsvc:serve -- restart"
              else "the cell controller has not reached the host service since \($h.lastHostError.at) (\($h.lastHostError.reason)), for the step of \($c). Run: mise run hostsvc:serve -- status" end)} else empty end),
          (if $req and ($islive | not) and ($open | not)
           then {cluster: $c, problem: "the cell \($c) is requested and has no cluster, and no step is open. Run: mise run portal -- recreate --cell \($c)"} else empty end),
          (if $islive and ($req | not)
           then {cluster: $c, problem: "the cell \($c) has a cluster and is not requested. Run: mise run portal -- request --cell \($c), or run: CELL=\($c) mise run cell:down"} else empty end),
          (if ($req | not) and ($islive | not)
           then {cluster: $c, problem: "the cell \($c) is neither requested nor live. Run: \(if $marker then "mise run gate:m6:repair" else "mise run portal -- request --cell \($c) --wait" end)"} else empty end)
        )]
      + [if ([$cells[]? | select(isopen)] | length) > 0 and ($sat == "" or ($sat | ts) == 0 or ($now - ($sat | ts)) > 90)
         then {cluster: "dev-cp", problem: "a step is open, and step-status of the cell controller is \(if $sat == "" then "absent" else "from \($sat)" end), which is more than 90 seconds old. Run: CELL=dev-cp HARNESS_ONLY=cell-controller mise run cell:restart"} else empty end]
      + [if $hs.running == true then
          (if ($hs.dev_root_sha256 // "") == "" then {cluster: "management", problem: "the host service has no dev-root.crt. Run: mise run hostsvc:serve -- sync"} else empty end),
          (if $wantkeys == null then {cluster: "management", problem: "mgmtd prints no signing key, so the keys of the host service are unchecked. Run: mise run mgmt -- pubkey"}
           elif (($hs.keys // []) | sort) != $wantkeys then {cluster: "management", problem: "the host service trusts the keys \(($hs.keys // []) | tojson), and mgmtd holds \($wantkeys | tojson). Run: mise run hostsvc:serve -- sync"} else empty end),
          (if ($hs.spec_revision | tojson) != ($m.signed | tojson) and (($m.hostSpecPushedAt // "") | ts) < ($now - 120)
           then {cluster: "management", problem: "the host service knows the spec revision \($hs.spec_revision | tojson), and mgmtd signed \($m.signed | tojson), for more than 2 minutes. Run: mise run hostsvc:serve -- sync, or run: CELL=management LINK_ONLY=mgmt-api mise run cell:link"} else empty end)
        else empty end]
      + $extra
      + (if $clockp != "" then [{cluster: "management", problem: $clockp}] else [] end))' <<<"$st"
}

# bundle_problems prints the problems of the signed bundle sets as a JSON array of {cluster, problem}, for each cluster with the bundle role cell or cp
# that exists. It reads ConfigMap bundle-state, the sync revision of the Application root and the AppProjects of the cluster, and mise run mgmt -- status
# for the allow-list digest that the applier reports and for the set of the control plane. A cell with no cluster has none of them. The ages come from the
# clock of a node. A state that is a wait gives no problem: applying or rolling_back with an until in the future or less than 10 minutes in the past.
bundle_problems() {
  local st cluster role ns state root_rev projects projs reported out now clock_problem extra='[]'
  st="$(mise run mgmt -- status 2>/dev/null)" || st=""
  addp() { extra="$(jq -c --arg c "$1" --arg p "$2" '. + [{cluster: $c, problem: $p}]' <<<"$extra")"; }
  # The allow-list comparison and the open-set check of dev-cp read this status. Without it they cannot run, and the object of management says so.
  if ! jq -e 'type == "object" and has("signed")' >/dev/null 2>&1 <<<"$st"; then
    st='{}'
    addp management "the bundle checks that read the status of mgmtd (the allow-list digest of each applier and the open set of dev-cp) did not run, because mise run mgmt -- status gave no status. Run: mise run mgmt -- status"
  fi
  read_clock
  for cluster in $clusters; do
    role="$(bundle_role_of "$cluster" 2>/dev/null)" || continue
    [[ "$role" == cell || "$role" == cp ]] || continue
    if grep -qx -- "$cluster" <<<"$catalog" && [[ " $live " != *" $cluster "* ]]; then continue; fi
    ns="$(bundle_state_ns "$role")"
    if ! state="$(kubectl --context "kind-$cluster" -n "$ns" get configmap bundle-state --ignore-not-found -o 'jsonpath={.data.state\.json}' 2>&1)"; then
      addp "$cluster" "the bundle state of $cluster cannot be read: ${state//$'\n'/ }. Run: CELL=$cluster mise run cell:verify"
      continue
    fi
    [[ -n "$state" ]] || state='{}'
    if ! jq -e 'type == "object"' >/dev/null 2>&1 <<<"$state"; then
      addp "$cluster" "ConfigMap bundle-state of $cluster holds no JSON object. Run: mise run bundle -- publish --target $cluster --wait"
      continue
    fi
    if ! root_rev="$(kubectl --context "kind-$cluster" -n argocd get application root -o 'jsonpath={.status.sync.revision}' 2>&1)"; then
      addp "$cluster" "the Application root of $cluster cannot be read, so its root is not compared with the bundle state: ${root_rev//$'\n'/ }. Run: CELL=$cluster mise run cell:verify"
      root_rev=""
    fi
    if ! projects="$(kubectl --context "kind-$cluster" -n argocd get appprojects -o json 2>&1)"; then
      addp "$cluster" "the AppProjects of $cluster cannot be read, so their allow-list digest is not compared: ${projects//$'\n'/ }. Run: CELL=$cluster mise run cell:verify"
      projects='{"items":[]}'
      projs='[]'
    elif ! projs="$(jq -c --arg role "$role" --argjson p "$projects" '[.roles[$role].appProjects[]? as $n
      | {name: $n, annotation: ([$p.items[]? | select(.metadata.name == $n) | .metadata.annotations["poc.internal/allow-sha256"]][0] // "")}]' "${BUNDLE_ALLOW_JSON:-$ROOT/internal/bundle/allow.json}")"; then
      addp "$cluster" "the AppProjects of $cluster could not be evaluated. Run: CELL=$cluster mise run cell:verify"
      projs='[]'
    fi
    reported="$(jq -r --arg role "$role" --arg c "$cluster" 'if $role == "cp" then .planeBundleStatus.allowSHA256 // ""
      else [.cells[]? | select(.name == $c) | .bundleStatus.allowSHA256 // empty][0] // "" end' <<<"$st")"
    out="$(jq -c --arg c "$cluster" --arg role "$role" --arg rootrev "$root_rev" --arg reported "$reported" --argjson projs "$projs" --argjson now "$now" --argjson m "$st" '
      def ts: try (sub("\\.[0-9]+Z$"; "Z") | fromdateiso8601) catch 0;
      def pub: "Run: mise run bundle -- publish --target \($c) --wait";
      (if (.source // "") != "signed" then
        ["\($c) has no signed bundle state (source \(.source // "absent")), so it runs no set that mgmtd signed. \(pub)"]
      else
        [(if .state == "rolled_back" and (.result.detail // "") == "rollback_unhealthy"
          then "the bundle state of \($c) is rolled_back with rollback_unhealthy, so the rollback did not finish and the cluster does not run the last good root. Run: mise run bundle -- repair --target \($c)"
          elif .state == "rolled_back"
          then "the bundle state of \($c) is rolled_back (\(.result.detail // "no detail")), so it runs the last good set and not the newest one. \(pub)"
          else empty end),
         (if (.state == "applying" or .state == "rolling_back") and ((.until // "") | ts) > 1000000000 and ($now - ((.until // "") | ts)) > 600
          then "the bundle state of \($c) has been \(.state) since before \(.until), which is more than 10 minutes. \(pub)" else empty end),
         (if (.state == "healthy" or .state == "rolled_back") and $rootrev != "" and $rootrev != (.root.digest // "")
          then "the Application root of \($c) is at \($rootrev), and the bundle state records the root \(.root.digest // "none"). \(pub)" else empty end)]
      end)
      + (if $reported == "" then [] else
          [$projs[] | select(.annotation != $reported)
            | if .annotation == "" then "the AppProject \(.name) of \($c) has no annotation poc.internal/allow-sha256, and the applier reports allowSHA256 \($reported). \(pub)"
              else "the AppProject \(.name) of \($c) carries allowSHA256 \(.annotation), and the applier reports allowSHA256 \($reported). \(pub)" end] end)
      + (if $role == "cp" and ($m.planeBundle // null) != null and $m.planeBundle.served == true and ($m.planeBundle.result // null) == null
            and (($m.planeBundle.issuedAt // "") | ts) > 1000000000 and ($now - (($m.planeBundle.issuedAt // "") | ts)) > 300
            and ((($m.planeBundleStatus.state // "") | IN("applying", "rolling_back")) | not)
          then ["envd reported the set \($m.planeBundle.opId // "") of \($c), and mgmtd has not closed its result for more than 5 minutes (issued at \($m.planeBundle.issuedAt), expires at \($m.planeBundle.expiresAt // "an unknown time")). Run: mise run bundle -- get --target \($c)"]
          else [] end)' <<<"$state")" || { addp "$cluster" "the bundle state of $cluster could not be evaluated. Run: CELL=$cluster mise run cell:verify"; continue; }
    extra="$(jq -c --arg c "$cluster" --argjson add "$out" '. + [$add[] | {cluster: $c, problem: .}]' <<<"$extra")"
  done
  printf '%s\n' "$extra"
}

# collect <cluster> writes the JSON object of one cluster to $tmp/<cluster>.json.
collect() {
  local cluster="$1" apps verify telemetry extras='{}' mp='[]' plane
  apps="$(applications "$cluster")"
  verify="$(run_verify "$cluster")"
  telemetry="$(run_telemetry "$cluster")"
  if [[ "$cluster" == management ]]; then
    extras="$(management_extras)"
    mp="$(jq -c .management <<<"$extras" | management_problems "$live")"
  fi
  if [[ "$cluster" == dev-cp ]]; then
    plane="$(gateway_plane)"
    extras="$(jq -c --argjson ttl "$(svid_ttl_json)" '{gateway, svidTTL: $ttl}' <<<"$plane")"
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
    | ([if $cluster == "dev-cp" and any($verify.failed[]; contains("admit lists"))
        then "the admit lists of dev-cp differ from the live cells. Run: CELL=dev-cp mise run cell:up" else empty end]) as $l
    | ($a + $v + $t + $m + $l + $mp) as $problems
    | {cluster: $cluster, ok: ($problems | length == 0), applications: $apps, verify: $verify, telemetry: $telemetry}
      + $extras + {problems: $problems}' >"$tmp/$cluster.json"
}

for cluster in $clusters; do
  if grep -qx -- "$cluster" <<<"$catalog" && [[ " $live " != *" $cluster "* ]]; then
    log "$cluster has no cluster"
    jq -nc --arg cluster "$cluster" '{cluster: $cluster, ok: true, absent: true, problems: []}' >"$tmp/$cluster.json"
    continue
  fi
  log "reading $cluster"
  collect "$cluster" &
done
wait

# The problems of provisioning read the clocks after the verify steps, so their ages are current. Each one joins the object of the
# cluster that it names.
log "reading the steps"
if ! m6="$(provisioning_problems 2>"$tmp/m6.err")" || ! jq -e 'type == "array"' >/dev/null 2>&1 <<<"$m6"; then
  m6="$(jq -nc --arg e "$(tail -n 1 "$tmp/m6.err" 2>/dev/null)" '[{cluster: "management", problem: "the steps could not be read\(if $e != "" then ": " + $e else "" end). Run: mise run mgmt -- status"}]')"
fi

log "reading the bundle states"
if ! m8="$(bundle_problems 2>"$tmp/m8.err")" || ! jq -e 'type == "array"' >/dev/null 2>&1 <<<"$m8"; then
  m8="$(jq -nc --arg e "$(tail -n 1 "$tmp/m8.err" 2>/dev/null)" '[{cluster: "management", problem: "the bundle states could not be read\(if $e != "" then ": " + $e else "" end). Run: mise run mgmt -- status"}]')"
fi
m6="$(jq -c --argjson b "$m8" '. + $b' <<<"$m6")"

status=0
for cluster in $clusters; do
  if [[ -s "$tmp/$cluster.json" ]]; then
    jq -c --arg c "$cluster" --argjson m6 "$m6" '.problems += [$m6[] | select(.cluster == $c) | .problem] | .ok = (.problems | length == 0)' "$tmp/$cluster.json" >"$tmp/$cluster.out"
    cat "$tmp/$cluster.out"
    jq -e .ok "$tmp/$cluster.out" >/dev/null || status=1
  else
    jq -nc --arg cluster "$cluster" '"the status script could not read the cluster" as $why
      | {cluster: $cluster, ok: false, applications: {total: 0, bad: [$why]}, verify: {ok: false, failed: [$why]},
        telemetry: {ok: false, wait: false, verdict: $why}, problems: [$why + ". Run: CELL=\($cluster) mise run cell:verify"]}'
    status=1
  fi
done
((status == 0)) && log "every cluster is healthy" || log "at least one value is bad. Read the problems field of each object"
exit "$status"
