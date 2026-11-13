#!/usr/bin/env bash
# Report each hop of the telemetry path of one cluster, from its collector to the store, so that an
# operator finds the hop that fails. Usage: uplink-status.sh <cluster>
#
# The collector and the uplink are read in the cluster itself, with kubectl, so the answer does not
# depend on the path that may be down. The gateway and the store are read in management, from the
# Prometheus of lgtm.
#   collector  Ready replica; the size of the queue volume on the node (the file of the persistent queue,
#              which grows with the queue and shrinks at its next compaction); the lines "Exporting
#              failed" and "Dropping data" of its log in the last 5 minutes. The size is the peak of
#              the file since the last start or compaction, not the current queue.
#   uplink     Ready pod; the ERROR lines of cell-proxy in the last 5 minutes. management has no uplink.
#   gateway    accepted exports, refusals and upstream failures of the gateway for this sender in the last
#              5 minutes. management has no gateway hop.
#   store      the age of the newest sample of the cluster in Prometheus.
# Standard output holds one JSON object with a verdict that names the first failing hop. The exit status
# is 1 when a hop fails. A wrong argument prints one JSON error line.
source "$(dirname "$0")/lib.sh"

cluster="${1:-}"
case "$cluster" in
  management | dev-cp | dev-cell-1 | dev-cell-2) ;;
  *) json_fail obs:uplink-status "the argument '$cluster' is not management, dev-cp, dev-cell-1 or dev-cell-2. Usage: mise run obs:uplink-status <cluster>" ;;
esac
kc() { kubectl --context "kind-$cluster" -n observability-system "$@"; }

# prom <promql> prints the first value of an instant query in management, or empty.
prom() {
  kubectl --context kind-management -n observability-system exec lgtm-0 -c lgtm -- curl -s --max-time 20 \
    --data-urlencode "query=$1" http://127.0.0.1:9090/api/v1/query 2>/dev/null | jq -r '.data.result[0].value[1] // empty' 2>/dev/null
}

# Collector.
ready="$(kc get statefulset otel-collector -o jsonpath='{.status.readyReplicas}' 2>/dev/null || true)"
col_log="$(kc logs otel-collector-0 --since=5m 2>/dev/null || true)"
failed="$(grep -c '"msg":"Exporting failed' <<<"$col_log" || true)"
dropped="$(grep -c 'Dropping data' <<<"$col_log" || true)"
pv_path="$(kubectl --context "kind-$cluster" get pv -o json 2>/dev/null | jq -r '.items[] | select(.spec.claimRef.name == "queue-otel-collector-0" and .spec.claimRef.namespace == "observability-system") | .spec.local.path // .spec.hostPath.path' || true)"
queue_kb=""
[[ -z "$pv_path" ]] || queue_kb="$(docker exec "$cluster-control-plane" du -sk "$pv_path" 2>/dev/null | awk '{print $1}' || true)"
collector_ok=false
[[ "${ready:-0}" == 1 && "${dropped:-0}" == 0 ]] && collector_ok=true

# Uplink.
uplink_ok=null uplink_errors=null
if [[ "$cluster" != management ]]; then
  up_ready="$(kc get deployment otel-uplink -o jsonpath='{.status.readyReplicas}' 2>/dev/null || true)"
  uplink_errors="$(kc logs deploy/otel-uplink -c cell-proxy --since=5m 2>/dev/null | grep -c '"level":"ERROR"' || true)"
  uplink_ok=false
  [[ "${up_ready:-0}" == 1 && "${uplink_errors:-0}" == 0 ]] && uplink_ok=true
fi

# Gateway and store, from management.
accepted="" denied="" upstream=""
gateway_ok=null
if [[ "$cluster" != management ]]; then
  accepted="$(prom "sum(increase(cellproxy_gateway_exports_accepted_total{k8s_cluster_name=\"management\",sender_cluster=\"$cluster\"}[5m]))")"
  denied="$(prom "sum(increase(cellproxy_gateway_exports_denied_total{k8s_cluster_name=\"management\",sender_cluster=\"$cluster\"}[5m]))")"
  upstream="$(prom "sum(increase(cellproxy_gateway_upstream_failures_total{k8s_cluster_name=\"management\"}[5m]))")"
  gateway_ok=false
  awk -v a="${accepted:-0}" -v d="${denied:-0}" -v u="${upstream:-0}" 'BEGIN { exit !(a + 0 > 0 && d + 0 < 0.5 && u + 0 < 0.5) }' && gateway_ok=true
fi
age="$(prom "time() - max(timestamp(up{k8s_cluster_name=\"$cluster\"}))")"
store_ok=false
awk -v a="${age:-99999}" 'BEGIN { exit !(a + 0 < 120) }' && store_ok=true

verdict="every hop is healthy"
status=0
if [[ "$collector_ok" != true ]]; then
  verdict="collector: it is not Ready, or it dropped data. Read: mise x -- kubectl --context kind-$cluster -n observability-system logs otel-collector-0"; status=1
elif [[ "$uplink_ok" == false ]]; then
  verdict="uplink: its pod is not Ready, or cell-proxy logs errors. Read: mise x -- kubectl --context kind-$cluster -n observability-system logs deploy/otel-uplink -c cell-proxy"; status=1
elif [[ "$gateway_ok" == false ]]; then
  verdict="gateway or relay: the gateway accepted no export from $cluster in 5 minutes, or it refused one. Read: CELL=management mise run cell:verify, then CELL=dev-cp mise run cell:verify"; status=1
elif [[ "${failed:-0}" -gt 0 ]]; then
  verdict="collector export: the exporter of the collector failed and retried ${failed} times in 5 minutes. Read: mise x -- kubectl --context kind-$cluster -n observability-system logs otel-collector-0"; status=1
elif [[ "$store_ok" != true ]]; then
  verdict="store: the newest sample of $cluster is ${age:-unknown} seconds old. Read the collector first: mise x -- kubectl --context kind-$cluster -n observability-system logs otel-collector-0"; status=1
fi

jq -nc --arg cluster "$cluster" --arg verdict "$verdict" --argjson collector_ok "$collector_ok" --argjson uplink_ok "$uplink_ok" \
  --argjson gateway_ok "$gateway_ok" --argjson store_ok "$store_ok" --arg ready "${ready:-0}" --arg queue_kb "${queue_kb:-}" \
  --arg failed "${failed:-0}" --arg dropped "${dropped:-0}" --arg uplink_errors "$uplink_errors" --arg accepted "${accepted:-}" \
  --arg denied "${denied:-}" --arg upstream "${upstream:-}" --arg age "${age:-}" \
  '{cluster: $cluster, verdict: $verdict,
    collector: {ok: $collector_ok, ready_replicas: ($ready | tonumber), queue_file_peak_kib: ($queue_kb | tonumber? // null), exporting_failed_5m: ($failed | tonumber), dropped_5m: ($dropped | tonumber)},
    uplink: {ok: $uplink_ok, error_lines_5m: ($uplink_errors | tonumber? // null)},
    gateway: {ok: $gateway_ok, accepted_5m: ($accepted | tonumber? // null), refused_5m: ($denied | tonumber? // null), upstream_failures_5m: ($upstream | tonumber? // null)},
    store: {ok: $store_ok, newest_sample_age_s: ($age | tonumber? // null)}}'
exit "$status"
