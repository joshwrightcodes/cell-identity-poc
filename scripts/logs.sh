#!/usr/bin/env bash
# Print the log lines of the pods that match a label selector, as JSON lines on standard output, each with
# the field "cluster". Usage: logs.sh <cluster or all> <label selector>
#
# "all" reads every cluster that has components in harness/topology.yaml. A line that is not a JSON object
# becomes {"cluster": ..., "raw": <line>}. A field "cluster" that a log line already holds moves to
# "source_cluster". A cluster that cannot be read gives one error line with its name, and the exit status is 1
# at the end, so the logs of the other clusters stay readable. LOGS_TAIL (default 200) is the number of lines
# for each container, and LOGS_SINCE (for example 10m) limits their age.
source "$(dirname "$0")/lib.sh"

target="${1:-}"
selector="${2:-}"
clusters="$(yq -r '.clusters[] | select(.components | length > 0) | .name' "$ROOT/harness/topology.yaml")"
if [[ -z "$target" || -z "$selector" ]]; then
  json_fail harness:logs "two arguments are required. Usage: mise run harness:logs <cluster or all> <label selector>"
fi
if [[ "$target" == all ]]; then
  targets="$clusters"
elif grep -qx -- "$target" <<<"$clusters"; then
  targets="$target"
else
  json_fail harness:logs "the argument '$target' is not all or a cluster with components: $(paste -sd' ' - <<<"$clusters"). Usage: mise run harness:logs <cluster or all> <label selector>"
fi

wrap() {
  jq -Rc --arg cluster "$1" '(fromjson? | select(type == "object")) // {raw: .}
    | (if has("cluster") then .source_cluster = .cluster else . end) | .cluster = $cluster'
}

status=0
for cluster in $targets; do
  kc() { kubectl --context "kind-$cluster" "$@"; }
  if ! pods="$(kc get pods -A -l "$selector" -o json 2>&1)"; then
    jq -nc --arg cluster "$cluster" --arg error "could not list the pods: $pods" '{cluster: $cluster, level: "ERROR", msg: "logs failed", error: $error}'
    status=1
    continue
  fi
  list="$(jq -r '.items[] | "\(.metadata.namespace) \(.metadata.name)"' <<<"$pods")"
  if [[ -z "$list" ]]; then
    log "no pod in $cluster matches $selector"
    continue
  fi
  while read -r ns pod; do
    args=(-n "$ns" logs "$pod" --all-containers=true --tail="${LOGS_TAIL:-200}")
    [[ -z "${LOGS_SINCE:-}" ]] || args+=(--since="$LOGS_SINCE")
    if ! out="$(kc "${args[@]}" 2>&1)"; then
      jq -nc --arg cluster "$cluster" --arg error "could not read the log of $ns/$pod: $out" '{cluster: $cluster, level: "ERROR", msg: "logs failed", error: $error}'
      status=1
      continue
    fi
    [[ -z "$out" ]] || wrap "$cluster" <<<"$out"
  done <<<"$list"
done
exit "$status"
