#!/usr/bin/env bash
# Scan the logs of the M5 and M6 components for a token. Usage: gate-token-scan.sh <start time, RFC 3339 UTC>
# In each cluster with components, it reads the log of every container that runs the image cellgw, envd, mgmtd, celld, cell-proxy or
# cell-controller since the start time, and the previous log of a container that restarted. It reads each step log of the host service
# (build/hostsvc/steps/*.log, or the files in HOSTSVC_STEPS_DIR) in full, because a stage prints the output of a harness task. A line that
# holds a compact JWS (eyJ..., a dot, eyJ..., a dot) or the text PRIVATE KEY----- is a token or a key: the script prints the cluster, the
# pod, the container and the line number, or the step log and the line number, never the line, and exits 1. The standard
# base64 of any JSON object starts with eyJ, so a bare eyJ is no token. The logs of a pod that a test deleted are gone, and so is the log of a middle
# instance of a container that restarted twice. The scan cannot read either.
source "$(dirname "$0")/lib.sh"
source "$ROOT/scripts/steps-lib.sh"

since="${1:?usage: gate-token-scan.sh <start time, RFC 3339 UTC>}"
shape='eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]*\.|PRIVATE KEY-----'
status=0

# A cell has no cluster until its step creates it, so the scan reads the clusters that exist.
existing="$(existing_clusters)" || die "could not list the clusters"
for cluster in $(yq -r '.clusters[] | select(.components | length > 0) | .name' "$ROOT/harness/topology.yaml"); do
  grep -qx -- "$cluster" <<<"$existing" || continue
  targets="$(kubectl --context "kind-$cluster" get pods -A -o json | jq -r '.items[] | . as $p
    | $p.spec.containers[] | select(.image | test("/(cellgw|envd|mgmtd|celld|cell-proxy|cell-controller)(@|:|$)")) | .name as $c
    | "\($p.metadata.namespace) \($p.metadata.name) \($c) \(([$p.status.containerStatuses[]? | select(.name == $c) | .restartCount] | first) // 0)"')" \
    || die "could not list the pods of $cluster"
  while read -r ns pod container restarts; do
    [[ -n "$pod" ]] || continue
    for previous in "" --previous; do
      [[ -z "$previous" || "$restarts" -gt 0 ]] || continue
      # The previous log of a container can be gone, so a failed read of it is no failure.
      if ! log="$(kubectl --context "kind-$cluster" -n "$ns" logs "$pod" -c "$container" --since-time="$since" ${previous:+"$previous"} 2>&1)"; then
        [[ -n "$previous" ]] || die "could not read the log of $ns/$pod $container in $cluster: $log"
        continue
      fi
      lines="$(grep -nE "$shape" <<<"$log" | cut -d: -f1 || true)"
      for n in $lines; do
        echo "a token is in the log: $cluster $ns/$pod $container line $n${previous:+ (previous log)}"
        status=1
      done
    done
  done <<<"$targets"
done

# The step logs of the host service are on this Mac.
steps="$(steps_dir)"
for file in "$steps"/*.log; do
  [[ -e "$file" ]] || continue
  lines="$(grep -nE "$shape" "$file" | cut -d: -f1 || true)"
  for n in $lines; do
    echo "a token or a key is in a step log: $file line $n"
    status=1
  done
done
exit "$status"
