#!/usr/bin/env bash
# Usage: harness-replicas.sh <cluster> <namespace> <kind/name> <replicas>
# Change the replicas of a harness workload through its scale subresource, with the field manager
# harness-replicas. A server-side apply with the harness manager would own only spec.replicas, and
# the next apply would drop every other field that the harness owns. The patch leaves the rest of
# the object as it is. check_harness_objects accepts this manager only when it owns exactly
# spec.replicas, and the next harness apply takes the field back.
set -euo pipefail

die() { printf 'error: harness-replicas: %s\n' "$*" >&2; exit 1; }

(($# == 4)) || die "usage: harness-replicas.sh <cluster> <namespace> <kind/name> <replicas>"
cluster="$1" ns="$2" target="$3" replicas="$4"
[[ "$cluster" =~ ^[a-z0-9]([a-z0-9-]*[a-z0-9])?$ ]] || die "'$cluster' is not a cluster name"
[[ "$ns" =~ ^[a-z0-9]([a-z0-9-]*[a-z0-9])?$ ]] || die "'$ns' is not a namespace name"
[[ "$target" =~ ^[A-Za-z.]+/[a-z0-9]([a-z0-9.-]*[a-z0-9])?$ ]] || die "'$target' is not <kind>/<name>"
[[ "$replicas" =~ ^[0-9]+$ ]] || die "'$replicas' is not a number of replicas"

kubectl --context "kind-$cluster" -n "$ns" patch "$target" --subresource=scale --type=merge \
  -p "{\"spec\":{\"replicas\":$replicas}}" --field-manager=harness-replicas
