#!/usr/bin/env bash
# Print the memory and CPU of every kind node container and the registry, then the VM memory.
source "$(dirname "$0")/lib.sh"

containers="$(
  docker ps --filter label=io.x-k8s.kind.cluster --format '{{.Names}}'
  docker ps --filter name=registry-mirror --format '{{.Names}}'
)"
[[ -n "$containers" ]] || die "no kind node or registry container is running"
# shellcheck disable=SC2086
docker stats --no-stream --format 'table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.MemPerc}}' $containers
echo
colima ssh --profile poc -- free -m
