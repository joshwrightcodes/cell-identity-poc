#!/usr/bin/env bash
# Stop and start the Colima VM, wait until every node is Ready, then run the M1 gate. A restart gives each node a new address, and the
# policies of dev-cp hold the old addresses. The last step fails when rogue takes an address that a policy still admits, and a pass does
# not show that the harness works. Rebuild with harness:down and harness:up afterwards. An API server that does not answer yet counts as
# not ready, and the loop keeps waiting for it.
source "$(dirname "$0")/lib.sh"

cd "$ROOT"
wait_seconds="${RESTART_WAIT_SECONDS:-300}"

mise run vm:down
mise run vm:up

log "container states after the restart"
docker ps -a --format '{{.Names}}\t{{.Status}}' | sort >&2

clusters="$(yq -r '.clusters[].name' "$ROOT/harness/topology.yaml")"
deadline=$((SECONDS + wait_seconds))
for name in $clusters; do
  while true; do
    not_ready="$(kubectl --context "kind-$name" get nodes --no-headers 2>/dev/null | awk '$2 != "Ready"' || true)"
    count="$(kubectl --context "kind-$name" get nodes --no-headers 2>/dev/null | wc -l | tr -d ' ')" || count=0
    if [[ "$count" -gt 0 && -z "$not_ready" ]]; then
      log "$name: every node is Ready"
      break
    fi
    ((SECONDS < deadline)) || die "$name: nodes not Ready within ${wait_seconds}s. Nodes: ${not_ready:-none listed}"
    sleep 5
  done
done

mise run gate:m1
