#!/usr/bin/env bash
# Run cellgw ctl in the pod cell-gateway-0 of dev-cp: mise run gw -- status|queue --cell <c>|enqueue --cell <c> [--replay]|inject|outbox.
# The admin socket of the gateway is a unix socket in the pod, so the command runs there, as the user of the
# container. Standard input reaches the command, for enqueue and inject. The binary prints one JSON line. When
# cell-gateway-0 is absent or not Ready, the script prints one JSON error line and exits with status 1. A failed
# kubectl exec with no output also prints one JSON error line. When the container log ends with a store error,
# the line names mise run gw:reset. Otherwise it names the cell:up of dev-cp.
export CELL=dev-cp
source "$(dirname "$0")/lib.sh"

ready="$(k -n gateway-system get pod cell-gateway-0 -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null || true)"
if [[ "$ready" != True ]]; then
  tail="$(k --request-timeout=20s -n gateway-system logs cell-gateway-0 -c cellgw --tail=5 2>/dev/null || true)"
  if grep -qiE '"level":"ERROR".*(store|queue\.db|sqlite|database|corrupt|malformed|disk|full)' <<<"$tail"; then
    json_fail gw "pod cell-gateway-0 is absent or not Ready, and its log ends with a store error. Run: $(dependents_of gateway-store)"
  fi
  json_fail gw "pod cell-gateway-0 is absent or not Ready. Run: CELL=dev-cp mise run cell:up"
fi
# The reads that harness:status and the tests make carry a request timeout, so a pod that hangs cannot stall them.
timeout=()
case "${1:-}" in status | queue | outbox) timeout=(--request-timeout=60s) ;; esac
# The output is captured, so a kubectl failure that prints nothing on standard output still ends with one JSON error line.
rc=0
out="$(kubectl --context "kind-$CELL_NAME" ${timeout[@]+"${timeout[@]}"} -n gateway-system exec -i cell-gateway-0 -c cellgw -- /ko-app/cellgw ctl "$@")" || rc=$?
if ((rc != 0)) && [[ -z "$out" ]]; then
  json_fail gw "kubectl exec into cell-gateway-0 failed with exit code $rc and printed no output. Run: mise run harness:status" "kubectl_exit:=$rc"
fi
[[ -z "$out" ]] || printf '%s\n' "$out"
exit "$rc"
