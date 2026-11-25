#!/usr/bin/env bash
# Run mgmtd ctl in the pod mgmtd-0 of management: mise run mgmt -- status|records|pubkey|keys|keycheck|revoke|unrevoke|restore|rotate-key.
# The command reset-state runs scripts/mgmt-reset-state.sh: it moves a lost or invalid state aside and restarts mgmtd with a new key.
# The command rotate-signing-key [--emergency | --step <name>] runs scripts/mgmt-rotate-key.sh: the overlap rotation, the render of the new key and the verify of both clusters.
# The admin socket of mgmtd is a unix socket in the pod, so the command runs there. The binary prints
# one JSON line. When mgmtd-0 is absent or not Ready, the script prints one JSON error line that
# names the link command, and exits with status 1. A failed kubectl exec with no output also prints one JSON error line.
# The commands step sign and bundle sign read JSON on standard input (the step, or the components of a set), so only these
# commands run kubectl exec with -i. Another command would take the standard input of a shell loop that calls this script.
# mgmtd runs in management only. A caller can inherit another CELL (scripts/ops.sh exports dev-cp), so the script never takes it.
export CELL=management
source "$(dirname "$0")/lib.sh"

if [[ "${1:-}" == rotate-signing-key ]]; then
  shift
  exec "$(dirname "$0")/mgmt-rotate-key.sh" "$@"
fi

if [[ "${1:-}" == reset-state ]]; then
  shift
  exec "$(dirname "$0")/mgmt-reset-state.sh" "$@"
fi

ready="$(k -n mgmt-system get pod mgmtd-0 -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null || true)"
[[ "$ready" == True ]] || json_fail mgmt "pod mgmtd-0 is absent or not Ready. Run: CELL=management LINK_ONLY=mgmt-api mise run cell:link"
# The reads that harness:status and the tests make carry a request timeout, so a pod that hangs cannot stall them.
timeout=()
case "${1:-}" in status | records | pubkey | keys) timeout=(--request-timeout=60s) ;; esac
# The output is captured, so a kubectl failure that prints nothing on standard output still ends with one JSON error line.
rc=0
stdin=()
[[ "${2:-}" != sign || ( "${1:-}" != step && "${1:-}" != bundle ) ]] || stdin=(-i)
out="$(kubectl --context "kind-$CELL_NAME" ${timeout[@]+"${timeout[@]}"} -n mgmt-system exec ${stdin[@]+"${stdin[@]}"} mgmtd-0 -c mgmtd -- /ko-app/mgmtd ctl "$@")" || rc=$?
if ((rc != 0)) && [[ -z "$out" ]]; then
  json_fail mgmt "kubectl exec into mgmtd-0 failed with exit code $rc and printed no output. Run: mise run harness:status" "kubectl_exit:=$rc"
fi
[[ -z "$out" ]] || printf '%s\n' "$out"
exit "$rc"
