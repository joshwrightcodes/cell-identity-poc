#!/usr/bin/env bash
# Run mgmtd ctl in the pod mgmtd-0 of management: mise run mgmt -- status|records|pubkey|keys|keycheck|restore|rotate-key.
# The command rotate-signing-key runs scripts/mgmt-rotate-key.sh: the rotation, then the render of the new key and the verify of both clusters.
# The admin socket of mgmtd is a unix socket in the pod, so the command runs there. The binary prints
# one JSON line. When mgmtd-0 is absent or not Ready, the script prints one JSON error line that
# names the link command, and exits with status 1.
export CELL="${CELL:-management}"
source "$(dirname "$0")/lib.sh"

if [[ "${1:-}" == rotate-signing-key ]]; then
  shift
  exec "$(dirname "$0")/mgmt-rotate-key.sh" "$@"
fi

ready="$(k -n mgmt-system get pod mgmtd-0 -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null || true)"
[[ "$ready" == True ]] || json_fail mgmt "pod mgmtd-0 is absent or not Ready. Run: CELL=management LINK_ONLY=mgmt-api mise run cell:link"
exec kubectl --context "kind-$CELL_NAME" -n mgmt-system exec mgmtd-0 -c mgmtd -- /ko-app/mgmtd ctl "$@"
