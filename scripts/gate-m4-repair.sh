#!/usr/bin/env bash
# Repair what a gate:m4 run can leave behind: a host service that is down, or that serves another
# pin or another management root than the deployed ones, and a StatefulSet mgmtd or a Deployment envd with
# another number of replicas than 1. The tests stop the host service on purpose, and they set the replicas
# through scripts/harness-replicas.sh. A run that stopped before its cleanups leaves both. It is safe to run again.
#
# Usage: gate-m4-repair.sh [--check]
#   --check prints each drift with the command that repairs it, and exits 1. It exits 0 when it finds none.
# The repair starts the host service and runs the link of mgmt-api when the pin or the root drifted
# (hostsvc-serve.sh restart), and sets the replicas of mgmtd and envd back to 1 (harness-replicas.sh).
# HOSTSVC_SERVE names another host service script, for the tests.
export CELL=management
source "$(dirname "$0")/lib.sh"

serve="${HOSTSVC_SERVE:-$ROOT/scripts/hostsvc-serve.sh}"
check=0
[[ "${1:-}" == "--check" ]] && check=1
repair="mise run gate:m4:repair"

# hostsvc_drift prints why the host service does not match the deployed pin and the live root.
hostsvc_drift() {
  local status running cert root live pin
  status="$("$serve" status)" || { echo "the host service status failed"; return; }
  running="$(jq -r '.running' <<<"$status")"
  [[ "$running" == true ]] || { echo "the host service does not run"; return; }
  cert="$(jq -r '.cert_sha256' <<<"$status")"
  root="$(jq -r '.root_sha256' <<<"$status")"
  live="$(peer_root_pem "$CELL_NAME" mgmt.poc.internal 2>/dev/null | pem_der_sha256)" || live=""
  [[ -n "$live" && "$root" == "$live" ]] || echo "the host service trusts the management root $root, and the live root is ${live:-unknown}"
  pin="$(k -n mgmt-system get configmap hostsvc-pin -o jsonpath='{.data.hostsvc\.crt}' 2>/dev/null | pem_der_sha256)" || pin=""
  [[ -n "$pin" && "$pin" == "$cert" ]] || echo "ConfigMap mgmt-system/hostsvc-pin holds the certificate ${pin:-none}, and the host service presents $cert"
}

source "$ROOT/components/lib/peer-root.sh"
status=0
drift="$(hostsvc_drift)"
if [[ -n "$drift" ]]; then
  status=1
  if ((check)); then
    while read -r line; do echo "$line. Run: $repair"; done <<<"$drift"
  else
    log "the host service drifted: ${drift//$'\n'/; }"
    "$serve" restart || die "could not restart the host service. Run: mise run hostsvc:serve -- restart"
    status=0
  fi
fi

replicas="$(k -n mgmt-system get statefulset mgmtd -o jsonpath='{.spec.replicas}' 2>/dev/null)" \
  || { echo "StatefulSet mgmtd is absent in management. Run: CELL=management LINK_ONLY=mgmt-api mise run cell:link"; exit 1; }
if [[ "$replicas" != 1 ]]; then
  status=1
  if ((check)); then
    echo "StatefulSet mgmtd has $replicas replicas. Run: $repair"
  else
    log "setting the replicas of mgmtd from $replicas to 1"
    "${HARNESS_REPLICAS:-$ROOT/scripts/harness-replicas.sh}" management mgmt-system statefulset/mgmtd 1 \
      || die "could not set the replicas of mgmtd. Run: scripts/harness-replicas.sh management mgmt-system statefulset/mgmtd 1"
    k -n mgmt-system rollout status statefulset/mgmtd --timeout=300s >/dev/null || die "statefulset/mgmtd did not finish its rollout in 300s"
    status=0
  fi
fi

replicas="$(kubectl --context kind-dev-cp -n envd-system get deployment envd -o jsonpath='{.spec.replicas}' 2>/dev/null)" \
  || { echo "Deployment envd is absent in dev-cp. Run: CELL=dev-cp mise run cell:up"; exit 1; }
if [[ "$replicas" != 1 ]]; then
  status=1
  if ((check)); then
    echo "Deployment envd has $replicas replicas. Run: $repair"
  else
    log "setting the replicas of envd from $replicas to 1"
    "${HARNESS_REPLICAS:-$ROOT/scripts/harness-replicas.sh}" dev-cp envd-system deployment/envd 1 \
      || die "could not set the replicas of envd. Run: scripts/harness-replicas.sh dev-cp envd-system deployment/envd 1"
    kubectl --context kind-dev-cp -n envd-system rollout status deployment/envd --timeout=300s >/dev/null || die "deployment/envd did not finish its rollout in 300s"
    status=0
  fi
fi
exit "$status"
