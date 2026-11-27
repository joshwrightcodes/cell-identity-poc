#!/usr/bin/env bash
# Rotate the intermediate CA of dev-cp before the M15 tests when it has under 7 days left, so that the alert rule A3 reads no real alert.
# gate.sh m15 runs this script before it starts the clock of the budget, so a rotation never counts against the budget.
# The script reads the time left from Prometheus in lgtm-0. When under GATE_M15_ROTATE_DAYS days (default 7) are left, it
#   1. writes build/gate/m15-intermediate-rotated, so that gate-m15-repair.sh finishes a rotation that stops half way;
#   2. runs CELL=dev-cp mise run pki:rotate-intermediate, which writes the new key and certificate through POC_SECRET_WRITE_CMD;
#   3. removes the marker and prints the time that the rotation took.
# A failed rotation keeps the marker. It changes nothing when enough time is left.
export CELL=management
source "$(dirname "$0")/lib.sh"

rotated="$BUILD_ROOT/gate/m15-intermediate-rotated"
days="${GATE_M15_ROTATE_DAYS:-7}"
query='min(last_over_time(trust_ca_not_after_seconds{ca="intermediate", service_name!="m15-synthetic"}[2m])) - time()'

answer="$(kubectl --context kind-management -n observability-system exec lgtm-0 -c lgtm -- \
  curl -sG --max-time 20 http://127.0.0.1:9090/api/v1/query --data-urlencode "query=$query")" \
  || die "could not read the intermediate CA from Prometheus in lgtm-0. Run: mise run harness:status"
left="$(jq -r '.data.result[0].value[1] // empty' <<<"$answer")" || die "Prometheus gave no readable answer: $answer"
if [[ -z "$left" ]]; then
  log "Prometheus holds no intermediate CA series, so the rotation check is skipped"
  exit 0
fi
if jq -en --arg left "$left" --argjson days "$days" '($left | tonumber) >= $days * 86400' >/dev/null; then
  log "the intermediate CA has $(jq -rn --arg left "$left" '($left | tonumber) / 86400 | floor') days left, so it needs no rotation"
  exit 0
fi

log "the intermediate CA has under $days days left, so the gate rotates it before the tests"
mkdir -p "$(dirname "$rotated")"
date -u '+%Y-%m-%dT%H:%M:%SZ' >"$rotated"
began=$SECONDS
(cd "$ROOT" && CELL=dev-cp mise run pki:rotate-intermediate) \
  || die "CELL=dev-cp mise run pki:rotate-intermediate failed, and the marker $rotated stays. Run: mise run gate:m15:repair"
rm -f "$rotated"
log "the rotation of the intermediate CA took $((SECONDS - began))s, which the budget of the gate does not count"
