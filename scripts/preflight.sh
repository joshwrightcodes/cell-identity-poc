#!/usr/bin/env bash
# Check the tool versions and the Colima profile against harness/versions.env.
source "$(dirname "$0")/lib.sh"

source "$ROOT/harness/versions.env"
failed=0

check() {
  local name="$1" want="$2" got="$3"
  if [[ "$got" == "$want" ]]; then
    log "ok: $name $got"
  else
    printf 'FAIL: %s is %s, expected %s\n' "$name" "${got:-unknown}" "$want" >&2
    failed=1
  fi
}

check colima "$COLIMA_VERSION" "$(colima version | sed -n '1s/^colima version v//p')"
check kind "$KIND_VERSION" "$(kind version | sed -n '1s/^kind v\([0-9.]*\) .*/\1/p')"
check docker-cli "$DOCKER_CLI_VERSION" "$(docker --version | sed -n 's/^Docker version \([0-9.]*\),.*/\1/p')"
check kubectl "$KUBECTL_VERSION" "$(kubectl version --client -o json | jq -r '.clientVersion.gitVersion | ltrimstr("v")')"

profile="$(colima list --profile "$COLIMA_PROFILE" --json 2>/dev/null | jq -r --arg p "$COLIMA_PROFILE" 'select(.name == $p) | .status + " " + .runtime')"
check "colima profile $COLIMA_PROFILE" "Running $COLIMA_RUNTIME" "$profile"

[[ "$failed" == 0 ]] || die "preflight failed"
log "preflight passed"
