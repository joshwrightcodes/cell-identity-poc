#!/usr/bin/env bash
# Rotate the Grafana admin password of management without a file on disk:
#   1. Read the current password from Secret grafana-admin into memory.
#   2. Make 32 random alphanumeric characters in memory.
#   3. Send PUT /api/user/password to Grafana from inside the lgtm pod. The pod has no route out
#      and Grafana listens on 127.0.0.1 there too. The Basic credentials and the JSON body travel
#      on the standard input of curl, so no password reaches an argument list.
#   4. Replace the password in Secret grafana-admin with a JSON merge patch on the standard input of
#      `kubectl patch`. The same patch removes the annotation last-applied-configuration, which a
#      client-side `kubectl apply` would fill with the password. The script never uses apply.
#   5. Check that the new password gets 200 and the old one gets 401.
# Standard output carries one JSON line on success, with no password in it. After a failure that
# follows the API call, the script prints one JSON error line with the command that makes Grafana
# use the password of the Secret again. The new password lives in memory only, so no output holds it.
# `obs-rotate-password.sh --restore-command` prints that command and does nothing else.
# Neither password reaches an argument list, on this Mac or in the pod: jq reads them from standard input.
source "$(dirname "$0")/lib.sh"

ns=observability-system

# api <user:password> <method> <path> [json body] prints the HTTP status code of lgtm_curl.
api() { lgtm_curl "$@" | tail -n 1; }

# The restore command sets the password of Grafana to the one in the Secret. run-grafana.sh exports the
# data paths only for the Grafana process, so a kubectl exec needs them: without GF_PATHS_DATA the CLI
# opens an empty database on the read-only root file system, not /data/grafana/data/grafana.db.
restore_command() {
  printf "mise run obs:password | mise x -- kubectl --context kind-%s -n %s exec -i lgtm-0 -c lgtm -- env GF_PATHS_DATA=/data/grafana/data GF_PATHS_HOME=/data/grafana /otel-lgtm/grafana/bin/grafana cli --homepath /otel-lgtm/grafana --config /otel-lgtm/grafana/conf/defaults.ini admin reset-admin-password --password-from-stdin" "$CELL_NAME" "$ns"
}
if [[ "${1:-}" == --restore-command ]]; then
  restore_command
  echo
  exit 0
fi

old="$(CELL="$CELL_NAME" "$ROOT/scripts/obs-password.sh")" || json_fail obs:rotate-password "could not read the current password: $old"
[[ -n "$old" ]] || json_fail obs:rotate-password "the current password is empty"
code="$(api "admin:$old" GET /api/user)" || json_fail obs:rotate-password "could not reach Grafana in the lgtm pod"
[[ "$code" == 200 ]] || json_fail obs:rotate-password "Grafana answers $code for the password in Secret grafana-admin, so the Secret and Grafana already differ" \
  restore="$(restore_command)"

# Thirty-two characters from the 62 letters and digits. head closes the pipe after 32, so tr ends
# with SIGPIPE, which the pipe status check below ignores.
new="$(LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c 32 || true)"
[[ "$new" =~ ^[A-Za-z0-9]{32}$ ]] || json_fail obs:rotate-password "could not make a random password"

body="$(printf '%s\n%s\n' "$old" "$new" | jq -Rnc '[inputs] | {oldPassword: .[0], newPassword: .[1], confirmNew: .[1]}')"
code="$(api "admin:$old" PUT /api/user/password "$body")" || json_fail obs:rotate-password "the password request did not finish, and Grafana may hold the new password" restore="$(restore_command)"
[[ "$code" == 200 ]] || json_fail obs:rotate-password "Grafana answers $code to PUT /api/user/password, and the Secret is unchanged"

# From here on Grafana holds the new password. Every failure names the command that repairs it.
fail_after() { json_fail obs:rotate-password "$1" restore="$(restore_command)"; }
printf '%s' "$new" | jq -Rnc '{data: {password: (input | @base64)}, metadata: {annotations: {"kubectl.kubernetes.io/last-applied-configuration": null}}}' \
  | k -n "$ns" patch secret grafana-admin --type merge --patch-file /dev/stdin >/dev/null 2>&1 \
  || fail_after "could not replace the password in Secret grafana-admin, and Grafana holds a password that the Secret does not"
code="$(api "admin:$new" GET /api/user)" || fail_after "could not check the new password"
[[ "$code" == 200 ]] || fail_after "Grafana answers $code for the new password"
code="$(api "admin:$old" GET /api/user)" || fail_after "could not check the old password"
[[ "$code" == 401 ]] || fail_after "Grafana answers $code for the old password, want 401"
log "rotated the Grafana admin password in $CELL_NAME"
jq -nc '{rotated: true, secret: "observability-system/grafana-admin", user: "admin"}'
