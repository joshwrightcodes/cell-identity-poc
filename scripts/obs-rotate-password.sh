#!/usr/bin/env bash
# Rotate the Grafana admin password of management without a file on disk:
#   1. Read the current password from Secret grafana-admin into memory.
#   2. Make 32 random alphanumeric characters in memory.
#   3. Send PUT /api/user/password to Grafana from inside the lgtm pod. The pod has no route out
#      and Grafana listens on 127.0.0.1 there too. The Basic credentials and the JSON body travel
#      on the standard input of curl, so no password reaches an argument list.
#   4. Replace Secret grafana-admin through `kubectl apply -f -`.
#   5. Check that the new password gets 200 and the old one gets 401.
# Standard output carries one JSON line on success, with no password in it. After a failure that
# follows the API call, the script prints one JSON error line with the command that makes Grafana
# use the password of the Secret again. The new password lives in memory only, so no output holds it.
source "$(dirname "$0")/lib.sh"

ns=observability-system

# api <user:password> <method> <path> [json body] prints the HTTP status code of lgtm_curl.
api() { lgtm_curl "$@" | tail -n 1; }

restore_command() {
  printf "mise run obs:password | mise x -- kubectl --context kind-%s -n %s exec -i lgtm-0 -c lgtm -- /otel-lgtm/grafana/bin/grafana cli --homepath /otel-lgtm/grafana --config /otel-lgtm/grafana/conf/defaults.ini admin reset-admin-password --password-from-stdin" "$CELL_NAME" "$ns"
}

old="$(CELL="$CELL_NAME" "$ROOT/scripts/obs-password.sh")" || json_fail obs:rotate-password "could not read the current password: $old"
[[ -n "$old" ]] || json_fail obs:rotate-password "the current password is empty"
code="$(api "admin:$old" GET /api/user)" || json_fail obs:rotate-password "could not reach Grafana in the lgtm pod"
[[ "$code" == 200 ]] || json_fail obs:rotate-password "Grafana answers $code for the password in Secret grafana-admin, so the Secret and Grafana already differ" \
  restore="$(restore_command)"

# Thirty-two characters from the 62 letters and digits. head closes the pipe after 32, so tr ends
# with SIGPIPE, which the pipe status check below ignores.
new="$(LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c 32 || true)"
[[ "$new" =~ ^[A-Za-z0-9]{32}$ ]] || json_fail obs:rotate-password "could not make a random password"

body="$(jq -nc --arg old "$old" --arg new "$new" '{oldPassword: $old, newPassword: $new, confirmNew: $new}')"
code="$(api "admin:$old" PUT /api/user/password "$body")" || json_fail obs:rotate-password "the password request did not finish, and Grafana may hold the new password" restore="$(restore_command)"
[[ "$code" == 200 ]] || json_fail obs:rotate-password "Grafana answers $code to PUT /api/user/password, and the Secret is unchanged"

# From here on Grafana holds the new password. Every failure names the command that repairs it.
fail_after() { json_fail obs:rotate-password "$1" restore="$(restore_command)"; }
jq -n --arg p "$new" '{apiVersion: "v1", kind: "Secret", metadata: {name: "grafana-admin", namespace: "observability-system",
    labels: {"app.kubernetes.io/name": "lgtm"}}, type: "Opaque", stringData: {password: $p}}' \
  | k apply -f - >/dev/null 2>&1 || fail_after "could not replace Secret grafana-admin, and Grafana holds a password that the Secret does not"
code="$(api "admin:$new" GET /api/user)" || fail_after "could not check the new password"
[[ "$code" == 200 ]] || fail_after "Grafana answers $code for the new password"
code="$(api "admin:$old" GET /api/user)" || fail_after "could not check the old password"
[[ "$code" == 401 ]] || fail_after "Grafana answers $code for the old password, want 401"
log "rotated the Grafana admin password in $CELL_NAME"
jq -nc '{rotated: true, secret: "observability-system/grafana-admin", user: "admin"}'
