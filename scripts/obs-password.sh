#!/usr/bin/env bash
# Print the Grafana admin password of management on standard output, and nothing else, so that a
# pipe can copy it, for example: mise run obs:password | pbcopy. The script writes no file. On a
# failure it prints one JSON error line and nothing else.
source "$(dirname "$0")/lib.sh"

encoded="$(k -n observability-system get secret grafana-admin -o jsonpath='{.data.password}' 2>/dev/null)" \
  || json_fail obs:password "could not read Secret grafana-admin in observability-system of $CELL_NAME" \
    fix="CELL=$CELL_NAME mise run cell:up"
[[ -n "$encoded" ]] || json_fail obs:password "Secret grafana-admin has no key password" fix="CELL=$CELL_NAME mise run cell:up"
password="$(base64 -d <<<"$encoded")" || json_fail obs:password "Secret grafana-admin does not hold valid base64"
printf '%s\n' "$password"
