#!/usr/bin/env bash
# Serve Grafana of management on http://127.0.0.1:${OBS_UI_PORT:-3300}. Grafana needs the admin
# password: print it with `mise run obs:password`. kubectl port-forward enters the lgtm pod
# through the kubelet, so the NetworkPolicy, which admits no pod on port 3000, does not block it.
# Stop the forward with Ctrl-C. When the port is busy, the script prints one JSON error line.
source "$(dirname "$0")/lib.sh"

port="${OBS_UI_PORT:-3300}"
[[ "$port" =~ ^[1-9][0-9]{0,4}$ ]] && ((port <= 65535)) || json_fail obs:ui "OBS_UI_PORT '$port' is not a port number"
if lsof -nP -iTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1; then
  json_fail obs:ui "port $port already has a listener, probably an old obs:ui" \
    port="$port" find="lsof -nP -iTCP:$port -sTCP:LISTEN"
fi
log "WARNING: while obs:ui runs, every pod on the VM, rogue included, can reach Grafana through host.docker.internal:$port"
log "serving Grafana on http://127.0.0.1:$port. The user is admin, and the password comes from: mise run obs:password"
kubectl --context "kind-$CELL_NAME" -n observability-system port-forward --address 127.0.0.1 svc/lgtm "$port:3000" \
  || die "the port-forward to lgtm stopped. Check the store: CELL=$CELL_NAME mise run cell:verify"
