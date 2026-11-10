#!/usr/bin/env bash
# Serve the central Argo CD UI of management on http://127.0.0.1:8090. The UI is anonymous and
# read-only. kubectl port-forward enters the argocd-server pod through the kubelet, so the
# NetworkPolicy, which admits only the kubelet probes on port 8080, does not block it. Stop the
# forward with Ctrl-C.
source "$(dirname "$0")/lib.sh"

port=8090
if curl -fsS -o /dev/null "http://127.0.0.1:$port/" 2>/dev/null; then
  die "port $port already serves a page, probably from an old view:ui. Find its process with: lsof -nP -iTCP:$port -sTCP:LISTEN"
fi
log "serving the central view on http://127.0.0.1:$port"
exec kubectl --context "kind-$CELL_NAME" -n central-view-system port-forward --address 127.0.0.1 svc/argocd-server "$port:80"
