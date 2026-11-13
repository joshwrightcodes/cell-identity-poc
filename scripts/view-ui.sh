#!/usr/bin/env bash
# Serve the central Argo CD UI of management on http://127.0.0.1:8090. The UI is anonymous and
# read-only. kubectl port-forward enters the argocd-server pod through the kubelet, so the
# NetworkPolicy, which admits only the kubelet probes on port 8080, does not block it. Stop the
# forward with Ctrl-C.
source "$(dirname "$0")/lib.sh"

port=8090
if lsof -nP -iTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1; then
  die "port $port already has a listener, probably an old view:ui. Find its process with: lsof -nP -iTCP:$port -sTCP:LISTEN"
fi
log "WARNING: while view:ui runs, every pod on the VM, rogue included, can read this view through host.docker.internal:$port"
log "serving the central view on http://127.0.0.1:$port. Before the cell agents connect, the list of Applications is empty"
kubectl --context "kind-$CELL_NAME" -n central-view-system port-forward --address 127.0.0.1 svc/argocd-server "$port:80" \
  || die "the port-forward to argocd-server stopped. Check the view: CELL=$CELL_NAME mise run cell:verify"
