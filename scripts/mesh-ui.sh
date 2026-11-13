#!/usr/bin/env bash
# Serve Kiali of management on http://127.0.0.1:20001/kiali. Kiali is anonymous and read-only. kubectl
# port-forward enters the Kiali pod through the kubelet, so the NetworkPolicy, which admits no pod
# on port 20001, does not block it. Stop the forward with Ctrl-C.
source "$(dirname "$0")/lib.sh"

port=20001
if lsof -nP -iTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1; then
  die "port $port already has a listener, probably an old mesh:ui. Find its process with: lsof -nP -iTCP:$port -sTCP:LISTEN"
fi
log "WARNING: while mesh:ui runs, every pod on the VM, rogue included, can read the mesh view through host.docker.internal:$port"
log "serving Kiali on http://127.0.0.1:$port/kiali. The page shows the clusters of the hub after both tunnels are up"
kubectl --context "kind-$CELL_NAME" -n mesh-view-system port-forward --address 127.0.0.1 svc/kiali "$port:20001" \
  || die "the port-forward to Kiali stopped. Check the mesh view: CELL=$CELL_NAME mise run cell:verify"
