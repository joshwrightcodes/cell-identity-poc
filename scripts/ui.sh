#!/usr/bin/env bash
# Serve the Argo CD UI of the cell from this Mac.
source "$(dirname "$0")/lib.sh"

exec argocd admin dashboard --context "kind-$CELL_NAME" --namespace argocd --address 127.0.0.1 --port 8080
