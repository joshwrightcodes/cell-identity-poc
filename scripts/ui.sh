#!/usr/bin/env bash
# Serve the Argo CD UI of the cell from this Mac. The local server of argocd admin dashboard
# does not read application.namespaces and has no flag for it, so the UI shows only the root
# Application in argocd. This script first prints the child Applications of argocd-apps.
source "$(dirname "$0")/lib.sh"

k -n "$APPS_NAMESPACE" get applications
exec argocd admin dashboard --context "kind-$CELL_NAME" --namespace argocd --address 127.0.0.1 --port 8080
