#!/usr/bin/env bash
# Serve the Argo CD UI of the cell from this Mac. The local server of argocd admin dashboard
# does not read application.namespaces and has no flag for it, so the UI shows only the root
# Application in argocd. This script first prints the Applications of both namespaces.
# The server also writes server.secretkey into argocd-secret, and an admin password when
# admin.enabled is not false. The script removes those keys when the server stops.
# Usage: ui.sh [--clean]   --clean only removes what an earlier run left behind.
source "$(dirname "$0")/lib.sh"

if [[ "${1:-}" == --clean ]]; then
  clean_dashboard_leftovers || die "could not clean argocd-secret of $CELL_NAME"
  log "argocd of $CELL_NAME holds no dashboard leftovers"
  exit 0
fi

k get applications -A || die "cannot read the Applications of $CELL_NAME. Run: CELL=$CELL_NAME mise run cell:verify"
log "the UI lists only the root Application. The table above lists the child Applications"
trap 'clean_dashboard_leftovers || log "could not clean argocd-secret. Run: CELL=$CELL_NAME mise run cell:ui:clean"' EXIT
argocd admin dashboard --context "kind-$CELL_NAME" --namespace argocd --address 127.0.0.1 --port 8080
