#!/usr/bin/env bash
# Serve the Argo CD UI of the cell from this Mac. The UI lists every Application, because all of
# them live in argocd.
# The server also writes server.secretkey into argocd-secret, and an admin password when
# admin.enabled is not false. The script removes those keys when the server stops.
# Usage: ui.sh [--clean]   --clean only removes what an earlier run left behind.
source "$(dirname "$0")/lib.sh"

if [[ "${1:-}" == --clean ]]; then
  clean_dashboard_leftovers || die "could not clean argocd-secret of $CELL_NAME"
  log "argocd of $CELL_NAME holds no dashboard leftovers"
  exit 0
fi

k -n argocd get applications || die "cannot read the Applications of $CELL_NAME. Run: CELL=$CELL_NAME mise run cell:verify"
trap 'clean_dashboard_leftovers || log "could not clean argocd-secret. Run: CELL=$CELL_NAME mise run cell:ui:clean"' EXIT
argocd admin dashboard --context "kind-$CELL_NAME" --namespace argocd --address 127.0.0.1 --port 8080
