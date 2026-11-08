#!/usr/bin/env bash
# Delete the cell cluster and its kubeconfig context.
source "$(dirname "$0")/lib.sh"

(cd "$ROOT" && mise run hostsvc -- down --only "$CELL_NAME")
rm -rf "$BUILD"
