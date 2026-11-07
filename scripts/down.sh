#!/usr/bin/env bash
# Delete the cell cluster and its kubeconfig context.
source "$(dirname "$0")/lib.sh"

container cluster delete --name "$CELL_NAME"
rm -rf "$BUILD"
