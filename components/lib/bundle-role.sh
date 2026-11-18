# The bundle role of a cluster. Source this file from a render script or from scripts/lib.sh. It needs only yq.
#
# The role decides which signed bundle sets the cluster accepts (internal/bundle/allow.json): cell for a
# cluster with the cell-identity set, cp for one with the envd set, and open for every other cluster.
# A cluster with role open keeps the harness publish and the project cell of M7.

BUNDLE_ROLE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

# bundle_role_of <cluster> prints cell, cp or open. BUNDLE_ROLE_TOPOLOGY names another topology file, for the tests.
bundle_role_of() {
  local topology="${BUNDLE_ROLE_TOPOLOGY:-$BUNDLE_ROLE_ROOT/harness/topology.yaml}" sets
  sets="$(NAME="$1" yq -r '.clusters[] | select(.name == strenv(NAME)) | .components[]' "$topology")" \
    || { echo "error: could not read the component sets of $1 from $topology" >&2; return 1; }
  [[ -n "$sets" ]] || { echo "error: no cluster $1 with components in $topology" >&2; return 1; }
  if grep -qx cell-identity <<<"$sets"; then echo cell
  elif grep -qx envd <<<"$sets"; then echo cp
  else echo open; fi
}

# bundle_store_writer_of <role> prints the user name of the one account that may write to the bundle store of
# a cluster with that role, or nothing for role open.
bundle_store_writer_of() {
  case "$1" in
    cell) echo system:serviceaccount:cell-identity-system:celld ;;
    cp) echo system:serviceaccount:envd-system:envd ;;
    open) ;;
    *) echo "error: unknown bundle role '$1'" >&2; return 1 ;;
  esac
}
