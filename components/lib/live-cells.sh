# The cells that exist now. Source this file from a render script or from scripts/lib.sh.
#
# lib.sh drops every variable that a cell env file defines, so a render cannot source lib.sh. This
# file needs only kind, docker and yq.

LIVE_CELLS_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

# catalog_cells prints the clusters of harness/topology.yaml with the cell-identity set, one on each line, in topology order.
# These are the cells that a portal request may name. LIVE_CELLS_TOPOLOGY names another topology file, for the tests.
catalog_cells() {
  yq -r '.clusters[] | select(.components[] == "cell-identity") | .name' "${LIVE_CELLS_TOPOLOGY:-$LIVE_CELLS_ROOT/harness/topology.yaml}"
}

# live_cells prints the live cells, one on each line, in topology order. A live cell is a cluster of
# harness/topology.yaml with the cell-identity set, whose kind cluster exists and whose node container has
# an IPv4 address on the network kind. A cluster with no node address is not live. When kind does not
# answer, it prints the reason on standard error and returns 1, so that a read error never drops a cell.
# LIVE_CELLS_TOPOLOGY names another topology file, for the tests.
live_cells() {
  local topology="${LIVE_CELLS_TOPOLOGY:-$LIVE_CELLS_ROOT/harness/topology.yaml}" catalog cell existing ip
  catalog="$(catalog_cells)" || { echo "error: could not read the cells of $topology" >&2; return 1; }
  [[ -n "$catalog" ]] || return 0
  existing="$(kind get clusters 2>/dev/null)" || { echo "error: kind get clusters failed, so the live cells are unknown" >&2; return 1; }
  for cell in $catalog; do
    grep -qx -- "$cell" <<<"$existing" || continue
    ip="$(docker inspect -f '{{with index .NetworkSettings.Networks "kind"}}{{.IPAddress}}{{end}}' "$cell-control-plane" 2>/dev/null)" || continue
    ip="${ip//[[:space:]]/}"
    [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || continue
    printf '%s\n' "$cell"
  done
}

# is_live_cell <cell> succeeds when the cell is live. It fails with the reason of live_cells when kind does not answer.
is_live_cell() {
  local live
  live="$(live_cells)" || return 2
  grep -qx -- "$1" <<<"$live"
}

# existing_clusters prints the clusters of harness/topology.yaml whose kind cluster exists, one on each line, in topology
# order. A repair or a gate that walks every cluster uses it, so an absent cell is skipped and not an error. When kind does not
# answer, it prints the reason on standard error and returns 1.
existing_clusters() {
  local topology="${LIVE_CELLS_TOPOLOGY:-$LIVE_CELLS_ROOT/harness/topology.yaml}" existing name
  existing="$(kind get clusters 2>/dev/null)" || { echo "error: kind get clusters failed, so the existing clusters are unknown" >&2; return 1; }
  for name in $(yq -r '.clusters[].name' "$topology"); do
    ! grep -qx -- "$name" <<<"$existing" || printf '%s\n' "$name"
  done
}
