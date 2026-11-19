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

# kind_clusters prints the kind clusters, one on each line. A caller searches the printed list and never pipes kind into grep -q:
# grep -q stops at the first match, a later write of kind then ends kind with SIGPIPE, and pipefail reads that as no match. A failed
# call runs again, up to KIND_CLUSTERS_TRIES calls in all (default 3, also for a value that is not a positive number) with a pause
# of KIND_CLUSTERS_PAUSE seconds (default 1). When every call fails, it prints the error of kind on standard error and returns 1, so
# that a caller never reads a failure as no cluster.
kind_clusters() {
  local tries="${KIND_CLUSTERS_TRIES:-3}" i out err errfile
  [[ "$tries" =~ ^[1-9][0-9]*$ ]] || tries=3
  errfile="$(mktemp)" || return 1
  for ((i = 1; ; i++)); do
    if out="$(kind get clusters 2>"$errfile")"; then
      rm -f "$errfile"
      [[ -z "$out" ]] || printf '%s\n' "$out"
      return 0
    fi
    ((i < tries)) || break
    sleep "${KIND_CLUSTERS_PAUSE:-1}"
  done
  err="$(tr '\n' ' ' <"$errfile")"
  rm -f "$errfile"
  echo "error: kind get clusters failed $tries times: ${err:-no error text}" >&2
  return 1
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
  existing="$(kind_clusters)" || { echo "error: kind get clusters failed, so the live cells are unknown" >&2; return 1; }
  for cell in $catalog; do
    grep -qx -- "$cell" <<<"$existing" || continue
    # A cluster that kind lists but docker cannot inspect is an error, never an absent cell: a dropped cell would leave every admit list.
    ip="$(docker inspect -f '{{with index .NetworkSettings.Networks "kind"}}{{.IPAddress}}{{end}}' "$cell-control-plane" 2>&1)" \
      || { echo "error: docker inspect of $cell-control-plane failed, so the live cells are unknown: $ip" >&2; return 1; }
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
  existing="$(kind_clusters)" || { echo "error: kind get clusters failed, so the existing clusters are unknown" >&2; return 1; }
  for name in $(yq -r '.clusters[].name' "$topology"); do
    ! grep -qx -- "$name" <<<"$existing" || printf '%s\n' "$name"
  done
}
