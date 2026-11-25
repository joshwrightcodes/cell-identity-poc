#!/usr/bin/env bash
# Repair what a gate:m15 run can leave behind. The M15 tests rotate the API server key, cut links, revoke cells and write synthetic series, and
# they run probe objects in namespaces m15-<name>. The script
#   1. runs scripts/gate-m9-repair.sh, which heals the gate-m9-cut- rules, un-revokes the cells of build/gate/m9-revoked and repairs the test
#      key of the API server. gate-m9-repair.sh also deletes the m9- namespaces and runs svid-ttl.sh restore, which restarts dev-cp and each
#      live cell. Then it waits for harness:status;
#   2. deletes each namespace m15-<name> with the label cell.poc.internal/e2e=true in every existing cluster, and waits until none is left.
# A synthetic series needs no repair. Its own step deletes only namespaces m15-<name> with the label. Each run repeats the restart of the
# clusters, so a run takes several minutes. It is safe to run again.
#
# Usage: gate-m15-repair.sh [--check]
#   --check runs gate-m9-repair.sh --check, lists the m15- namespaces, and exits 1 with the repair command when either finds a trace. It
#   changes nothing. It exits 0 when it finds none.
# GATE_M15_WAIT bounds the wait for the deletions in seconds (default 180), and GATE_M15_POLL sets the seconds between two reads (default 5).
export CELL=management
source "$(dirname "$0")/lib.sh"

check=0
case "${1:-}" in
  "") ;;
  --check) check=1 ;;
  *) die "usage: gate-m15-repair.sh [--check]" ;;
esac
((${#} <= 1)) || die "usage: gate-m15-repair.sh [--check]"
repair="mise run gate:m15:repair"
test_label="cell.poc.internal/e2e"
wait_seconds="${GATE_M15_WAIT:-180}"
poll="${GATE_M15_POLL:-5}"

existing="$(existing_clusters)" || die "could not list the clusters. Run: mise run harness:status"

# m15_namespaces <cluster> prints the namespaces m15-<name> with the test label in the cluster.
m15_namespaces() {
  local out
  out="$(kubectl --context "kind-$1" get namespaces -l "$test_label=true" -o name)" || return 1
  grep '^namespace/m15-' <<<"$out" | sed 's|^namespace/||' || true
}

if ((check)); then
  found=0
  "$ROOT/scripts/gate-m9-repair.sh" --check || found=1
  for c in $existing; do
    out="$(m15_namespaces "$c")" || die "could not list the namespaces of $c"
    for ns in $out; do
      echo "$c holds the test namespace $ns" >&2
      found=1
    done
  done
  ((found == 0)) || die "a run of gate:m15 left traces. Run: $repair"
  exit 0
fi

# Every failure from here on leaves the repair unfinished, and a new run continues it.
die() { printf 'error: %s. Run: %s again\n' "$*" "$repair" >&2; exit 1; }

"$ROOT/scripts/gate-m9-repair.sh" || die "scripts/gate-m9-repair.sh failed"

for c in $existing; do
  namespaces="$(m15_namespaces "$c")" || die "could not list the namespaces of $c"
  for ns in $namespaces; do
    kubectl --context "kind-$c" delete namespace "$ns" --wait=false >/dev/null || die "could not delete the namespace $ns of $c"
  done
done
no_namespaces() {
  local c out
  for c in $existing; do
    out="$(m15_namespaces "$c" 2>/dev/null)" || return 1
    [[ -z "$out" ]] || return 1
  done
}
waited=0
log "waiting up to ${wait_seconds}s until no test namespace m15-* is left"
until no_namespaces; do
  ((waited < wait_seconds)) || die "a test namespace m15-* is still there after ${wait_seconds}s"
  sleep "$poll"
  waited=$((waited + poll))
done
log "every trace of a run of gate:m15 is repaired"
