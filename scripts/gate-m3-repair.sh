#!/usr/bin/env bash
# Remove what a gate:m3 run leaves behind when it stops before its cleanups, for example after Ctrl-C,
# a go test timeout or a closed terminal. The guard test makes a Role and a RoleBinding in argocd, a
# ClusterRole and a ClusterRoleBinding, and a Namespace, each with the label poc.internal/test. The
# script deletes every object with that label in each cell with the Argo CD Agent. It is safe to run
# again.
#
# Usage: gate-m3-repair.sh [--check]
#   --check prints each object that it would delete and exits 1, or exits 0 when it finds none.
# GATE_M3_CELLS names the cells to act on, separated by spaces. The default is every cluster of
# harness/topology.yaml with the component argocd-agent.
export CELL=dev-cell-1
source "$(dirname "$0")/lib.sh"

cells="${GATE_M3_CELLS:-$(yq -r '.clusters[] | select(.components[] == "argocd-agent") | .name' "$ROOT/harness/topology.yaml")}"
check=0
[[ "${1:-}" == "--check" ]] && check=1

# leftovers <cell> prints "<kind> <namespace or -> <name>" for each object with the test label.
leftovers() {
  kubectl --context "kind-$1" get roles,rolebindings,clusterroles,clusterrolebindings,namespaces,serviceaccounts -A -l "$GUARD_TEST_LABEL" -o json \
    | jq -r '.items[] | "\(.kind | ascii_downcase) \(.metadata.namespace // "-") \(.metadata.name)"'
}

status=0
# TestM3KeepaliveBlackhole drops the packets between the relay of dev-cp and the hub with firewall rules on the
# dev-cp node. Each rule carries a comment that starts with gate-m3-blackhole-. The test removes them, and a timer
# in the node removes them too. A run that stopped hard can leave them, and they cut the tunnel of every cell.
# The match is the comment, so it needs no address. When the node does not answer, the script stops with the reason.
if docker inspect dev-cp-control-plane >/dev/null 2>&1; then
  rules="$(blackhole_present dev-cp-control-plane)" || die "the dev-cp node does not answer, so the firewall rules of a gate test cannot be checked. Run: CELL=dev-cp mise run cell:verify"
  while read -r rule; do
    [[ -n "$rule" ]] || continue
    status=1
    if ((check)); then
      echo "dev-cp: the firewall rule '${rule#-D }' drops the mesh tunnels. Run: mise run gate:m3:repair"
      continue
    fi
    log "deleting the firewall rule '${rule#-D }' on the dev-cp node"
    # shellcheck disable=SC2086
    docker exec dev-cp-control-plane iptables $rule || die "could not delete the firewall rule '${rule#-D }' on the dev-cp node"
    status=0
  done <<<"$rules"
fi
for cell in $cells; do
  found="$(leftovers "$cell")" || die "could not list the objects with the label $GUARD_TEST_LABEL in $cell"
  [[ -n "$found" ]] || continue
  status=1
  while read -r kind ns name; do
    if ((check)); then
      echo "$cell: $kind $ns/$name has the label $GUARD_TEST_LABEL. Run: mise run gate:m3:repair"
      continue
    fi
    log "deleting $kind $ns/$name in $cell"
    # A ServiceAccount goes with its Namespace, and a delete of one that is already gone is no error.
    if [[ "$ns" == "-" ]]; then
      kubectl --context "kind-$cell" delete "$kind" "$name" --ignore-not-found --wait=true --timeout=2m || die "could not delete $kind $name in $cell"
    else
      kubectl --context "kind-$cell" -n "$ns" delete "$kind" "$name" --ignore-not-found --wait=true --timeout=2m || die "could not delete $kind $ns/$name in $cell"
    fi
  done <<<"$found"
  if ((!check)); then
    again="$(leftovers "$cell")" || die "could not list the objects with the label $GUARD_TEST_LABEL in $cell"
    [[ -z "$again" ]] || die "$cell still has objects with the label $GUARD_TEST_LABEL: $(tr '\n' ',' <<<"$again")"
    status=0
  fi
done
# TestM3VerifyDetectsPeerRootDrift changes ConfigMap mesh-view-system/mgmt-root in GATE_M3_ROOT_CELL (default
# dev-cell-1) for about 80 seconds. A run that stopped hard leaves it changed, and the next start of the tunnel
# pod then fails to verify the hub. The repair applies the live roots of management again. An empty
# GATE_M3_ROOT_CELL skips this step.
root_cell="${GATE_M3_ROOT_CELL-dev-cell-1}"
if [[ -n "$root_cell" ]]; then
  live="$(kubectl --context kind-management -n spire-system exec spire-server-0 -c spire-server -- \
    /opt/spire/bin/spire-server bundle show -socketPath /run/spire/sockets/api.sock -format pem)" \
    || die "could not read the trust bundle of management, so mgmt-root of $root_cell cannot be checked. Run: CELL=management mise run cell:verify"
  have="$(kubectl --context "kind-$root_cell" -n mesh-view-system get configmap mgmt-root -o jsonpath='{.data.root\.crt}')" \
    || die "could not read ConfigMap mesh-view-system/mgmt-root in $root_cell. Run: CELL=$root_cell mise run cell:verify"
  # The render stores the roots without the final newline, so both sides are compared in that form.
  if [[ "$(printf '%s' "$live")" != "$have" ]]; then
    status=1
    if ((check)); then
      echo "$root_cell: ConfigMap mesh-view-system/mgmt-root holds other roots than management. Run: mise run gate:m3:repair"
    else
      log "applying the live roots of management to mesh-view-system/mgmt-root in $root_cell"
      jq -nc --arg pem "$live" '{apiVersion: "v1", kind: "ConfigMap", metadata: {name: "mgmt-root", namespace: "mesh-view-system"}, data: {"root.crt": $pem}}' \
        | kubectl --context "kind-$root_cell" apply --server-side --force-conflicts -f - >/dev/null || die "could not apply mgmt-root in $root_cell"
      status=0
    fi
  fi
fi
exit "$status"
