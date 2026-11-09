#!/usr/bin/env bash
# Restore the API server of dev-cell-1 after the M2 key rotation test. The test runs the same steps
# in its cleanup. Run `mise run gate:m2:repair` after a run that ended before its cleanup, for
# example after Ctrl-C, a go test timeout or a closed terminal. The script is safe to run again.
#
# Usage: gate-m2-repair.sh [--check]
#   --check prints each trace of the test and exits 1, or exits 0 when the node is clean.
#
# The repair:
#   1. puts back the manifest that the test saved, or removes the two test flags when no saved
#      manifest exists, and deletes the test key files;
#   2. waits until the API server publishes one key and signs with it;
#   3. checks that kube-controller-manager, which keeps a token for each controller in memory, runs a
#      container that started after the restore, and restarts it when it does not;
#   4. deletes each pod with a projected token from another key, and waits for the workloads.
export CELL=dev-cell-1
source "$(dirname "$0")/lib.sh"

node="$CELL_NAME-control-plane"
wait_seconds=240
on_node() { docker exec "$node" "$@"; }

# api_kids prints the sorted key IDs that the API server publishes.
api_kids() { k get --raw /openid/v1/jwks | jq -r '[.keys[].kid] | sort | join(" ")'; }

# signing_kid requests a short token for celld and prints the key ID of its header. The audience
# m2-kid-probe makes the token useless to any service.
signing_kid() {
  local head
  head="$(k -n cell-identity-system create token celld --duration 10m --audience m2-kid-probe | cut -d. -f1)" || return 1
  b64url_json "$head" | jq -r '.kid // ""'
}

b64url_json() {
  local s="${1//-/+}"
  s="${s//_//}"
  while ((${#s} % 4)); do s+="="; done
  base64 -d <<<"$s" 2>/dev/null
}

if [[ "${1:-}" == "--check" ]]; then
  traces="$(keytest_leftover "$CELL_NAME")" || die "cannot read the node $node"
  kids="$(api_kids 2>/dev/null)" || die "cannot read the JWKS of $CELL_NAME"
  [[ "$kids" == *" "* ]] && traces+=$'\n'"the API server of $CELL_NAME publishes the keys $kids"
  traces="$(sed '/^$/d' <<<"$traces")"
  if [[ -n "$traces" ]]; then
    printf '%s\n' "$traces" >&2
    die "the M2 key rotation test left $CELL_NAME changed. Run: mise run gate:m2:repair"
  fi
  exit 0
fi

restore_time="$(on_node date -u +%s)"
# changed records whether this run found the node edited. A run that finds a clean node and no
# saved manifest repeats only the token scan, because an earlier run completed the other steps.
changed=0
if on_node test -e "$KEYTEST_SAVED"; then
  changed=1
  on_node sh -c "umask 077 && cp '$KEYTEST_SAVED' /root/m2-test.tmp && mv /root/m2-test.tmp '$KEYTEST_MANIFEST'"
  log "restored $KEYTEST_MANIFEST from $KEYTEST_SAVED"
elif on_node grep -q 'm2-test-sa' "$KEYTEST_MANIFEST"; then
  changed=1
  on_node sh -c "umask 077 && sed -e '\\|--service-account-key-file=$KEYTEST_KEY.pub|d' \
    -e 's|--service-account-signing-key-file=$KEYTEST_KEY.key|--service-account-signing-key-file=/etc/kubernetes/pki/sa.key|' \
    '$KEYTEST_MANIFEST' > /root/m2-test.tmp && mv /root/m2-test.tmp '$KEYTEST_MANIFEST'"
  log "removed the test key flags from $KEYTEST_MANIFEST"
fi
on_node rm -f "$KEYTEST_KEY.key" "$KEYTEST_KEY.pub"
on_node grep -q 'm2-test-sa' "$KEYTEST_MANIFEST" && die "$KEYTEST_MANIFEST still names the test key"

end=$((SECONDS + wait_seconds))
kid=""
until kids="$(api_kids 2>/dev/null)" && [[ -n "$kids" && "$kids" != *" "* ]] \
    && signing="$(signing_kid 2>/dev/null)" && [[ "$signing" == "$kids" ]] \
    && [[ "$(k -n kube-system get pod "kube-apiserver-$node" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null)" == True ]]; do
  ((SECONDS < end)) || die "the API server of $CELL_NAME did not return to one key within ${wait_seconds}s (keys '${kids:-none}', signing key '${signing:-none}')"
  sleep 3
done
kid="$kids"
log "the API server of $CELL_NAME publishes and signs with the key $kid"

# kube-controller-manager requests a token for each controller and keeps it in memory. The restart
# of the API server usually ends its container. A container that started before the restore still
# holds tokens from the test key, so the repair stops it. kubelet can delay the new container by its
# restart back-off, up to 5 minutes.
manager="kube-controller-manager-$node"
manager_started() {
  k -n kube-system get pod "$manager" -o json 2>/dev/null \
    | jq -r '.status.containerStatuses[0] | select(.ready) | .state.running.startedAt // empty | fromdateiso8601'
}
if ((changed)); then
  started="$(manager_started)" || started=""
  if [[ -n "$started" ]] && ((started < restore_time)); then
    for id in $(on_node crictl ps --name '^kube-controller-manager$' -q); do
      on_node crictl stop "$id" >/dev/null
    done
    log "stopped the kube-controller-manager container, which started before the restore"
  fi
  end=$((SECONDS + 330))
  until started="$(manager_started)" && [[ -n "$started" ]] && ((started >= restore_time)); do
    ((SECONDS < end)) || die "kube-controller-manager in $CELL_NAME has no ready container that started after the restore"
    sleep 3
  done
  log "kube-controller-manager runs a container that started after the restore"
fi

# Each regular file of a projected volume that holds a token starts with the base64 of '{"'. Only
# the header leaves the node.
stale=()
while read -r path head; do
  [[ -n "$head" ]] || continue
  file_kid="$(b64url_json "$head" | jq -r '.kid // ""' 2>/dev/null)"
  if [[ -n "$file_kid" && "$file_kid" != "$kid" ]]; then
    uid="${path#/var/lib/kubelet/pods/}"
    stale+=("${uid%%/*}")
  fi
done < <(on_node sh -c 'for f in /var/lib/kubelet/pods/*/volumes/kubernetes.io~projected/*/*; do
  [ -f "$f" ] && [ "$(head -c 3 "$f")" = eyJ ] && printf "%s %s\n" "$f" "$(cut -d. -f1 "$f")"; done; true')
if ((${#stale[@]} > 0)); then
  uids="$(printf '%s\n' "${stale[@]}" | jq -Rsc 'split("\n") | map(select(length > 0)) | unique')"
  while read -r ns name; do
    log "deleting pod $ns/$name, which holds a token from another key"
    k -n "$ns" delete pod "$name" --wait=false >/dev/null
  done < <(k get pods -A -o json | jq -r --argjson uids "$uids" '.items[] | select(.metadata.uid as $u | $uids | index($u)) | "\(.metadata.namespace) \(.metadata.name)"')
fi

end=$((SECONDS + 300))
until bad="$(k get deployments,statefulsets,daemonsets -A -o json | jq -r '.items[] | select(
    if .kind == "DaemonSet" then .status.numberReady != .status.desiredNumberScheduled or .status.updatedNumberScheduled != .status.desiredNumberScheduled
    else ((.status.readyReplicas // 0) != (.spec.replicas // 1)) or ((.status.updatedReplicas // 0) != (.spec.replicas // 1)) or ((.status.replicas // 0) != (.spec.replicas // 1)) end)
    | "\(.kind)/\(.metadata.namespace)/\(.metadata.name)"')" && [[ -z "$bad" ]]; do
  ((SECONDS < end)) || die "workloads of $CELL_NAME not ready within 300s: ${bad//$'\n'/, }"
  sleep 5
done
on_node rm -f "$KEYTEST_SAVED"
log "$CELL_NAME is repaired. Run: CELL=$CELL_NAME mise run cell:verify"
