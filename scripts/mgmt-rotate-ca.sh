#!/usr/bin/env bash
# Replace the CA of a SPIRE server that has no upstream authority (management) with a new
# self-signed root. Use it when someone may hold a copy of keys.json, or before SPIRE prepares the
# next root by itself. Other clusters hold copies of the root, so the order keeps the root that
# signs the live SVIDs in every copy at every step:
#   1. Prepare a new X.509 authority and a new JWT authority. Without an upstream authority, SPIRE
#      adds the new root to the bundle when it prepares it (SPIRE v1.15.5
#      pkg/server/ca/manager/manager.go, PrepareX509CA and selfSignX509CA, the appendBundle call).
#   2. Refresh each copy, then wait until each copy holds exactly the roots of the bundle: the old
#      and the new root.
#   3. Activate both new authorities. New SVIDs chain to the new root, which every copy holds.
#   4. Taint both old authorities, so the agents replace the SVIDs that they signed. Wait, then
#      revoke both. SPIRE then removes the old root from the bundle (only a tainted old authority
#      can be revoked: pkg/server/api/localauthority/v1/service.go, RevokeX509Authority).
#   5. Refresh each copy again, and wait until each copy holds only the new root.
# The old key stays in keys.json until SPIRE prepares into its slot again, but no copy trusts its
# root after step 5. No other cluster holds a copy of the JWT keys.
#
# A copy is a ConfigMap in another cluster with the annotation poc.internal/peer-root-sha256 and a
# key root.crt whose certificates are all CAs of SPIRE_TRUST_DOMAIN (components/lib/peer-root.sh).
# By default, a refresh runs cell:up once for each cluster that holds a copy, because the render of
# that cluster reads the live bundle. MGMT_ROTATE_REFRESH names another command, for the tests. The
# script runs it once for each copy, as <command> <cluster> <namespace> <name>.
# MGMT_ROTATE_WAIT bounds each wait for the copies in seconds (default 900). MGMT_ROTATE_TAINT_WAIT
# is the time between taint and revoke in seconds (default 120).
source "$(dirname "$0")/lib.sh"

runs_spire_server=0
for entry in "${COMPONENTS[@]}"; do
  [[ "${entry%%:*}" == spire-server ]] && runs_spire_server=1
done
((runs_spire_server)) || die "cluster $CELL_NAME runs no SPIRE server in harness/topology.yaml. Run: CELL=management mise run mgmt:rotate-ca"
[[ -z "${SPIRE_UPSTREAM:-}" ]] || die "the SPIRE server of $CELL_NAME has an upstream authority, which signs each new CA. Run: CELL=$CELL_NAME mise run pki:rotate-intermediate"
: "${SPIRE_TRUST_DOMAIN:?}"
wait_seconds="${MGMT_ROTATE_WAIT:-900}"
taint_wait="${MGMT_ROTATE_TAINT_WAIT:-120}"
[[ "$wait_seconds" =~ ^[0-9]+$ && "$taint_wait" =~ ^[0-9]+$ ]] || die "MGMT_ROTATE_WAIT and MGMT_ROTATE_TAINT_WAIT take a number of seconds"

# server <arguments> runs spire-server in the server pod with JSON output.
server() {
  k -n spire-system exec spire-server-0 -c spire-server -- /opt/spire/bin/spire-server "$@" \
    -socketPath /run/spire/sockets/api.sock -output json
}

# pem_blocks prints each PEM certificate on standard input as one line, sorted.
pem_blocks() {
  awk '/-----BEGIN CERTIFICATE-----/ { b = "" } { b = b $0 } /-----END CERTIFICATE-----/ { print b }' | sort
}

bundle_blocks() {
  k -n spire-system exec spire-server-0 -c spire-server -- /opt/spire/bin/spire-server bundle show \
    -socketPath /run/spire/sockets/api.sock -format pem | pem_blocks
}

# copies prints "<cluster> <namespace> <name>" for each copy of the root in another cluster.
copies() {
  local cluster list ns name
  for cluster in $(yq -r '.clusters[] | select(.components | length > 0) | .name' "$ROOT/harness/topology.yaml"); do
    [[ "$cluster" != "$CELL_NAME" ]] || continue
    list="$(kubectl --context "kind-$cluster" get configmaps -A -o json)" || die "could not list the ConfigMaps of $cluster"
    while read -r ns name; do
      [[ -n "$ns" ]] || continue
      # pkigen fails unless every certificate is a CA of the trust domain.
      if jq -r --arg ns "$ns" --arg name "$name" '.items[] | select(.metadata.namespace == $ns and .metadata.name == $name) | .data["root.crt"]' <<<"$list" \
        | (cd "$ROOT" && mise run pki -- trust-bundle --trust-domain "$SPIRE_TRUST_DOMAIN") >/dev/null 2>&1; then
        echo "$cluster $ns $name"
      fi
    done < <(jq -r '.items[] | select(.metadata.annotations["poc.internal/peer-root-sha256"] != null and .data["root.crt"] != null)
      | "\(.metadata.namespace) \(.metadata.name)"' <<<"$list")
  done
}

# refresh <copies> renders each copy again from the live bundle.
refresh() {
  local cluster ns name done_clusters=" "
  while read -r cluster ns name; do
    [[ -n "$cluster" ]] || continue
    if [[ -n "${MGMT_ROTATE_REFRESH:-}" ]]; then
      "$MGMT_ROTATE_REFRESH" "$cluster" "$ns" "$name" || die "the refresh of $cluster $ns/$name failed"
    elif [[ "$done_clusters" != *" $cluster "* ]]; then
      log "running cell:up in $cluster, which holds the copy $ns/$name"
      CELL="$cluster" "$ROOT/scripts/up.sh" || die "cell:up of $cluster failed. Fix the cause, then run: CELL=$cluster mise run cell:up, and CELL=$CELL_NAME mise run mgmt:rotate-ca again"
      done_clusters+="$cluster "
    fi
  done <<<"$1"
}

# wait_for_copies <copies> waits until each copy holds exactly the roots of the live bundle.
wait_for_copies() {
  local want cluster ns name got end=$((SECONDS + wait_seconds)) stale
  want="$(bundle_blocks)" || die "could not read the bundle of $CELL_NAME"
  while :; do
    stale=()
    while read -r cluster ns name; do
      [[ -n "$cluster" ]] || continue
      got="$(kubectl --context "kind-$cluster" -n "$ns" get configmap "$name" -o jsonpath='{.data.root\.crt}' | pem_blocks)"
      [[ "$got" == "$want" ]] || stale+=("$cluster $ns/$name")
    done <<<"$1"
    ((${#stale[@]} == 0)) && return 0
    ((SECONDS < end)) || die "after ${wait_seconds}s these copies still differ from the bundle of $CELL_NAME: ${stale[*]}"
    sleep 5
  done
}

old_x509="$(server localauthority x509 show | jq -r '.active.authority_id // ""')"
old_jwt="$(server localauthority jwt show | jq -r '.active.authority_id // ""')"
[[ -n "$old_x509" && -n "$old_jwt" ]] || die "could not read the active authorities of the SPIRE server in $CELL_NAME"
holders="$(copies)"
log "other clusters hold $(grep -c . <<<"$holders" || true) copies of the root of $SPIRE_TRUST_DOMAIN"
before="$(bundle_blocks)" || die "could not read the bundle of $CELL_NAME"

new_x509="$(server localauthority x509 prepare | jq -r '.prepared_authority.authority_id // ""')"
new_jwt="$(server localauthority jwt prepare | jq -r '.prepared_authority.authority_id // ""')"
[[ -n "$new_x509" && -n "$new_jwt" ]] || die "SPIRE prepared no new authority. Run: CELL=$CELL_NAME mise run mgmt:rotate-ca again"
added="$(comm -13 <(printf '%s\n' "$before") <(bundle_blocks))"
[[ -n "$added" && "$(wc -l <<<"$added")" -eq 1 ]] || die "the bundle of $CELL_NAME did not gain exactly one root when SPIRE prepared $new_x509"
log "prepared the X.509 authority $new_x509 and the JWT authority $new_jwt. The bundle holds the new root"

refresh "$holders"
wait_for_copies "$holders"
log "each copy holds the new root"

server localauthority x509 activate -authorityID "$new_x509" >/dev/null || die "could not activate $new_x509. Each copy holds it. Run: mise x -- kubectl --context kind-$CELL_NAME -n spire-system exec spire-server-0 -c spire-server -- /opt/spire/bin/spire-server localauthority x509 activate -socketPath /run/spire/sockets/api.sock -authorityID $new_x509"
server localauthority jwt activate -authorityID "$new_jwt" >/dev/null || die "could not activate the JWT authority $new_jwt"
log "activated $new_x509 and the JWT authority $new_jwt"

server localauthority x509 taint -authorityID "$old_x509" >/dev/null || die "could not taint the old authority $old_x509"
server localauthority jwt taint -authorityID "$old_jwt" >/dev/null || die "could not taint the old JWT authority $old_jwt"
log "tainted the old authorities. The agents replace the SVIDs that they signed. Waiting ${taint_wait}s"
sleep "$taint_wait"
server localauthority x509 revoke -authorityID "$old_x509" >/dev/null || die "could not revoke the old authority $old_x509"
server localauthority jwt revoke -authorityID "$old_jwt" >/dev/null || die "could not revoke the old JWT authority $old_jwt"
left="$(comm -12 <(printf '%s\n' "$before") <(bundle_blocks) | grep -c . || true)"
((left == 0)) || log "the bundle still holds $left root(s) from before the rotation, which SPIRE prepared earlier and never activated"
log "revoked the old authorities. The bundle holds $(bundle_blocks | wc -l | tr -d ' ') root(s)"

refresh "$holders"
wait_for_copies "$holders"
log "the CA of $CELL_NAME is $new_x509, and each copy holds only the roots of the bundle"
