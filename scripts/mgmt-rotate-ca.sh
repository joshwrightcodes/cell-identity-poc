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
# A run that stops goes on from the step that failed when it runs again. Before a prepare, the
# script reads the authority slots and the bundle. A prepared authority is activated, not prepared
# again. An old authority that is not revoked yet is tainted or revoked first, and nothing is
# prepared, because SPIRE prepares into the slot of the old authority.
#
# The host service on this Mac (scripts/hostsvc-serve.sh) holds a copy of the root too, in
# build/hostsvc/mgmt-root.crt. Both refresh steps restart it, and wait until that file holds the roots
# of the bundle.
#
# A copy is a ConfigMap in another cluster with the annotation poc.internal/peer-root-sha256 and a
# key root.crt whose certificates are all CAs of SPIRE_TRUST_DOMAIN (components/lib/peer-root.sh).
# The trust bundle of each SPIRE agent sidecar of a link component in this cluster is a copy too:
# ConfigMap spire-trust-bundle-<workload> with the harness label and the key bundle.crt. A new pod
# of that workload attests with it, so it must hold the active root.
# By default, a refresh runs cell:up once for each other cluster that holds a copy, and the link
# phase (cell:link) of this cluster for its own copies, because each render reads the live bundle. MGMT_ROTATE_REFRESH names another command, for the tests. The
# script runs it once for each copy, as <command> <cluster> <namespace> <name>.
# Exit status: 0 after a rotation, 1 after a failure, and 3 after a run that only finished step 5 of an earlier rotation. Status 3
# means that no new CA exists. Run the task again to rotate.
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

# copies prints "<cluster> <namespace> <name> <key>" for each copy of the root.
copies() {
  local cluster list ns name key links existing
  # Only cell:link renders the copies of this cluster, so only link components count.
  links="$(printf '%s\n' ${LINK_COMPONENTS[@]+"${LINK_COMPONENTS[@]%%:*}"} | jq -Rn '[inputs | select(length > 0)]')"
  # A cell with no cluster holds no copy, so only the clusters that exist are read.
  existing="$(existing_clusters)" || die "could not list the clusters"
  for cluster in $(yq -r '.clusters[] | select(.components | length > 0) | .name' "$ROOT/harness/topology.yaml"); do
    grep -qx -- "$cluster" <<<"$existing" || continue
    list="$(kubectl --context "kind-$cluster" get configmaps -A -o json)" || die "could not list the ConfigMaps of $cluster"
    while read -r ns name key; do
      [[ -n "$ns" ]] || continue
      # pkigen fails unless every certificate is a CA of the trust domain.
      if jq -r --arg ns "$ns" --arg name "$name" --arg key "$key" '.items[] | select(.metadata.namespace == $ns and .metadata.name == $name) | .data[$key]' <<<"$list" \
        | (cd "$ROOT" && mise run pki -- trust-bundle --trust-domain "$SPIRE_TRUST_DOMAIN") >/dev/null 2>&1; then
        echo "$cluster $ns $name $key"
      fi
    done < <(jq -r --arg own "$([[ "$cluster" == "$CELL_NAME" ]] && echo 1)" --arg label "$HARNESS_LABEL" --argjson links "$links" '.items[]
      | if $own == "" then select(.metadata.annotations["poc.internal/peer-root-sha256"] != null and .data["root.crt"] != null)
          | "\(.metadata.namespace) \(.metadata.name) root.crt"
        else select((.metadata.name | startswith("spire-trust-bundle-")) and .data["bundle.crt"] != null
            and ((.metadata.labels[$label] // "") as $c | $links | index($c) != null))
          | "\(.metadata.namespace) \(.metadata.name) bundle.crt" end' <<<"$list")
  done
}

# refresh_hostsvc restarts the host service on this Mac, which reads the live root of this cluster only
# at start, and waits until build/hostsvc/mgmt-root.crt holds exactly the roots of the bundle. Only a
# cluster with the link component mgmt-api has a host service to restart. HOSTSVC_SERVE names another
# host service script, for the tests.
refresh_hostsvc() {
  local want got end=$((SECONDS + wait_seconds))
  has_component_entry mgmt-api mgmt-system || return 0
  log "restarting the host service, which holds a copy of the root"
  "${HOSTSVC_SERVE:-$ROOT/scripts/hostsvc-serve.sh}" restart \
    || die "the restart of the host service failed. Fix the cause, then run: mise run hostsvc:serve -- restart, and CELL=$CELL_NAME mise run mgmt:rotate-ca again"
  want="$(bundle_blocks)" || die "could not read the bundle of $CELL_NAME"
  while :; do
    got="$(pem_blocks <"$BUILD_ROOT/hostsvc/mgmt-root.crt" 2>/dev/null || true)"
    [[ "$got" == "$want" ]] && return 0
    ((SECONDS < end)) || die "after ${wait_seconds}s the host service root $BUILD_ROOT/hostsvc/mgmt-root.crt still differs from the bundle of $CELL_NAME. Run: mise run hostsvc:serve -- restart"
    sleep 1
  done
}

# refresh <copies> renders each copy again from the live bundle, then restarts the host service.
refresh() {
  local cluster ns name key done_clusters=" "
  while read -r cluster ns name key; do
    [[ -n "$cluster" ]] || continue
    if [[ -n "${MGMT_ROTATE_REFRESH:-}" ]]; then
      "$MGMT_ROTATE_REFRESH" "$cluster" "$ns" "$name" || die "the refresh of $cluster $ns/$name failed"
    elif [[ "$cluster" == "$CELL_NAME" && "$done_clusters" != *" $cluster "* ]]; then
      log "running cell:link in $cluster, which holds the copy $ns/$name"
      CELL="$cluster" "$ROOT/scripts/link.sh" || die "cell:link of $cluster failed. Fix the cause, then run: CELL=$cluster mise run cell:link, and CELL=$CELL_NAME mise run mgmt:rotate-ca again"
      done_clusters+="$cluster "
    elif [[ "$done_clusters" != *" $cluster "* ]]; then
      log "running cell:up in $cluster, which holds the copy $ns/$name"
      CELL="$cluster" "$ROOT/scripts/up.sh" || die "cell:up of $cluster failed. Fix the cause, then run: CELL=$cluster mise run cell:up, and CELL=$CELL_NAME mise run mgmt:rotate-ca again"
      done_clusters+="$cluster "
    fi
  done <<<"$1"
  refresh_hostsvc
}

# wait_for_copies <copies> waits until each copy holds exactly the roots of the live bundle.
wait_for_copies() {
  local want cluster ns name key got end=$((SECONDS + wait_seconds)) stale
  want="$(bundle_blocks)" || die "could not read the bundle of $CELL_NAME"
  while :; do
    stale=()
    while read -r cluster ns name key; do
      [[ -n "$cluster" ]] || continue
      got="$(kubectl --context "kind-$cluster" -n "$ns" get configmap "$name" -o json | jq -r --arg key "${key:-root.crt}" '.data[$key] // ""' | pem_blocks)"
      [[ "$got" == "$want" ]] || stale+=("$cluster $ns/$name")
    done <<<"$1"
    ((${#stale[@]} == 0)) && return 0
    ((SECONDS < end)) || die "after ${wait_seconds}s these copies still differ from the bundle of $CELL_NAME: ${stale[*]}"
    sleep 5
  done
}

# stale_copies <copies> prints the copies that hold a root which the live bundle does not hold.
stale_copies() {
  local want cluster ns name key got
  want="$(bundle_blocks)" || die "could not read the bundle of $CELL_NAME"
  while read -r cluster ns name key; do
    [[ -n "$cluster" ]] || continue
    got="$(kubectl --context "kind-$cluster" -n "$ns" get configmap "$name" -o json | jq -r --arg key "${key:-root.crt}" '.data[$key] // ""' | pem_blocks)"
    [[ -z "$(comm -23 <(printf '%s\n' "$got") <(printf '%s\n' "$want"))" ]] || echo "$cluster $ns/$name"
  done <<<"$1"
}

# manual <kind> <verb> <authority ID> prints the command that runs one authority step by hand.
manual() {
  printf 'mise x -- kubectl --context kind-%s -n spire-system exec spire-server-0 -c spire-server -- /opt/spire/bin/spire-server localauthority %s %s -socketPath /run/spire/sockets/api.sock -authorityID %s' \
    "$CELL_NAME" "$1" "$2" "$3"
}

# bundle_state prints "<kind> <authority ID> <tainted>" for each authority in the bundle. The ID of
# an X.509 authority is the subject key ID of its root, which pkigen info prints as SPIRE does.
bundle_state() {
  local json asn1 tainted ski
  json="$(server bundle show)" || return 1
  while read -r asn1 tainted; do
    ski="$(printf -- '-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----\n' "$(fold -w 64 <<<"$asn1")" \
      | (cd "$ROOT" && mise run pki -- info 2>/dev/null) | jq -r '.subject_key_id // ""')" || return 1
    [[ -n "$ski" ]] || return 1
    echo "x509 $ski $tainted"
  done < <(jq -r '.x509_authorities[]? | "\(.asn1) \(.tainted // false)"' <<<"$json")
  jq -r '.jwt_authorities[]? | "jwt \(.key_id) \(.tainted // false)"' <<<"$json"
}

# read_state reads the authority slots of both kinds and the bundle.
read_state() {
  x509_state="$(server localauthority x509 show)" && jwt_state="$(server localauthority jwt show)" && bundle="$(bundle_state)" \
    || die "could not read the authorities of the SPIRE server in $CELL_NAME"
}

# slot <kind> <active|prepared|old> prints the authority ID in that slot, or nothing.
slot() {
  local state="${1}_state"
  jq -r --arg slot "$2" '.[$slot].authority_id // ""' <<<"${!state}"
}

# old_status <kind> prints none, untainted, tainted or revoked for the old slot. SPIRE keeps
# listing an old authority after its revoke, so the bundle tells whether a step is left.
old_status() {
  local id tainted
  id="$(slot "$1" old)"
  [[ -n "$id" ]] || { echo none; return; }
  tainted="$(awk -v k="$1" -v id="$id" '$1 == k && $2 == id { print $3 }' <<<"$bundle")"
  case "$tainted" in
    true) echo tainted ;;
    false) echo untainted ;;
    *) echo revoked ;;
  esac
}

holders="$(copies)"
log "$(grep -c . <<<"$holders" || true) ConfigMaps hold a copy of the root of $SPIRE_TRUST_DOMAIN: $(cut -d' ' -f1-3 <<<"$holders" | paste -sd, - | sed 's/,/, /g')"
read_state

# SPIRE prepares into the slot that holds the old authority, so a prepare before the old authority
# is revoked would leave its root trusted until it expires. A run that stopped after the activate
# goes on from the taint or the revoke, and prepares nothing.
resume_refresh=0
if [[ -z "$(slot x509 prepared)" && -z "$(slot jwt prepared)" && "$(old_status x509)" != *tainted && "$(old_status jwt)" != *tainted ]]; then
  stale="$(stale_copies "$holders")"
  [[ -z "$stale" ]] || resume_refresh=1
fi
if ((resume_refresh)); then
  log "the new authorities are active and the old ones are revoked, but these copies hold an old root: $(paste -sd, - <<<"$stale" | sed 's/,/, /g'). This run finishes step 5, the refresh of the copies, and prepares nothing"
elif [[ "$(old_status x509)" == *tainted || "$(old_status jwt)" == *tainted ]]; then
  log "an earlier rotation left old authorities to revoke (X.509 $(old_status x509), JWT $(old_status jwt)). This run finishes that rotation, and prepares nothing"
else
  for kind in x509 jwt; do
    id="$(slot "$kind" prepared)"
    if [[ -n "$id" ]]; then
      log "the $kind authority $id is prepared already, from an earlier run or from SPIRE itself"
      continue
    fi
    before="$(bundle_blocks)" || die "could not read the bundle of $CELL_NAME"
    id="$(server localauthority "$kind" prepare | jq -r '.prepared_authority.authority_id // ""')"
    [[ -n "$id" ]] || die "SPIRE prepared no new $kind authority. Run: CELL=$CELL_NAME mise run mgmt:rotate-ca again"
    if [[ "$kind" == x509 ]]; then
      added="$(comm -13 <(printf '%s\n' "$before") <(bundle_blocks))"
      [[ -n "$added" && "$(wc -l <<<"$added")" -eq 1 ]] || die "the bundle of $CELL_NAME did not gain exactly one root when SPIRE prepared $id"
    fi
    log "prepared the $kind authority $id"
  done
  read_state

  refresh "$holders"
  wait_for_copies "$holders"
  log "each copy holds the new root"

  for kind in x509 jwt; do
    id="$(slot "$kind" prepared)"
    server localauthority "$kind" activate -authorityID "$id" >/dev/null \
      || die "could not activate the $kind authority $id. Each copy holds its root. Run: $(manual "$kind" activate "$id"), then CELL=$CELL_NAME mise run mgmt:rotate-ca again"
    log "activated the $kind authority $id"
  done
  read_state
fi

tainted_now=0
for kind in x509 jwt; do
  if [[ "$(old_status "$kind")" == untainted ]]; then
    id="$(slot "$kind" old)"
    server localauthority "$kind" taint -authorityID "$id" >/dev/null \
      || die "could not taint the old $kind authority $id. Run: $(manual "$kind" taint "$id"), wait ${taint_wait}s, then run: $(manual "$kind" revoke "$id"). Or run CELL=$CELL_NAME mise run mgmt:rotate-ca again, which goes on from this step"
    log "tainted the old $kind authority $id"
    tainted_now=1
  fi
done
if ((tainted_now)); then
  log "the agents replace the SVIDs that the tainted authorities signed. Waiting ${taint_wait}s"
  sleep "$taint_wait"
fi
read_state
for kind in x509 jwt; do
  if [[ "$(old_status "$kind")" == tainted ]]; then
    id="$(slot "$kind" old)"
    server localauthority "$kind" revoke -authorityID "$id" >/dev/null \
      || die "could not revoke the old $kind authority $id. Run: $(manual "$kind" revoke "$id"). Or run CELL=$CELL_NAME mise run mgmt:rotate-ca again, which goes on from this step"
    log "revoked the old $kind authority $id"
  fi
done
read_state
log "the bundle holds $(grep -c '^x509 ' <<<"$bundle" || true) root(s)"

refresh "$holders"
wait_for_copies "$holders"
if ((resume_refresh)); then
  # Exit status 3 tells a caller that this run rotated nothing. Status 1 is a failure, and status 0 is a rotation.
  log "step 5 is finished, and each copy holds only the roots of the bundle. NO NEW CA was prepared or activated: the CA of $CELL_NAME is still $(slot x509 active). To rotate the CA, run CELL=$CELL_NAME mise run mgmt:rotate-ca again"
  exit 3
fi
log "the CA of $CELL_NAME is $(slot x509 active), and each copy holds only the roots of the bundle"
