#!/usr/bin/env bash
# Replace the intermediate CA of the SPIRE server in the cluster $CELL with a new one.
#   1. Read the root CA bundle from the secret manager, and let pkigen sign a new intermediate.
#   2. Write the new key and certificate to the remote keys <cluster>/spire-server/intermediate-key
#      and <cluster>/spire-server/intermediate-cert.
#   3. Run secrets:connect, which syncs Secret spire-upstream now.
#   4. Restart the SPIRE server, so that it signs a new CA through the new intermediate.
#   5. Check that the active X.509 authority of the server names the new intermediate as its
#      upstream authority.
# Three settings come from .envrc.local, next to the two of secrets:connect:
#   POC_SECRET_READ_CMD   a command that prints the value of the remote key "$1"
#   POC_SECRET_WRITE_CMD  a command that stores standard input at the remote key "$1"
#   POC_ROOT_CA_BUNDLE    the remote key of the root CA bundle
# PKI_INTERMEDIATE_DAYS sets the validity of the new intermediate. The default is 30.
# PKI_ROTATE_CHECK_WAIT bounds the last check in seconds. The default is 120.
# Keys stay in shell variables and pipes. No step prints a key or writes one to disk.
source "$(dirname "$0")/lib.sh"

runs_spire_server=0
for entry in "${COMPONENTS[@]}"; do
  [[ "${entry%%:*}" == spire-server ]] && runs_spire_server=1
done
((runs_spire_server)) || die "cluster $CELL_NAME runs no SPIRE server in harness/topology.yaml. Run: CELL=dev-cp mise run pki:rotate-intermediate"

load_local_settings POC_SECRET_READ_CMD POC_SECRET_WRITE_CMD POC_ROOT_CA_BUNDLE
for name in POC_SECRET_READ_CMD POC_SECRET_WRITE_CMD POC_ROOT_CA_BUNDLE; do
  [[ -n "${!name:-}" ]] || die "$name is not set. Copy it from .envrc.local.example to .envrc.local and complete it. direnv loads .envrc.local after you run direnv allow, and this script reads it when a setting is unset"
done
days="${PKI_INTERMEDIATE_DAYS:-30}"
[[ "$days" =~ ^[1-9][0-9]*$ ]] || die "PKI_INTERMEDIATE_DAYS '$days' is not a whole number of days"

# pki <args...> runs pkigen with standard input. A failure prints one JSON error line, which
# carries no key material.
pki() { (cd "$ROOT" && mise run pki -- "$@"); }

root="$(bash -c "$POC_SECRET_READ_CMD" _ "$POC_ROOT_CA_BUNDLE")" || die "POC_SECRET_READ_CMD failed for the root CA bundle"
inter="$(printf '%s\n' "$root" | pki intermediate --days "$days")" || die "pkigen could not sign an intermediate: $inter"
unset root
key="$(printf '%s\n' "$inter" | pki key)" || die "pkigen could not print the key: $key"
cert="$(printf '%s\n' "$inter" | pki cert)" || die "pkigen could not print the certificate: $cert"
unset inter
info="$(printf '%s\n' "$cert" | pki info)" || die "pkigen could not read the new certificate: $info"
want_ski="$(jq -r '.subject_key_id' <<<"$info")"
log "signed a new intermediate with subject key ID $want_ski, valid until $(jq -r '.not_after' <<<"$info")"

# The certificate goes second, so a reader of the pair never sees a new certificate with an old key.
printf '%s\n' "$key" | bash -c "$POC_SECRET_WRITE_CMD" _ "$CELL_NAME/spire-server/intermediate-key" \
  || die "POC_SECRET_WRITE_CMD failed for $CELL_NAME/spire-server/intermediate-key"
unset key
printf '%s\n' "$cert" | bash -c "$POC_SECRET_WRITE_CMD" _ "$CELL_NAME/spire-server/intermediate-cert" \
  || die "POC_SECRET_WRITE_CMD failed for $CELL_NAME/spire-server/intermediate-cert. The key is new and the certificate is old. Run: CELL=$CELL_NAME mise run pki:rotate-intermediate again"
log "wrote the new intermediate to $CELL_NAME/spire-server/intermediate-key and intermediate-cert"

"$ROOT/scripts/secrets-connect.sh" || die "secrets:connect failed. Fix the cause, then run: CELL=$CELL_NAME mise run secrets:connect, and then CELL=$CELL_NAME mise run cell:restart"
"$ROOT/scripts/restart.sh" || die "the restart failed. Run: CELL=$CELL_NAME mise run cell:restart"

# active_upstream prints the subject key ID of the upstream authority of the active X.509 authority.
active_upstream() {
  k -n spire-system exec spire-server-0 -c spire-server -- /opt/spire/bin/spire-server localauthority x509 show \
    -socketPath /run/spire/sockets/api.sock -output json | jq -r '.active.upstream_authority_subject_key_id // ""'
}
end=$((SECONDS + ${PKI_ROTATE_CHECK_WAIT:-120}))
until got="$(active_upstream 2>/dev/null)" && [[ "$got" == "$want_ski" ]]; do
  if ((SECONDS >= end)); then
    die "the active X.509 authority of the SPIRE server has the upstream authority '${got:-unknown}', and the new intermediate is $want_ski. Read the server log: mise x -- kubectl --context kind-$CELL_NAME -n spire-system logs spire-server-0 -c spire-server"
  fi
  sleep 5
done
log "the active X.509 authority of the SPIRE server chains to the new intermediate $want_ski"
