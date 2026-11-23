# The seed pipes of the operator scripts. Source this file from scripts/operator-key.sh and scripts/revoke.sh, after scripts/lib.sh,
# and run from the repository root. The read command POC_SECRET_READ_CMD pipes the seed straight into operatorctl, so no file,
# variable, argument or log line holds it. The caller sets pipefail, so a failed read fails the pipe. This file holds every read of the operator
# seed, for scripts/operator-key.sh and scripts/revoke.sh. scripts/operator-key.sh also writes the seed in its keygen pipe.
# scripts/pki-rotate-intermediate.sh reads and writes the secret manager for the root CA bundle and the intermediate. components/lib never does.

# operator_seed_pub <remote key name> prints the public key of the seed.
operator_seed_pub() {
  local name="$1"
  operator_key_name_valid "$name" || { echo "error: the remote key name is not valid, so no secret is read" >&2; return 1; }
  bash -c "$POC_SECRET_READ_CMD" _ "$name" | mise run operatorctl -- pub
}

# operator_seed_sign <remote key name> <operatorctl sign arguments...> prints the signed envelope.
operator_seed_sign() {
  local name="$1"
  shift
  operator_key_name_valid "$name" || { echo "error: the remote key name is not valid, so no secret is read" >&2; return 1; }
  bash -c "$POC_SECRET_READ_CMD" _ "$name" | mise run operatorctl -- sign "$@"
}
