# The seed pipes of the operator scripts. Source this file from scripts/operator-key.sh and scripts/revoke.sh, after scripts/lib.sh,
# and run from the repository root. The read command POC_SECRET_READ_CMD pipes the seed straight into operatorctl, so no file,
# variable, argument or log line holds it. The caller sets pipefail, so a failed read fails the pipe. This file and scripts/operator-key.sh
# read the operator seed. scripts/pki-rotate-intermediate.sh also reads the secret manager, for the root CA bundle. components/lib never does.

# operator_seed_pub <remote key name> prints the public key of the seed.
operator_seed_pub() {
  local name="$1"
  bash -c "$POC_SECRET_READ_CMD" _ "$name" | mise run operatorctl -- pub
}

# operator_seed_sign <remote key name> <operatorctl sign arguments...> prints the signed envelope.
operator_seed_sign() {
  local name="$1"
  shift
  bash -c "$POC_SECRET_READ_CMD" _ "$name" | mise run operatorctl -- sign "$@"
}
