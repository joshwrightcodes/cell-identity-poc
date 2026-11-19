# The Argo CD Applications that the apply engine of a bundle role may patch. Source this file from a render script. It
# needs only jq.
#
# The engine patches root to ask for a hard refresh, and on a rollback it terminates the running sync operation of root
# and of each component Application. The root bundle holds one Application for each component, named after it, so the
# names come from the components of the role in internal/bundle/allow.json. BUNDLE_ALLOW_JSON names another allow-list
# file, for the tests.

BUNDLE_APPS_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

# bundle_argo_apps <role> prints a JSON array: root, then the components of the role in name order.
bundle_argo_apps() {
  local allow="${BUNDLE_ALLOW_JSON:-$BUNDLE_APPS_ROOT/internal/bundle/allow.json}"
  jq -ce --arg role "$1" '.roles[$role].components // {} | keys | select(length > 0 and (index("root") | not)) | ["root"] + .' "$allow" \
    || { echo "error: bundle-apps: $allow lists no components for role $1" >&2; return 1; }
}
