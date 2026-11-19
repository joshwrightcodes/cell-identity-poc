#!/usr/bin/env bash
# Render the argocd bundle: the kustomization, with the AppProjects of the role of the cluster.
# A cluster with role cell or cp gets the projects that `bundlectl projects --role <role>` prints, which
# are the spec that the applier checks (internal/bundle ExpectedAppProjectSpec) and carry the SHA-256 of
# the allow-list. A cluster with role open keeps the project cell of project.yaml. The render still holds
# the token @CELL_PROXY_IMAGE@, which scripts/hydrate.sh replaces.
set -euo pipefail
: "${CELL_NAME:?}"

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
source "$root/components/lib/bundle-role.sh"

role="$(bundle_role_of "$CELL_NAME")" || exit 1
raw="$(kustomize build --enable-helm --load-restrictor LoadRestrictionsNone "$here")"
if [[ "$role" == open ]]; then
  printf '%s\n' "$raw"
  exit 0
fi
projects="$(cd "$root" && mise run bundlectl -- projects --role "$role" --root "$root")" \
  || { echo "error: argocd render: bundlectl projects --role $role failed" >&2; exit 1; }
[[ -n "$projects" ]] || { echo "error: argocd render: bundlectl printed no project for role $role" >&2; exit 1; }
{
  yq 'select(.kind != "AppProject" or .metadata.name != "cell")' <<<"$raw"
  echo "---"
  printf '%s\n' "$projects"
}
