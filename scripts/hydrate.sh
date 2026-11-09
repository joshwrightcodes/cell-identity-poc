#!/usr/bin/env bash
# Render every component into build/<cluster>/bundles/<component>/manifests.yaml.
# A component with an executable render.sh renders itself. Every other component is a kustomization.
source "$(dirname "$0")/lib.sh"

[[ -f "$FACTS" ]] || "$ROOT/scripts/facts.sh"
set -a; source "$FACTS"; set +a
export CELL_NAME CELL_MESH_TRUST_DOMAIN

# The render writes into a temporary directory. A failed render leaves the last good bundle in place.
for entry in "${COMPONENTS[@]}" ${HARNESS_COMPONENTS[@]+"${HARNESS_COMPONENTS[@]}"}; do
  c="${entry%%:*}"
  dir="$ROOT/components/$c"
  out="$BUNDLES/$c"
  mkdir -p "$BUNDLES"
  tmp="$(mktemp -d "$BUNDLES/.$c.XXXXXX")"
  trap 'rm -rf "$tmp"' EXIT
  if [[ -x "$dir/render.sh" ]]; then
    "$dir/render.sh" >"$tmp/raw.yaml"
  else
    kustomize build --enable-helm --load-restrictor LoadRestrictionsNone "$dir" >"$tmp/raw.yaml"
  fi
  sed -e "s|@CELL_NAME@|$CELL_NAME|g" \
    -e "s|@CELL_MESH_TRUST_DOMAIN@|$CELL_MESH_TRUST_DOMAIN|g" \
    "$tmp/raw.yaml" >"$tmp/manifests.yaml"
  rm "$tmp/raw.yaml"
  if grep -n '@[A-Z_]*@' "$tmp/manifests.yaml"; then
    die "$c has a token that hydrate does not replace"
  fi
  rm -rf "$out"
  mv "$tmp" "$out"
  trap - EXIT
  log "$c: $(grep -c '^kind:' "$out/manifests.yaml") resources"
done
