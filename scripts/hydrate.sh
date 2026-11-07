#!/usr/bin/env bash
# Render every component into build/bundles/<component>/manifests.yaml.
# A component with an executable render.sh renders itself. Every other component is a kustomization.
source "$(dirname "$0")/lib.sh"

[[ -f "$FACTS" ]] || "$ROOT/scripts/facts.sh"
set -a; source "$FACTS"; set +a
export CELL_NAME CELL_MESH_TRUST_DOMAIN

for entry in "${COMPONENTS[@]}"; do
  c="${entry%%:*}"
  dir="$ROOT/components/$c"
  out="$BUNDLES/$c"
  rm -rf "$out"
  mkdir -p "$out"
  if [[ -x "$dir/render.sh" ]]; then
    "$dir/render.sh" >"$out/raw.yaml"
  else
    kustomize build --enable-helm --load-restrictor LoadRestrictionsNone "$dir" >"$out/raw.yaml"
  fi
  sed -e "s|@CELL_NAME@|$CELL_NAME|g" \
    -e "s|@CELL_MESH_TRUST_DOMAIN@|$CELL_MESH_TRUST_DOMAIN|g" \
    "$out/raw.yaml" >"$out/manifests.yaml"
  rm "$out/raw.yaml"
  if grep -n '@[A-Z_]*@' "$out/manifests.yaml"; then
    die "$c has a token that hydrate does not replace"
  fi
  log "$c: $(grep -c '^kind:' "$out/manifests.yaml") resources"
done
