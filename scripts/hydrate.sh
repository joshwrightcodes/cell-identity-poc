#!/usr/bin/env bash
# Render every component into build/<cluster>/bundles/<component>/manifests.yaml.
# A component with an executable render.sh renders itself. Every other component is a kustomization.
# The renders of link components read the live roots and node addresses of other clusters, so
# CELL_UP_SKIP_LINK=1 skips them, and HYDRATE_ONLY=link renders only them. The harness components in
# LATE_HARNESS read the SPIRE server of their own cluster: CELL_UP_SKIP_LATE=1 skips them, and
# HYDRATE_ONLY=late renders only them. LINK_ONLY=<component> narrows HYDRATE_ONLY=link to that one
# link component, and an unknown name fails.
# HARNESS_ONLY=<component> renders only that harness component, for cell:up with HARNESS_ONLY, and an unknown
# name fails. It cannot go with HYDRATE_ONLY.
source "$(dirname "$0")/lib.sh"

[[ -f "$FACTS" ]] || "$ROOT/scripts/facts.sh"
set -a; source "$FACTS"; set +a
export CELL_NAME CELL_MESH_TRUST_DOMAIN

entries=()
[[ -z "${HARNESS_ONLY:-}" || -z "${HYDRATE_ONLY:-}" ]] || die "HARNESS_ONLY and HYDRATE_ONLY cannot go together"
case "${HYDRATE_ONLY:-}" in
  "") if [[ -n "${HARNESS_ONLY:-}" ]]; then
      entries=("$(harness_only_entry)") || exit 1
    else
      entries=("${COMPONENTS[@]}" ${HARNESS_COMPONENTS[@]+"${HARNESS_COMPONENTS[@]}"})
      if [[ "${CELL_UP_SKIP_LINK:-}" == 1 ]]; then
        ((${#LINK_COMPONENTS[@]} == 0)) || log "skipping the link components, because CELL_UP_SKIP_LINK=1"
      else
        entries+=(${LINK_COMPONENTS[@]+"${LINK_COMPONENTS[@]}"})
      fi
      if [[ "${CELL_UP_SKIP_LATE:-}" == 1 ]]; then
        kept=()
        for e in "${entries[@]}"; do [[ " ${LATE_HARNESS[*]} " == *" ${e%%:*} "* ]] || kept+=("$e"); done
        entries=("${kept[@]}")
      fi
    fi ;;
  link) linked="$(link_entries)" || exit 1
    while read -r e; do [[ -z "$e" ]] || entries+=("$e"); done <<<"$linked" ;;
  late) for e in ${HARNESS_COMPONENTS[@]+"${HARNESS_COMPONENTS[@]}"}; do
      if [[ " ${LATE_HARNESS[*]} " == *" ${e%%:*} "* ]]; then entries+=("$e"); fi
    done ;;
  *) die "HYDRATE_ONLY '$HYDRATE_ONLY' is not link or late" ;;
esac
[[ -z "${LINK_ONLY:-}" || "${HYDRATE_ONLY:-}" == link ]] || die "LINK_ONLY applies only with HYDRATE_ONLY=link"

# The render writes into a temporary directory. A failed render leaves the last good bundle in place.
for entry in ${entries[@]+"${entries[@]}"}; do
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
