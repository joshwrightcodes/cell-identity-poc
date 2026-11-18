#!/usr/bin/env bash
# Publish, read and repair the signed bundle sets of the clusters with a bundle role (a cell, or dev-cp).
#
#   bundle.sh publish --target <cluster>... [--wait]
#       For each target: write the bootstrap state when none exists, pack the hydrated bundles and push them to the registry
#       mirror (bundlectl push), ask mgmtd to sign the set (mgmt -- bundle sign), push the root of the set to the mirror
#       (bundlectl push-root), and attach the Sigstore bundle to that root (bundlectl attach). The Sigstore bundle is public
#       data, and the script keeps it in build/<target>/sigstore-<counter>.json. The script prints one JSON line for each target.
#       With --wait, it then polls mgmt -- bundle get every 10 s, for up to 15 min, until the operation of each target has a
#       result. It exits 1 unless that result is applied or already_applied, and on both it writes build/<target>/published.env.
#       A cluster of role open has no signed sets: it keeps cell:publish.
#   bundle.sh get --target <cluster>
#       Print the last signed set of the target, with the result of its operation (mgmt -- bundle get).
#   bundle.sh cosign --target <cluster>
#       Attach the Sigstore bundle that mgmtd holds now for the last set. After a rotation of the signing key, the bundle has the
#       new key, and the referrer of the old key stays.
#   bundle.sh repair --target <cluster>
#       Break glass for a set of argocd or cell-system that left the cluster unable to read the store, so that no rollback can
#       finish. Read good[0] from the state ConfigMap, pull its argocd and cell-system bundles from the mirror, check them against
#       their digests, apply them server side with --force-conflicts, put the root of good[0] back under the tag current through a
#       port-forward to the loopback registry of the store pod, refresh the root Application, and wait until every Application
#       of good[0] is Synced and Healthy at its digest. It prints one JSON line. No signature covers the act, because it restores
#       content that a signed set carried.
#
# BUNDLE_WAIT_SECONDS (default 900) and BUNDLE_WAIT_POLL (default 10) set the bounds of --wait. BUNDLE_REPAIR_SECONDS (default 900)
# sets the bound of the repair wait.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
usage="usage: mise run bundle -- publish --target <cluster>... [--wait] | get --target <cluster> | cosign --target <cluster> | repair --target <cluster>"

# A phase runs for one cluster, with the settings of that cluster. The script starts itself again for each target, with CELL set.
case "${1:-}" in
  _check | _publish | _wait | _cosign | _repair) source "$here/lib.sh" ;;
  *) fail() { printf 'error: %s\n' "$*" >&2; exit 1; } ;;
esac

# mirror_host prints the address of the registry mirror on this Mac.
mirror_host() {
  local facts host
  facts="$(mise run hostsvc -- facts --registry)" || { printf '%s\n' "$facts" >&2; die "could not read the address of the registry mirror"; }
  host="$(jq -r '.host // ""' <<<"$facts")"
  [[ "$host" =~ ^127\.0\.0\.1:[0-9]+$ ]] || die "the registry mirror is at '$host', which is no loopback address with a port"
  printf '%s' "$host"
}

# attach_sigstore <answer of mgmtd> <mirror> writes the Sigstore bundle of the answer to build/<target>/sigstore-<counter>.json and
# attaches it to the root of the set on the mirror. It prints the path of the file.
attach_sigstore() {
  local answer="$1" mirror="$2" root counter file
  root="$(jq -er '.rootDigest' <<<"$answer")" || die "the answer of mgmtd has no root digest"
  counter="$(jq -er '.version.counter' <<<"$answer")" || die "the answer of mgmtd has no version"
  file="$BUILD/sigstore-$counter.json"
  mkdir -p "$BUILD"
  jq -ec '.sigstoreBundle' <<<"$answer" >"$file" || die "the answer of mgmtd has no Sigstore bundle"
  mise run bundlectl -- attach --target "$CELL_NAME" --digest "$root" --bundle "$file" --registry "$mirror" --build "$BUILD_ROOT" >/dev/null \
    || die "could not attach the Sigstore bundle $file to the root $root of $CELL_NAME on the mirror"
  printf '%s' "$file"
}

_check() {
  local role
  role="$(bundle_role)" || exit 1
  case "$role" in
    cell | cp) ;;
    *) die "$CELL_NAME has role $role, so it has no signed bundle sets. Publish its bundles with: CELL=$CELL_NAME mise run cell:publish" ;;
  esac
}

_publish() {
  local role mirror set signed root_digest file pushed
  _check
  role="$(bundle_role)"
  [[ -d "$BUNDLES" ]] || die "no hydrated bundles for $CELL_NAME. Run: CELL=$CELL_NAME mise run cell:hydrate"
  mirror="$(mirror_host)" || exit 1
  bundle_state_bootstrap
  set="$(mise run bundlectl -- push --target "$CELL_NAME" --registry "$mirror" --build "$BUILD_ROOT" --root "$ROOT" "${COMPONENTS[@]}")" \
    || die "bundlectl push failed for $CELL_NAME: $set"
  signed="$(printf '%s' "$set" | CELL=management mise run mgmt -- bundle sign --target "$CELL_NAME")" \
    || die "mgmtd did not sign the set of $CELL_NAME: $signed"
  jq -e '.opId and .rootDigest and .version and .sigstoreBundle' >/dev/null <<<"$signed" || die "the answer of mgmtd for $CELL_NAME is incomplete"
  root_digest="$(jq -r '.rootDigest' <<<"$signed")"
  pushed="$(printf '%s' "$set" | mise run bundlectl -- push-root --role "$role" --target "$CELL_NAME" --set - --registry "$mirror")" \
    || die "bundlectl push-root failed for $CELL_NAME: $pushed"
  [[ "$(jq -r '.digest // ""' <<<"$pushed")" == "$root_digest" ]] \
    || die "the root that bundlectl pushed for $CELL_NAME ($(jq -r '.digest // ""' <<<"$pushed")) differs from the root that mgmtd signed ($root_digest)"
  file="$(attach_sigstore "$signed" "$mirror")"
  log "signed set $(jq -c '.version' <<<"$signed") for $CELL_NAME, root $root_digest, Sigstore bundle $file"
  jq -c --arg target "$CELL_NAME" '{target: $target, opId, version, rootDigest}' <<<"$signed"
}

_wait() {
  local op="$1" end poll got got_op outcome line tmp
  end=$((SECONDS + ${BUNDLE_WAIT_SECONDS:-900}))
  poll="${BUNDLE_WAIT_POLL:-10}"
  while :; do
    if got="$(CELL=management mise run mgmt -- bundle get --target "$CELL_NAME")"; then
      got_op="$(jq -r '.opId // ""' <<<"$got" 2>/dev/null || true)"
      [[ "$got_op" == "$op" ]] || die "the last set of $CELL_NAME is another operation ($got_op), and not the operation $op of this publish"
      outcome="$(jq -r '.result.outcome // ""' <<<"$got")"
      line="$(jq -c --arg target "$CELL_NAME" '{target: $target, opId, version, rootDigest, outcome: .result.outcome, reason: .result.reason, detail: .result.detail}
        | with_entries(select(.value != null))' <<<"$got")"
      case "$outcome" in
        applied | already_applied)
          tmp="$(mktemp "$BUILD/.published.env.XXXXXX")"
          { jq -r '.components[] | "\(.name)=\(.digest)"' <<<"$got"; printf 'root=%s\n' "$(jq -r '.rootDigest' <<<"$got")"; } >"$tmp"
          mv "$tmp" "$PUBLISHED"
          printf '%s\n' "$line"
          return 0 ;;
        "") ;;
        *)
          printf '%s\n' "$line"
          die "the set of $CELL_NAME ended $outcome: $(jq -r '[.result.reason, .result.detail] | map(select(. != null and . != "")) | join(" ")' <<<"$got"). Read it with: mise run bundle -- get --target $CELL_NAME" ;;
      esac
    else
      log "mgmtd did not answer for $CELL_NAME: ${got:-no output}"
    fi
    ((SECONDS < end)) || die "timeout: the set of $CELL_NAME has no final result after ${BUNDLE_WAIT_SECONDS:-900}s. Read it with: mise run bundle -- get --target $CELL_NAME"
    sleep "$poll"
  done
}

_cosign() {
  local mirror answer file
  _check
  mirror="$(mirror_host)" || exit 1
  answer="$(CELL=management mise run mgmt -- bundle cosign --target "$CELL_NAME")" || die "mgmtd has no Sigstore bundle for $CELL_NAME: $answer"
  file="$(attach_sigstore "$answer" "$mirror")"
  jq -c --arg target "$CELL_NAME" --arg file "$file" '{target: $target, opId, rootDigest, sigstore: $file}' <<<"$answer"
}

# fetch_bundle <mirror> <component> <digest> prints the manifests of one bundle from the mirror, after it checks the manifest against the digest.
fetch_bundle() {
  local mirror="$1" component="$2" digest="$3" ref manifest layer text
  ref="$mirror/bundles/$CELL_NAME/$component"
  manifest="$(oras manifest fetch --plain-http "$ref@$digest" && printf x)" || die "could not read $component@$digest from the mirror"
  manifest="${manifest%x}"
  [[ "sha256:$(printf '%s' "$manifest" | sha256)" == "$digest" ]] || die "the manifest of $component on the mirror does not match the digest $digest"
  layer="$(jq -er '.layers[-1].digest' <<<"$manifest")" || die "the manifest of $component names no layer"
  text="$(oras blob fetch --plain-http --output - "$ref@$layer" | tar -xzOf - manifests.yaml && printf x)" || die "could not read the layer of $component"
  printf '%s' "${text%x}"
}

_repair() {
  local role state good root_digest mirror component digest text want apps blockers end
  _check
  role="$(bundle_role)"
  state="$(bundle_state_json)" || exit 1
  [[ -n "$state" ]] || die "$CELL_NAME has no bundle state, so it has no good root to restore"
  good="$(jq -c '.good[0] // empty' <<<"$state")"
  [[ -n "$good" ]] || die "the bundle state of $CELL_NAME records no good root (good[0]), so repair has nothing to restore"
  root_digest="$(jq -r '.root.digest' <<<"$good")"
  [[ "sha256:$(jq -j '.root.manifest | @base64d' <<<"$good" | sha256)" == "$root_digest" ]] \
    || die "the root manifest in good[0] of $CELL_NAME does not match its digest $root_digest"
  mirror="$(mirror_host)" || exit 1

  # Read and check both bundles before the first change.
  local names=(argocd cell-system) texts=()
  for component in "${names[@]}"; do
    digest="$(jq -er --arg c "$component" '.components[$c]' <<<"$good")" || die "good[0] of $CELL_NAME names no digest for $component"
    text="$(fetch_bundle "$mirror" "$component" "$digest" && printf x)" || exit 1
    texts+=("$text")
  done
  local i
  for i in "${!names[@]}"; do
    text="${texts[$i]%x}"
    if ! k apply --server-side --force-conflicts -f - >/dev/null 2>&1 <<<"$text"; then
      # A bundle can hold a CRD and an object of that kind. Wait for the CRD, then apply again to see any real error.
      k wait --for=condition=Established crd --all --timeout=120s >/dev/null
      k apply --server-side --force-conflicts -f - >/dev/null <<<"$text"
    fi
    log "applied ${names[$i]} of good[0]"
  done

  bundle_store_forward
  jq -j '.root.manifest | @base64d' <<<"$good" \
    | oras manifest push --plain-http --media-type application/vnd.oci.image.manifest.v1+json "127.0.0.1:${CELL_BUNDLE_STORE_PORT}/bundles/root:current" - >/dev/null \
    || die "could not put the root $root_digest back under the tag current"
  log "put the root $root_digest back under the tag current"
  k -n argocd annotate application root argocd.argoproj.io/refresh=hard --overwrite >/dev/null

  want="$(jq -c '.components + {root: .root.digest}' <<<"$good")"
  end=$((SECONDS + ${BUNDLE_REPAIR_SECONDS:-900}))
  while :; do
    apps="$(k -n argocd get applications -o json)" || die "could not read the Applications of $CELL_NAME"
    blockers="$(jq -r --argjson want "$want" '(.items | map({key: .metadata.name, value: .}) | from_entries) as $a
      | $want | to_entries[] | . as $w | ($a[$w.key] // {}) as $app
      | select(($app.status.sync.status // "") != "Synced" or ($app.status.health.status // "") != "Healthy" or ($app.status.sync.revision // "") != $w.value)
      | "\($w.key) is \($app.status.sync.status // "missing")/\($app.status.health.status // "missing") at \($app.status.sync.revision // "no revision"), want \($w.value)"' <<<"$apps")"
    [[ -n "$blockers" ]] && ((SECONDS < end)) || break
    sleep "${BUNDLE_WAIT_POLL:-10}"
  done
  [[ -z "$blockers" ]] || die "after the repair, the Applications of $CELL_NAME are not at good[0]: ${blockers//$'\n'/; }"
  jq -nc --arg target "$CELL_NAME" --arg root "$root_digest" --argjson components "$(jq -c '.components' <<<"$good")" \
    '{target: $target, root: $root, components: $components, applied: ["argocd", "cell-system"]}'
}

if [[ "${1:-}" == _* ]]; then
  phase="$1"
  shift
  "$phase" "$@"
  exit
fi

# The main script reads the arguments, checks every target, and runs the phases for one target after the other.
cmd="${1:-}"
[[ -n "$cmd" ]] || fail "$usage"
shift
targets=() wait=0
while (($#)); do
  case "$1" in
    --target)
      [[ -n "${2:-}" ]] || fail "--target needs a cluster name. $usage"
      targets+=("$2")
      shift 2 ;;
    --wait)
      [[ "$cmd" == publish ]] || fail "--wait belongs to publish. $usage"
      wait=1
      shift ;;
    *) fail "unknown argument '$1'. $usage" ;;
  esac
done
((${#targets[@]} > 0)) || fail "$cmd needs --target. $usage"
case "$cmd" in
  publish) ;;
  get | cosign | repair) ((${#targets[@]} == 1)) || fail "$cmd takes one --target. $usage" ;;
  *) fail "unknown command '$cmd'. $usage" ;;
esac

run_for() { local t="$1"; shift; CELL="$t" "$here/bundle.sh" "$@"; }

if [[ "$cmd" == get ]]; then
  CELL=management mise run mgmt -- bundle get --target "${targets[0]}"
  exit
fi
# Every target is checked before the first signature, so a call with a wrong target changes nothing.
for t in "${targets[@]}"; do run_for "$t" _check || exit 1; done
case "$cmd" in
  publish)
    ops=()
    for t in "${targets[@]}"; do
      line="$(run_for "$t" _publish)" || exit 1
      printf '%s\n' "$line"
      ops+=("$(jq -r '.opId' <<<"$line")")
    done
    ((wait)) || exit 0
    rc=0
    for i in "${!targets[@]}"; do run_for "${targets[$i]}" _wait "${ops[$i]}" || rc=1; done
    exit "$rc" ;;
  cosign) run_for "${targets[0]}" _cosign ;;
  repair) run_for "${targets[0]}" _repair ;;
esac
