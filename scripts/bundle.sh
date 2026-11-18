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
#       finish. It trusts only what it verifies. The root of good[0] is either the bootstrap root that build/<t>/root.json names, or a
#       root that cosign verifies offline against the current public key of mgmtd (mise run mgmt -- pubkey) with the signed digest as
#       subject. The digests of argocd and cell-system come from the root layer, and the signed statement must name the same ones.
#       Then: put the verified root manifest back under the tag current through a port-forward to the loopback registry of the store
#       pod, pin the Applications cell-system and argocd at the good digests (Argo CD would serve the bad set from its cache), apply the
#       two bundles server side with --force-conflicts, delete the pod bundle-store-0 (a pod that never became Ready stays), refresh the
#       root Application, and wait until every Application of the good root is Synced and Healthy at its digest. It prints one JSON line.
#       The Mac administrator applies the bundles, and no new signature covers the act.
#
# publish and repair take the cluster lock of each target, in sorted order, and hold it until the end. cell:up holds it and runs publish,
# so a nested call passes. BUNDLE_WAIT_SECONDS is one bound for every target.
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

# pull_bundle <host> <repository> <digest> <directory> reads one bundle from a registry into <directory>: manifest.json, after its bytes
# are checked against the digest, and layer.tgz, after its bytes are checked against the digest in the manifest. The files hold public
# bundle content, and the caller removes the directory.
pull_bundle() {
  local host="$1" repo="$2" digest="$3" dir="$4" layer
  mkdir -p "$dir"
  oras manifest fetch --plain-http "$host/$repo@$digest" >"$dir/manifest.json" || die "could not read $repo@$digest from $host"
  [[ "sha256:$(sha256 <"$dir/manifest.json")" == "$digest" ]] || die "the manifest of $repo on $host does not match the digest $digest"
  layer="$(jq -er '.layers[-1].digest' "$dir/manifest.json")" || die "the manifest of $repo names no layer"
  oras blob fetch --plain-http --output - "$host/$repo@$layer" >"$dir/layer.tgz" || die "could not read the layer of $repo from $host"
  [[ "sha256:$(sha256 <"$dir/layer.tgz")" == "$layer" ]] || die "the layer of $repo on $host does not match its digest $layer"
}

# verify_signed_root <root digest> <statement file> checks with cosign, offline, that mgmtd signed the root bundle of this target with its
# current key, and writes the in-toto statement of the signature to <statement file>. cosign gets an empty Docker configuration, and
# it skips the transparency log, which no set uses. A root that a key before a rotation signed needs: mise run bundle -- cosign --target <t>.
verify_signed_root() {
  local root="$1" out="$2" keyline pem keydir dockerdir envelope
  keyline="$(CELL=management mise run mgmt -- pubkey)" || die "could not read the public key of mgmtd: $keyline"
  pem="$(printf '%s' "$keyline" | mise run bundlectl -- pubkey-pem)" || die "could not convert the public key of mgmtd"
  keydir="$(mktemp -d)"
  dockerdir="$(mktemp -d)"
  printf '%s\n' "$pem" >"$keydir/mgmt.pub"
  envelope="$(DOCKER_CONFIG="$dockerdir" mise x -- cosign verify-attestation --key "$keydir/mgmt.pub" --insecure-ignore-tlog=true --allow-http-registry \
    --type https://cell.poc.internal/bundle-set/v1 "$MIRROR/bundles/$CELL_NAME/root@$root" 2>/dev/null)" \
    || { rm -rf "$keydir" "$dockerdir"; die "cosign does not verify the root $root of $CELL_NAME against the current key of mgmtd, so repair does not trust it. If the key rotated, run: mise run bundle -- cosign --target $CELL_NAME"; }
  rm -rf "$keydir" "$dockerdir"
  jq -s 'map(.payload | @base64d | fromjson) | .[0]' <<<"$envelope" >"$out" || die "the cosign answer for $root holds no statement"
  jq -e --arg d "${root#sha256:}" --arg n "bundles/$CELL_NAME/root" '[.subject[]? | select(.name == $n and .digest.sha256 == $d)] | length == 1' "$out" >/dev/null \
    || die "the signed statement has no subject bundles/$CELL_NAME/root with the digest $root"
}

_repair() {
  local role state good root_digest store anchor origin host root_repo comp_repo stmt component rev text apps_want
  _check
  role="$(bundle_role)"
  state="$(bundle_state_json)" || exit 1
  [[ -n "$state" ]] || die "$CELL_NAME has no bundle state, so it has no good root to restore"
  good="$(jq -c '.good[0] // empty' <<<"$state")"
  [[ -n "$good" ]] || die "the bundle state of $CELL_NAME records no good root (good[0]), so repair has nothing to restore"
  root_digest="$(jq -r '.root.digest // ""' <<<"$good")"
  [[ "$root_digest" =~ ^sha256:[0-9a-f]{64}$ ]] || die "good[0] of $CELL_NAME holds no root digest"
  MIRROR="$(mirror_host)" || exit 1
  bundle_store_forward
  store="127.0.0.1:${CELL_BUNDLE_STORE_PORT}"
  work="$(mktemp -d)"
  trap 'kill "$BUNDLE_STORE_PF_PID" 2>/dev/null || true; rm -rf "$work"' EXIT

  # The state is no anchor: any writer of ConfigMaps in the operations namespace can change it. Repair trusts a root that the Mac knows as the
  # bootstrap root (build/<t>/root.json), or one that mgmtd signed (cosign, current key). It takes the bundle digests from the root layer.
  anchor="$(jq -r '.digest // ""' "$BUILD/root.json" 2>/dev/null || true)"
  stmt="$work/statement.json"
  if [[ -n "$anchor" && "$anchor" == "$root_digest" ]]; then
    origin=bootstrap host="$store" root_repo=bundles/root comp_repo=bundles
  else
    origin=signed host="$MIRROR" root_repo="bundles/$CELL_NAME/root" comp_repo="bundles/$CELL_NAME"
    verify_signed_root "$root_digest" "$stmt"
  fi
  pull_bundle "$host" "$root_repo" "$root_digest" "$work/root"
  for component in argocd cell-system; do
    rev="$(tar -xzOf "$work/root/layer.tgz" "$component.yaml" | yq -r '.spec.source.targetRevision // ""')" || die "the root $root_digest holds no Application $component"
    [[ "$rev" =~ ^sha256:[0-9a-f]{64}$ ]] || die "the Application $component in the root $root_digest pins '$rev', which is no digest"
    if [[ "$origin" == signed ]]; then
      [[ "$(jq -r --arg n "bundles/$CELL_NAME/$component" '[.subject[]? | select(.name == $n) | .digest.sha256][0] // ""' "$stmt")" == "${rev#sha256:}" ]] \
        || die "the signed statement names another digest for $component than the root layer ($rev)"
    elif [[ -f "$BUILD/root.json" ]]; then
      [[ "$(jq -r --arg c "$component" '.components[$c] // ""' "$BUILD/root.json")" == "" || "$(jq -r --arg c "$component" '.components[$c]' "$BUILD/root.json")" == "$rev" ]] \
        || die "build/$CELL_NAME/root.json names another digest for $component than the root layer ($rev)"
    fi
    pull_bundle "$host" "$comp_repo/$component" "$rev" "$work/$component"
  done
  # Every Application of the good root must come back: the root layer names each one.
  apps_want="$(for f in $(tar -tzf "$work/root/layer.tgz" | grep '\.yaml$'); do
    tar -xzOf "$work/root/layer.tgz" "$f" | yq -o=json -I=0 '{(.metadata.name): .spec.source.targetRevision}'
  done | jq -sc --arg root "$root_digest" 'add + {root: $root}')" || die "could not read the Applications of the root $root_digest"

  # The tag goes first, through the loopback forward, which works while the store proxy is down. Then Argo CD must not serve a bad set from its
  # cache: pin the child Applications at the good digests, apply the good bundles, and replace the pod of the store that never became Ready.
  oras manifest push --plain-http --media-type application/vnd.oci.image.manifest.v1+json "$store/bundles/root:current" - <"$work/root/manifest.json" >/dev/null \
    || die "could not put the root $root_digest back under the tag current"
  log "put the root $root_digest back under the tag current"
  for component in cell-system argocd; do
    rev="$(jq -r --arg c "$component" '.[$c]' <<<"$apps_want")"
    k -n argocd patch application "$component" --type merge -p "$(jq -nc --arg d "$rev" '{spec: {source: {targetRevision: $d}}}')" >/dev/null \
      || log "could not pin the Application $component at $rev"
  done
  for component in argocd cell-system; do
    text="$(tar -xzOf "$work/$component/layer.tgz" manifests.yaml && printf x)" || die "the bundle $component holds no manifests.yaml"
    text="${text%x}"
    if ! k apply --server-side --force-conflicts -f - >/dev/null 2>&1 <<<"$text"; then
      # A bundle can hold a CRD and an object of that kind. Wait for the CRD, then apply again to see any real error.
      k wait --for=condition=Established crd --all --timeout=120s >/dev/null || die "a CustomResourceDefinition of the $component bundle is not Established after 120s"
      k apply --server-side --force-conflicts -f - >/dev/null <<<"$text" || die "could not apply the bundle $component of good[0]"
    fi
    log "applied $component of good[0]"
  done
  k -n cell-system delete pod bundle-store-0 --ignore-not-found --wait=true --timeout=120s >/dev/null || die "could not delete the pod bundle-store-0"
  k -n argocd annotate application root argocd.argoproj.io/refresh=hard --overwrite >/dev/null

  local apps blockers end
  end=$((SECONDS + ${BUNDLE_REPAIR_SECONDS:-900}))
  while :; do
    apps="$(k -n argocd get applications -o json)" || die "could not read the Applications of $CELL_NAME"
    blockers="$(jq -r --argjson want "$apps_want" '(.items | map({key: .metadata.name, value: .}) | from_entries) as $a
      | $want | to_entries[] | . as $w | ($a[$w.key] // {}) as $app
      | select(($app.status.sync.status // "") != "Synced" or ($app.status.health.status // "") != "Healthy" or ($app.status.sync.revision // "") != $w.value)
      | "\($w.key) is \($app.status.sync.status // "missing")/\($app.status.health.status // "missing") at \($app.status.sync.revision // "no revision"), want \($w.value)"' <<<"$apps")"
    [[ -n "$blockers" ]] && ((SECONDS < end)) || break
    sleep "${BUNDLE_WAIT_POLL:-10}"
  done
  [[ -z "$blockers" ]] || die "after the repair, the Applications of $CELL_NAME are not at good[0]: ${blockers//$'\n'/; }"
  jq -nc --arg target "$CELL_NAME" --arg root "$root_digest" --arg origin "$origin" --argjson components "$apps_want" \
    '{target: $target, root: $root, origin: $origin, components: ($components | del(.root)), applied: ["argocd", "cell-system"]}'
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
for t in "${targets[@]}"; do
  [[ -f "$here/../cells/$t.env" ]] || fail "unknown cluster '$t'. $usage"
done
# Every target is checked before the first lock and the first signature, so a call with a wrong target changes nothing.
for t in "${targets[@]}"; do run_for "$t" _check || exit 1; done
if [[ "$cmd" != cosign ]]; then
  # Publish and repair change a cluster, so they take its lock, as cell:up does. The locks go in sorted order, and the phases below inherit
  # them (POC_HELD_LOCKS). cosign reads mgmtd and writes a referrer on the mirror of this Mac, so it takes none.
  sorted=()
  while IFS= read -r t; do sorted+=("$t"); done < <(printf '%s\n' "${targets[@]}" | sort -u)
  CELL="${sorted[0]}"
  source "$here/lib.sh"
  for t in "${sorted[@]}"; do cluster_lock "$t"; done
fi
case "$cmd" in
  publish)
    ops=()
    for t in "${targets[@]}"; do
      line="$(run_for "$t" _publish)" || exit 1
      printf '%s\n' "$line"
      ops+=("$(jq -r '.opId' <<<"$line")")
    done
    ((wait)) || exit 0
    # One bound for all the targets: each wait gets what is left.
    deadline=$((SECONDS + ${BUNDLE_WAIT_SECONDS:-900}))
    rc=0
    for i in "${!targets[@]}"; do
      left=$((deadline - SECONDS))
      ((left >= 0)) || left=0
      BUNDLE_WAIT_SECONDS="$left" run_for "${targets[$i]}" _wait "${ops[$i]}" || rc=1
    done
    exit "$rc" ;;
  cosign) run_for "${targets[0]}" _cosign ;;
  repair) run_for "${targets[0]}" _repair ;;
esac
