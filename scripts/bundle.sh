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
#   bundle.sh verify --target <cluster>
#       Check on this Mac that mgmtd signed the root of the state: cosign verify-attestation, offline, against the current public key of mgmtd.
#       It prints one JSON line with the signed version and the subjects of the statement (the root and each component). It changes nothing.
#   bundle.sh repair --target <cluster> [--allow-older]
#       Break glass for a set of argocd or cell-system that left the cluster unable to read the store, so that no rollback can
#       finish. It trusts only what it verifies. The root of good[0] is either the bootstrap root that build/<t>/root.json names, or a
#       root that cosign verifies offline against the current public key of mgmtd (mise run mgmt -- pubkey) with the signed digest as
#       subject. The digests of argocd and cell-system come from the root layer, and the signed statement must name the same ones.
#       Then: put the verified root manifest back under the tag current through a port-forward to the loopback registry of the store
#       pod, pin the Applications cell-system and argocd at the good digests (Argo CD would serve the bad set from its cache), apply the
#       two bundles server side with --force-conflicts, delete the pod bundle-store-0 (a pod that never became Ready stays), refresh the
#       root Application, and wait until every Application of the good root is Synced and Healthy at its digest. It prints one JSON line.
#       The Mac administrator applies the bundles, and no new signature covers the act. A verified root whose signed version is lower than the
#       version that the state records for good[0] is refused, because repair would roll the cluster back to older signed content, unless
#       --allow-older is given.
#
# publish and repair take the cluster lock of each target, in sorted order, and hold it until the end. cell:up holds it and runs publish,
# so a nested call passes. BUNDLE_WAIT_SECONDS is one bound for every target.
#
# BUNDLE_WAIT_SECONDS (default 900) and BUNDLE_WAIT_POLL (default 10) set the bounds of --wait. BUNDLE_REPAIR_SECONDS (default 900)
# sets the bound of the repair wait.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
usage="usage: mise run bundle -- publish --target <cluster>... [--wait] | get --target <cluster> | cosign --target <cluster> | verify --target <cluster> | repair --target <cluster> [--allow-older]"

# A phase runs for one cluster, with the settings of that cluster. The script starts itself again for each target, with CELL set.
case "${1:-}" in
  _check | _publish | _wait | _cosign | _repair | _verify) source "$here/lib.sh" ;;
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

# check_build_fresh stops the publish when a hydrated bundle is older than an input of its render, because bundlectl packs build/<t>/bundles as it is,
# and a render change without a new hydrate would sign the old content. The rule is the one of ko_image for build/images.env: a file that is newer than the
# bundle. The inputs of the bundle of a component are the files and directories of components/<component> and components/lib (a deleted file changes its
# directory), vendor/, scripts/lib.sh, scripts/hydrate.sh, scripts/ko-image.sh, cells/common.env, cells/<t>.env, internal/bundle/allow.json,
# build/<t>/facts.env and build/images.env (IMAGES_ENV names another file). For dev-cp, the slow-tier marker build/gate/m9-svid-ttl and the stamp
# build/gate/m9-svid-ttl.restored that svid-ttl.sh restore leaves count too, because the render of dev-cp reads the marker, and a marker that goes
# leaves no file. Live facts that a render reads from a cluster are not files, so a change in them still needs cell:hydrate. A find that fails stops
# the publish.
check_build_fresh() {
  local entry c file i newer inputs slow=()
  [[ "$CELL_NAME" != dev-cp ]] || slow=("$SVID_TTL_MARKER" "$SVID_TTL_MARKER.restored")
  for entry in "${COMPONENTS[@]}"; do
    c="${entry%%:*}"
    file="$BUNDLES/$c/manifests.yaml"
    [[ -f "$file" ]] || die "no hydrated bundle $c for $CELL_NAME ($file). Run: CELL=$CELL_NAME mise run cell:hydrate"
    inputs=()
    for i in "$ROOT/components/$c" "$ROOT/components/lib" "$ROOT/vendor" "$ROOT/scripts/lib.sh" "$ROOT/scripts/hydrate.sh" "$ROOT/scripts/ko-image.sh" \
      "$ROOT/cells/common.env" "$ROOT/cells/$CELL_NAME.env" "$ROOT/internal/bundle/allow.json" "$BUILD/facts.env" "${IMAGES_ENV:-$ROOT/build/images.env}" \
      ${slow[@]+"${slow[@]}"}; do
      [[ ! -e "$i" ]] || inputs+=("$i")
    done
    newer="$(find "${inputs[@]}" -type f -newer "$file" -print -quit)" || die "could not check the inputs of the bundle $c against $file"
    # A directory that is newer lost or gained a file after the render.
    [[ -n "$newer" ]] || newer="$(find "${inputs[@]}" -type d -newer "$file" -print -quit)" || die "could not check the inputs of the bundle $c against $file"
    [[ -z "$newer" ]] || die "${newer#"$ROOT"/} is newer than the hydrated bundle $c ($file), so the bundle holds an old render. Run: CELL=$CELL_NAME mise run cell:hydrate"
  done
}

_check() {
  local role
  role="$(bundle_role)" || exit 1
  case "$role" in
    cell | cp) ;;
    *) die "$CELL_NAME has role $role, so it has no signed bundle sets. Publish its bundles with: CELL=$CELL_NAME mise run cell:publish" ;;
  esac
  # A publish checks the build of every target before the first lock and the first signature.
  [[ "${BUNDLE_CHECK_FRESH:-}" != 1 ]] || { [[ -d "$BUNDLES" ]] || die "no hydrated bundles for $CELL_NAME. Run: CELL=$CELL_NAME mise run cell:hydrate"; check_build_fresh; }
}

_publish() {
  local role mirror set signed root_digest file pushed
  _check
  role="$(bundle_role)"
  [[ -d "$BUNDLES" ]] || die "no hydrated bundles for $CELL_NAME. Run: CELL=$CELL_NAME mise run cell:hydrate"
  check_build_fresh
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

# verify_signed_root <root digest> <statement file> [version as JSON] [1 for strict] checks with cosign, offline, that mgmtd signed the root bundle of this target with its
# current key, and writes the in-toto statement of the signature to <statement file>. cosign gets an empty Docker configuration, and
# it skips the transparency log, which no set uses. A root that a key before a rotation signed needs: mise run bundle -- cosign --target <t>.
verify_signed_root() {
  local root="$1" out="$2" want="${3:-null}" strict="${4:-0}" keyline pem keydir dockerdir envelope reason all mine
  keyline="$(CELL=management mise run mgmt -- pubkey)" || die "could not read the public key of mgmtd: $keyline"
  pem="$(printf '%s' "$keyline" | mise run bundlectl -- pubkey-pem)" || die "could not convert the public key of mgmtd"
  keydir="$(mktemp -d)"
  dockerdir="$(mktemp -d)"
  printf '%s\n' "$pem" >"$keydir/mgmt.pub"
  # The standard error of cosign holds no secret. Its last line tells a key mismatch from a network error.
  envelope="$(DOCKER_CONFIG="$dockerdir" mise x -- cosign verify-attestation --key "$keydir/mgmt.pub" --insecure-ignore-tlog=true --allow-http-registry \
    --type https://cell.poc.internal/bundle-set/v1 "$MIRROR/bundles/$CELL_NAME/root@$root" 2>"$keydir/cosign.err")" \
    || { reason="$(tail -n 1 "$keydir/cosign.err")"; rm -rf "$keydir" "$dockerdir"; die "cosign does not verify the root $root of $CELL_NAME against the current key of mgmtd (${reason:-no message}), so it is not trusted. If the key rotated, run: mise run bundle -- cosign --target $CELL_NAME"; }
  rm -rf "$keydir" "$dockerdir"
  # cosign prints one statement for each signed version of the root, because the same content signs the same root again. Keep the statements that
  # name this root as their subject, and choose the one with the wanted version. Without one, a strict call fails, and any other call takes the
  # highest version.
  all="$(jq -sc 'map(.payload | @base64d | fromjson)' <<<"$envelope")" || die "the cosign answer for $root holds no statement"
  mine="$(jq -c --arg d "${root#sha256:}" --arg n "bundles/$CELL_NAME/root" 'map(select([.subject[]? | select(.name == $n and .digest.sha256 == $d)] | length == 1))' <<<"$all")"
  [[ "$(jq 'length' <<<"$mine")" -gt 0 ]] || die "the signed statement has no subject bundles/$CELL_NAME/root with the digest $root"
  if [[ "$(jq -c --argjson v "$want" '[.[] | select($v != null and .predicate.version == $v)] | length' <<<"$mine")" -gt 0 ]]; then
    jq -c --argjson v "$want" '[.[] | select(.predicate.version == $v)][0]' <<<"$mine" >"$out"
  elif [[ "$strict" == 1 ]]; then
    die "no signed statement for the root $root has the version $(jq -r 'if . == null then "none" else "\(.epoch)/\(.counter)" end' <<<"$want") that the state records. The root is not the set of that version"
  else
    jq -c 'sort_by([(.predicate.version.epoch // -1), (.predicate.version.counter // -1)]) | last' <<<"$mine" >"$out"
  fi
}

_verify() {
  local state root want
  _check
  state="$(bundle_state_json)" || exit 1
  [[ -n "$state" ]] || die "$CELL_NAME has no bundle state, so it has no root to verify"
  [[ "$(jq -r '.source // ""' <<<"$state")" == signed ]] || die "the bundle state of $CELL_NAME has source '$(jq -r '.source // ""' <<<"$state")', so its root is a bootstrap root that nobody signed"
  root="$(jq -r '.root.digest // ""' <<<"$state")"
  [[ "$root" =~ ^sha256:[0-9a-f]{64}$ ]] || die "the bundle state of $CELL_NAME holds no root digest"
  MIRROR="$(mirror_host)" || exit 1
  work="$(mktemp -d)"
  trap 'rm -rf "$work"' EXIT
  # A rollback keeps the version of the failed set in state.version and moves state.root back to the good root, which carries the version of its own
  # good entry. So the wanted version is the one of the good entry for this root, and state.version only when no entry names it.
  want="$(jq -c --arg r "$root" '([.good[]? | select(.root.digest == $r) | .version] | map(select(. != null)) | .[0]) // .version // null' <<<"$state")"
  verify_signed_root "$root" "$work/statement.json" "$want" 1
  jq -c --arg target "$CELL_NAME" --arg root "$root" '{target: $target, root: $root, version: .predicate.version,
    subjects: [.subject[] | {name, digest: ("sha256:" + .digest.sha256)}]}' "$work/statement.json"
}

# check_not_older <good[0] as JSON> <statement file> refuses a verified root whose signed version is lower than the version that the state records
# for good[0], unless BUNDLE_ALLOW_OLDER=1. The signature proves that mgmtd signed the root once, and not that it is the newest good one.
check_not_older() {
  local recorded signed older
  recorded="$(jq -c '.version // empty' <<<"$1")"
  [[ -n "$recorded" ]] || return 0
  signed="$(jq -c '.predicate.version // empty' "$2")"
  [[ -n "$signed" ]] || die "the signed statement of $CELL_NAME holds no version"
  older="$(jq -n --argjson s "$signed" --argjson r "$recorded" '($s.epoch < $r.epoch) or ($s.epoch == $r.epoch and $s.counter < $r.counter)')"
  [[ "$older" == true ]] || return 0
  if [[ "${BUNDLE_ALLOW_OLDER:-}" == 1 ]]; then
    log "the verified root is signed at version $(jq -r '"\(.epoch)/\(.counter)"' <<<"$signed"), older than the version $(jq -r '"\(.epoch)/\(.counter)"' <<<"$recorded") that the state records, and --allow-older goes on"
    return 0
  fi
  die "the verified root is signed at version $(jq -r '"\(.epoch)/\(.counter)"' <<<"$signed"), which is older than the version $(jq -r '"\(.epoch)/\(.counter)"' <<<"$recorded") that the state records for good[0]. Repair would roll $CELL_NAME back to older signed content. If that is intended, run it again with --allow-older"
}

# police_bundle <component> <directory> runs conftest with bundle.rego, allow.json, the role and the component, the harness plane policies of the role and the
# scope of the custom kinds that the bundle defines (as the engine learns it), over manifests.yaml of the pulled bundle. A denial stops the repair
# with each message printed. Nothing has changed in the cluster at this point.
police_bundle() {
  local comp="$1" dir="$2" allow data file out rc=0
  allow="${BUNDLE_ALLOW_JSON:-$ROOT/internal/bundle/allow.json}"
  data="$work/policy-$comp"
  file="$work/$comp.manifests.yaml"
  mkdir -p "$data/allow" "$data/context" "$data/harness" "$data/scope"
  tar -xzOf "$dir/layer.tgz" manifests.yaml >"$file" || die "the bundle $comp of the good root holds no manifests.yaml"
  cp "$allow" "$data/allow/data.json"
  jq -nc --arg role "$role" --arg c "$comp" '{role: $role, component: $c}' >"$data/context/data.json"
  jq -c --arg role "$role" '{networkPolicies: [.roles[$role].planePolicies[]? | {namespace, name}]}' "$allow" >"$data/harness/data.json" \
    || die "could not read the plane policies of role $role from $allow"
  yq -N -r 'select(.kind == "CustomResourceDefinition") | .spec.group + "/" + .spec.names.kind + " " + .spec.scope' "$file" \
    | jq -Rsc '[split("\n")[] | select(length > 0) | split(" ")] | {cluster: [.[] | select(.[1] == "Cluster") | .[0]], namespaced: [.[] | select(.[1] == "Namespaced") | .[0]]}' >"$data/scope/data.json" \
    || die "could not read the custom kinds of the bundle $comp"
  out="$(mise x -- conftest test --policy "$ROOT/internal/bundleapply/policy" --namespace bundle.allow --data "$data" --output json --no-color "$file" 2>"$work/conftest.err")" || rc=$?
  if ((rc != 0 && rc != 1)) || ! jq -e 'type == "array"' >/dev/null 2>&1 <<<"$out"; then
    die "conftest failed for the bundle $comp of the good root (exit $rc): $(tail -n 1 "$work/conftest.err")"
  fi
  if jq -e 'any(.[]; (.failures // []) | length > 0)' >/dev/null <<<"$out"; then
    die "the bundle policy refuses the bundle $comp of the good root of $CELL_NAME, so repair does not apply it: $(jq -r '[.[].failures[]?.msg] | join("; ")' <<<"$out"). The signature proves that mgmtd signed the root, not that the engine accepted it"
  fi
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
    verify_signed_root "$root_digest" "$stmt" "$(jq -c '.version // null' <<<"$good")" 0
    check_not_older "$good" "$stmt"
  fi
  pull_bundle "$host" "$root_repo" "$root_digest" "$work/root"
  for component in argocd cell-system; do
    rev="$(tar -xzOf "$work/root/layer.tgz" "$component.yaml" | yq -r '.spec.source.targetRevision // ""')" || die "the root $root_digest holds no Application $component"
    [[ "$rev" =~ ^sha256:[0-9a-f]{64}$ ]] || die "the Application $component in the root $root_digest pins '$rev', which is no digest"
    if [[ "$origin" == signed ]]; then
      [[ "$(jq -r --arg n "bundles/$CELL_NAME/$component" '[.subject[]? | select(.name == $n) | .digest.sha256][0] // ""' "$stmt")" == "${rev#sha256:}" ]] \
        || die "the signed statement names another digest for $component than the root layer ($rev)"
    fi
    pull_bundle "$host" "$comp_repo/$component" "$rev" "$work/$component"
  done
  # A signature proves that mgmtd signed this root for this target. It does not prove that an engine ever accepted it: mgmtd signs every set of the
  # right shape, and the cosign bundle reaches the mirror before any engine reads the set. The repair applies the two bundles as the administrator, so
  # the bundle policy (the bundle.rego and the allow.json that the engine runs) must pass them first.
  for component in argocd cell-system; do
    police_bundle "$component" "$work/$component"
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
      || die "could not pin the Application $component at $rev, so Argo CD could serve the bad set from its cache again. Nothing was applied"
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
  k -n argocd annotate application root argocd.argoproj.io/refresh=hard --overwrite >/dev/null || die "could not ask Argo CD for a refresh of the Application root"

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
targets=() wait=0 allow_older=0
while (($#)); do
  case "$1" in
    --target)
      [[ -n "${2:-}" ]] || fail "--target needs a cluster name. $usage"
      targets+=("$2")
      shift 2 ;;
    --allow-older)
      [[ "$cmd" == repair ]] || fail "--allow-older belongs to repair. $usage"
      allow_older=1
      shift ;;
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
  get | cosign | repair | verify) ((${#targets[@]} == 1)) || fail "$cmd takes one --target. $usage" ;;
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
for t in "${targets[@]}"; do BUNDLE_CHECK_FRESH="$([[ "$cmd" == publish ]] && echo 1 || echo 0)" run_for "$t" _check || exit 1; done
if [[ "$cmd" == publish || "$cmd" == repair ]]; then
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
  repair) BUNDLE_ALLOW_OLDER="$allow_older" run_for "${targets[0]}" _repair ;;
  verify) run_for "${targets[0]}" _verify ;;
esac
