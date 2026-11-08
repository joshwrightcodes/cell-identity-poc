#!/usr/bin/env bash
# Download the pinned Argo CD manifest, Istio charts and External Secrets Operator chart into vendor/.
# Review the git diff before you commit or apply the new files. vendor/README.md lists the checks.
source "$(dirname "$0")/lib.sh"

argocd_dir="$ROOT/vendor/argocd/$ARGOCD_VERSION"
istio_dir="$ROOT/vendor/charts/istio-$ISTIO_VERSION"
eso_dir="$ROOT/vendor/charts/external-secrets-$EXTERNAL_SECRETS_VERSION"
mkdir -p "$argocd_dir" "$istio_dir" "$eso_dir"

curl -fsSL -o "$argocd_dir/core-install.yaml" \
  "https://raw.githubusercontent.com/argoproj/argo-cd/$ARGOCD_VERSION/manifests/core-install.yaml"
cat >"$argocd_dir/kustomization.yaml" <<'EOF'
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
  - core-install.yaml
EOF

for chart in base cni istiod gateway; do
  rm -rf "${istio_dir:?}/$chart"
  helm pull "oci://gcr.io/istio-release/charts/$chart" --version "$ISTIO_VERSION" --untar --untardir "$istio_dir"
done

# The chart archive must match the reviewed SHA-256 before it is unpacked.
eso_tmp="$(mktemp -d)"
trap 'rm -rf "$eso_tmp"' EXIT
helm pull oci://ghcr.io/external-secrets/charts/external-secrets --version "$EXTERNAL_SECRETS_VERSION" --destination "$eso_tmp"
eso_archive="$eso_tmp/external-secrets-$EXTERNAL_SECRETS_VERSION.tgz"
printf '%s  %s\n' "$EXTERNAL_SECRETS_CHART_SHA256" "$eso_archive" | shasum -a 256 -c - >/dev/null \
  || die "external-secrets chart $EXTERNAL_SECRETS_VERSION does not match EXTERNAL_SECRETS_CHART_SHA256 in cells/common.env"
rm -rf "${eso_dir:?}/external-secrets"
tar -xzf "$eso_archive" -C "$eso_dir"

shasum -a 256 "$argocd_dir/core-install.yaml"
log "fetched. Review the diff, then update vendor/README.md."
