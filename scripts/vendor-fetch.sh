#!/usr/bin/env bash
# Download the pinned Argo CD manifest and Istio charts into vendor/.
# Review the git diff before you commit or apply the new files. vendor/README.md lists the checks.
source "$(dirname "$0")/lib.sh"

argocd_dir="$ROOT/vendor/argocd/$ARGOCD_VERSION"
istio_dir="$ROOT/vendor/charts/istio-$ISTIO_VERSION"
mkdir -p "$argocd_dir" "$istio_dir"

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

shasum -a 256 "$argocd_dir/core-install.yaml"
log "fetched. Review the diff, then update vendor/README.md."
