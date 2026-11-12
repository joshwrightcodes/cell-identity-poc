#!/usr/bin/env bash
# Download the pinned Argo CD manifests, the Argo CD Agent manifests, the Istio charts, the External
# Secrets Operator chart and the Kiali server chart into vendor/. Review the git diff before you
# commit or apply the new files. vendor/README.md lists the checks.
source "$(dirname "$0")/lib.sh"

argocd_dir="$ROOT/vendor/argocd/$ARGOCD_VERSION"
istio_dir="$ROOT/vendor/charts/istio-$ISTIO_VERSION"
eso_dir="$ROOT/vendor/charts/external-secrets-$EXTERNAL_SECRETS_VERSION"
kiali_dir="$ROOT/vendor/charts/kiali-server-${KIALI_VERSION#v}"
agent_dir="$ROOT/vendor/argocd-agent/$ARGOCD_AGENT_VERSION"
mkdir -p "$argocd_dir" "$istio_dir" "$eso_dir" "$kiali_dir"

curl -fsSL -o "$argocd_dir/core-install.yaml" \
  "https://raw.githubusercontent.com/argoproj/argo-cd/$ARGOCD_VERSION/manifests/core-install.yaml"
cat >"$argocd_dir/kustomization.yaml" <<'EOF'
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
  - core-install.yaml
EOF
# The full install feeds only the central view in management. components/central-view names it
# directly, so the kustomization above keeps the core install alone.
curl -fsSL -o "$argocd_dir/install.yaml" \
  "https://raw.githubusercontent.com/argoproj/argo-cd/$ARGOCD_VERSION/manifests/install.yaml"

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

# The Kiali chart archive must match the reviewed SHA-256 before it is unpacked.
kiali_tmp="$(mktemp -d)"
trap 'rm -rf "$eso_tmp" "$kiali_tmp"' EXIT
helm pull kiali-server --repo https://kiali.org/helm-charts --version "${KIALI_VERSION#v}" --destination "$kiali_tmp"
kiali_archive="$kiali_tmp/kiali-server-${KIALI_VERSION#v}.tgz"
printf '%s  %s\n' "$KIALI_CHART_SHA256" "$kiali_archive" | shasum -a 256 -c - >/dev/null \
  || die "kiali-server chart $KIALI_VERSION does not match KIALI_CHART_SHA256 in cells/common.env"
rm -rf "${kiali_dir:?}/kiali-server"
tar -xzf "$kiali_archive" -C "$kiali_dir"

# The principal and agent manifests of the Argo CD Agent come from the archive of the tag. The
# SHA-256 of the reviewed file list must match before they replace the vendored copy.
agent_tmp="$(mktemp -d)"
trap 'rm -rf "$eso_tmp" "$kiali_tmp" "$agent_tmp"' EXIT
curl -fsSL -o "$agent_tmp/agent.tgz" \
  "https://codeload.github.com/argoproj-labs/argocd-agent/tar.gz/refs/tags/$ARGOCD_AGENT_VERSION"
tar -xzf "$agent_tmp/agent.tgz" -C "$agent_tmp"
agent_src="$agent_tmp/argocd-agent-${ARGOCD_AGENT_VERSION#v}/install/kubernetes"
[[ -d "$agent_src/principal" && -d "$agent_src/agent" ]] \
  || die "the archive of argocd-agent $ARGOCD_AGENT_VERSION has no install/kubernetes/principal and agent"
agent_sum="$(cd "$agent_src" && find principal agent -type f | LC_ALL=C sort \
  | while read -r f; do shasum -a 256 "$f"; done | shasum -a 256 | cut -d' ' -f1)"
[[ "$agent_sum" == "$ARGOCD_AGENT_MANIFESTS_SHA256" ]] \
  || die "the argocd-agent $ARGOCD_AGENT_VERSION manifests have SHA-256 $agent_sum, and ARGOCD_AGENT_MANIFESTS_SHA256 in cells/common.env is $ARGOCD_AGENT_MANIFESTS_SHA256"
rm -rf "${agent_dir:?}"
mkdir -p "$agent_dir"
cp -R "$agent_src/principal" "$agent_src/agent" "$agent_dir/"

shasum -a 256 "$argocd_dir/core-install.yaml" "$argocd_dir/install.yaml"
log "fetched. Review the diff, then update vendor/README.md."
