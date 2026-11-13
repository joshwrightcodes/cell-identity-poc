#!/usr/bin/env bash
# Render the telemetry store of management, a bundle at wave 8.
#
# The bundle holds StatefulSet lgtm (grafana/otel-lgtm, lgtm.yaml), its Service and NetworkPolicy,
# ConfigMap lgtm-config with the Prometheus and Loki overrides (prometheus.yaml and loki.yaml), and
# the Password generator and ExternalSecret of the Grafana admin password (grafana-password.yaml),
# and the read-only Prometheus proxy prom-readonly with its policies (prom-readonly.yaml). The proxy
# policy admits the kubelet from the node addresses of build/<cluster>/facts.env (NODE_IPS).
# The pod template carries the SHA-256 of the two config files, so a new config restarts the pod.
# Namespace observability-system comes from the namespaces bundle, and the operator of the
# external-secrets bundle serves the generator.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
source "$root/scripts/ko-image.sh"
source "$root/components/lib/addresses.sh"
: "${NODE_IPS:?}"
node_peers="$(ipv4_list NODE_IPS | jq -Rcn '[inputs | {ipBlock: {cidr: (. + "/32")}}]')" || exit 1
cell_proxy_image="$(ko_image cell-proxy)" || { echo "error: observability-store render: no cell-proxy image" >&2; exit 1; }

sum="$(cat "$here/prometheus.yaml" "$here/loki.yaml" | sha256)"
sed "s|@LGTM_CONFIG_SHA256@|$sum|" "$here/lgtm.yaml"
echo "---"
PROM="$(cat "$here/prometheus.yaml")" LOKI="$(cat "$here/loki.yaml")" yq -n '
  .apiVersion = "v1" | .kind = "ConfigMap" | .metadata.name = "lgtm-config" | .metadata.namespace = "observability-system"
  | .data["prometheus.yaml"] = strenv(PROM) | .data["loki.yaml"] = strenv(LOKI)
  | .data["prometheus.yaml"] style="literal" | .data["loki.yaml"] style="literal"'
echo "---"
cat "$here/grafana-password.yaml"
echo
echo "---"
sed "s|@CELL_PROXY_IMAGE@|$cell_proxy_image|" "$here/prom-readonly.yaml" \
  | PEERS="$node_peers" yq '(.. | select(. == "@NODE_PEERS@")) |= (env(PEERS) | ... style="")'
