#!/usr/bin/env bash
# Render the telemetry store of management, a bundle at wave 8.
#
# The bundle holds StatefulSet lgtm (grafana/otel-lgtm, lgtm.yaml), its Service and NetworkPolicy,
# ConfigMap lgtm-config with the Prometheus and Loki overrides (prometheus.yaml and loki.yaml), and
# the Password generator and ExternalSecret of the Grafana admin password (grafana-password.yaml).
# The pod template carries the SHA-256 of the two config files, so a new config restarts the pod.
# Namespace observability-system comes from the namespaces bundle, and the operator of the
# external-secrets bundle serves the generator.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
source "$root/scripts/ko-image.sh"

sum="$(cat "$here/prometheus.yaml" "$here/loki.yaml" | sha256)"
sed "s|@LGTM_CONFIG_SHA256@|$sum|" "$here/lgtm.yaml"
echo "---"
PROM="$(cat "$here/prometheus.yaml")" LOKI="$(cat "$here/loki.yaml")" yq -n '
  .apiVersion = "v1" | .kind = "ConfigMap" | .metadata.name = "lgtm-config" | .metadata.namespace = "observability-system"
  | .data["prometheus.yaml"] = strenv(PROM) | .data["loki.yaml"] = strenv(LOKI)
  | .data["prometheus.yaml"] style="literal" | .data["loki.yaml"] style="literal"'
echo "---"
cat "$here/grafana-password.yaml"
