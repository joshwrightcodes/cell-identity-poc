#!/usr/bin/env bash
# Render the telemetry store of management, a bundle at wave 8.
#
# The bundle holds StatefulSet lgtm (grafana/otel-lgtm, lgtm.yaml), its Service and NetworkPolicy,
# ConfigMap lgtm-config with the Prometheus and Loki overrides (prometheus.yaml and loki.yaml), and
# the Password generator and ExternalSecret of the Grafana admin password (grafana-password.yaml),
# and the read-only Prometheus proxy prom-readonly with its policies (prom-readonly.yaml). The proxy
# policy admits the kubelet from the node addresses of build/<cluster>/facts.env (NODE_IPS).
# The pod template carries the SHA-256 of the config files and the Grafana files, so a change restarts the pod.
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

# Grafana reads the dashboards, the alert rules and the provider file from ConfigMaps. Each dashboard has its own ConfigMap
# lgtm-dashboard-<file name>, and lgtm-grafana holds provider.yaml and rules.json. The files of a ConfigMap stay below 256 KiB together, as a
# margin, because Kubernetes limits an object to 1 MiB and the applications sync with server-side apply.
grafana="$here/grafana"
max_configmap=262144
dashboards=()
for f in "$grafana"/dashboards/*.json; do
  [[ -f "$f" ]] || { echo "error: observability-store render: no dashboard in $grafana/dashboards" >&2; exit 1; }
  dashboards+=("$f")
done
# check_size <file>... fails when the files of one ConfigMap add up to more than the limit.
check_size() {
  local total
  total="$(cat "$@" | wc -c | tr -d ' ')"
  ((total <= max_configmap)) || { echo "error: observability-store render: $* has $total bytes, the limit is $max_configmap" >&2; exit 1; }
}
for f in "${dashboards[@]}"; do check_size "$f"; done
check_size "$grafana/provider.yaml" "$grafana/alerting/rules.json"

sum="$(cat "$here/prometheus.yaml" "$here/loki.yaml" "${dashboards[@]}" "$grafana/provider.yaml" "$grafana/alerting/rules.json" | sha256)"
sed "s|@LGTM_CONFIG_SHA256@|$sum|" "$here/lgtm.yaml" | DASHBOARDS="$(for f in "${dashboards[@]}"; do basename "$f" .json; done | jq -Rcn '[inputs]')" yq '
  (select(.kind == "StatefulSet") | .spec.template.spec.volumes) += [{"name": "grafana-dashboards", "projected": {"sources": (env(DASHBOARDS) | ... style="" | map({"configMap": {"name": "lgtm-dashboard-" + .}}))}}]'
echo "---"
PROM="$(cat "$here/prometheus.yaml")" LOKI="$(cat "$here/loki.yaml")" yq -n '
  .apiVersion = "v1" | .kind = "ConfigMap" | .metadata.name = "lgtm-config" | .metadata.namespace = "observability-system"
  | .data["prometheus.yaml"] = strenv(PROM) | .data["loki.yaml"] = strenv(LOKI)
  | .data["prometheus.yaml"] style="literal" | .data["loki.yaml"] style="literal"'
echo "---"
PROVIDER="$grafana/provider.yaml" RULES="$grafana/alerting/rules.json" yq -n '
  .apiVersion = "v1" | .kind = "ConfigMap" | .metadata.name = "lgtm-grafana" | .metadata.namespace = "observability-system"
  | .data["provider.yaml"] = load_str(strenv(PROVIDER)) | .data["rules.json"] = load_str(strenv(RULES))
  | .data["provider.yaml"] style="literal" | .data["rules.json"] style="literal"'
echo "---"
for f in "${dashboards[@]}"; do
  name="$(basename "$f" .json)"
  NAME="lgtm-dashboard-$name" KEY="$name.json" BODY="$f" yq -n '
    .apiVersion = "v1" | .kind = "ConfigMap" | .metadata.name = strenv(NAME) | .metadata.namespace = "observability-system"
    | .data[strenv(KEY)] = load_str(strenv(BODY)) | .data[strenv(KEY)] style="literal"'
  echo "---"
done
echo "---"
cat "$here/grafana-password.yaml"
echo
echo "---"
sed "s|@CELL_PROXY_IMAGE@|$cell_proxy_image|" "$here/prom-readonly.yaml" \
  | PEERS="$node_peers" yq '(.. | select(. == "@NODE_PEERS@")) |= (env(PEERS) | ... style="")'
