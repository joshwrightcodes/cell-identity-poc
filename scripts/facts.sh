#!/usr/bin/env bash
# Record the cluster facts that the network policies need, in build/facts.env.
source "$(dirname "$0")/lib.sh"

mkdir -p "$BUILD"
cluster_config="$(k -n kube-system get configmap kubeadm-config -o jsonpath='{.data.ClusterConfiguration}')"
pod_cidr="$(yq '.networking.podSubnet' <<<"$cluster_config")"
service_cidr="$(yq '.networking.serviceSubnet' <<<"$cluster_config")"
node_ips="$(k get nodes -o jsonpath='{range .items[*]}{.status.addresses[?(@.type=="InternalIP")].address}{" "}{end}')"
api_ips="$(k get endpointslices -n default -l kubernetes.io/service-name=kubernetes \
  -o jsonpath='{range .items[*].endpoints[*]}{.addresses[0]}{" "}{end}')"
api_port="$(k get endpointslices -n default -l kubernetes.io/service-name=kubernetes \
  -o jsonpath='{.items[0].ports[0].port}')"
api_service_ip="$(k -n default get service kubernetes -o jsonpath='{.spec.clusterIP}')"
dns_service_ip="$(k -n kube-system get service kube-dns -o jsonpath='{.spec.clusterIP}')"

[[ -n "$pod_cidr" && -n "$service_cidr" && -n "$node_ips" && -n "$api_ips" && -n "$dns_service_ip" ]] || die "could not read the cluster facts"

# A render and the publish check read the time of facts.env, so the file keeps its time when the facts are the same.
tmp="$(mktemp "$BUILD/.facts.env.XXXXXX")"
trap 'rm -f "$tmp"' EXIT
cat >"$tmp" <<EOF
POD_CIDR='$pod_cidr'
SERVICE_CIDR='$service_cidr'
NODE_IPS='${node_ips% }'
API_SERVER_IPS='${api_ips% }'
API_SERVER_PORT='$api_port'
API_SERVICE_IP='$api_service_ip'
DNS_SERVICE_IP='$dns_service_ip'
EOF
if [[ -f "$FACTS" ]] && cmp -s "$tmp" "$FACTS"; then
  log "$FACTS is unchanged"
else
  mv "$tmp" "$FACTS"
  log "wrote $FACTS"
fi
trap - EXIT
rm -f "$tmp"
cat "$FACTS" >&2
