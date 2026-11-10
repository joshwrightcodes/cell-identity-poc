#!/usr/bin/env bash
# Render the observability-system bundle of one cluster, at wave 3: the collector, and the
# NetworkPolicies of the namespace. Namespace observability-system comes from the namespaces bundle.
#
# Every cluster gets the collector of collector.yaml, which prints what it receives. In a cluster
# with COLLECTOR_STORE set (management), the collector instead:
#   - sets k8s.cluster.name and platform.plane from COLLECTOR_CLUSTER and COLLECTOR_PLANE on every
#     resource, and replaces a value that a sender set,
#   - exports every signal as OTLP to COLLECTOR_STORE (host:port of the telemetry store), and
#   - may reach the pods of the store on that port only (flow N10).
# This needs the processor "resource", which the core collector image lacks, so the collector runs
# the Kubernetes distribution.
#
# The policies of the namespace are the default deny, DNS for every pod except lgtm (the store has
# no egress), the node addresses for probes (every pod except lgtm), and flow N11 in: any pod of
# the cluster sends OTLP to the collector on 4317 and 4318.
# Inputs: DNS_SERVICE_IP and NODE_IPS from build/<cluster>/facts.env; COLLECTOR_STORE,
# COLLECTOR_CLUSTER and COLLECTOR_PLANE from cells/<cluster>.env.
set -euo pipefail
: "${NODE_IPS:?}" "${DNS_SERVICE_IP:?}"

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
namespace=observability-system
K8S_COLLECTOR_IMAGE=docker.io/otel/opentelemetry-collector-k8s:0.164.0@sha256:8f7e5aaac0302f090164d5f9c14e4437d8037c5aaa2d025fc3ad74c1922602eb

die() { printf 'error: observability-system render: %s\n' "$*" >&2; exit 1; }

source "$root/scripts/ko-image.sh"
source "$root/components/lib/addresses.sh"
node_ips="$(ipv4_list NODE_IPS)" || exit 1
[[ "$DNS_SERVICE_IP" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || die "DNS_SERVICE_IP '$DNS_SERVICE_IP' is not an IPv4 address"

store="${COLLECTOR_STORE:-}"
if [[ -n "$store" ]]; then
  [[ "$store" =~ ^[a-z0-9.-]+:[1-9][0-9]{0,4}$ ]] || die "COLLECTOR_STORE '$store' is not host:port"
  [[ "${COLLECTOR_CLUSTER:-}" =~ ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$ ]] || die "COLLECTOR_CLUSTER '${COLLECTOR_CLUSTER:-}' is not a cluster name"
  [[ "${COLLECTOR_PLANE:-}" =~ ^[a-z]+$ ]] || die "COLLECTOR_PLANE '${COLLECTOR_PLANE:-}' is not a plane name"
  store_port="${store##*:}"
  ((store_port <= 65535)) || die "COLLECTOR_STORE '$store' has a port above 65535"
fi

collector="$(yq 'select(.kind != null) | .metadata.namespace = "observability-system"' "$here/collector.yaml")"
if [[ -n "$store" ]]; then
  config="$(cat <<YAML
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317
      http:
        endpoint: 0.0.0.0:4318
processors:
  resource:
    attributes:
      - key: k8s.cluster.name
        value: $COLLECTOR_CLUSTER
        action: upsert
      - key: platform.plane
        value: $COLLECTOR_PLANE
        action: upsert
  batch: {}
exporters:
  otlp:
    endpoint: $store
    tls:
      insecure: true
service:
  telemetry:
    metrics:
      level: none
  pipelines:
    traces:
      receivers: [otlp]
      processors: [resource, batch]
      exporters: [otlp]
    logs:
      receivers: [otlp]
      processors: [resource, batch]
      exporters: [otlp]
    metrics:
      receivers: [otlp]
      processors: [resource, batch]
      exporters: [otlp]
YAML
)"
  # The checksum restarts the pod when the config changes, because the collector reads it at start.
  collector="$(CONFIG="$config" IMAGE="$K8S_COLLECTOR_IMAGE" SUM="$(printf '%s' "$config" | sha256)" yq '
    (select(.kind == "ConfigMap" and .metadata.name == "otel-collector") | .data["config.yaml"]) = strenv(CONFIG)
    | (select(.kind == "ConfigMap" and .metadata.name == "otel-collector") | .data["config.yaml"]) style="literal"
    | (select(.kind == "Deployment") | .spec.template.spec.containers[0].image) = strenv(IMAGE)
    | (select(.kind == "Deployment") | .spec.template.metadata.annotations["poc.internal/collector-config-sha256"]) = strenv(SUM)' <<<"$collector")"
fi
echo "$collector"

node_peers() {
  local ip
  for ip in $node_ips; do
    printf '        - ipBlock:\n            cidr: %s/32\n' "$ip"
  done
}

cat <<EOF
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny
  namespace: $namespace
spec:
  podSelector: {}
  policyTypes: [Ingress, Egress]
---
# Flow N24. The store has no egress, so it resolves no name.
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-dns
  namespace: $namespace
spec:
  podSelector:
    matchExpressions:
      - key: app.kubernetes.io/name
        operator: NotIn
        values: [lgtm]
  policyTypes: [Egress]
  egress:
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: kube-system
          podSelector:
            matchLabels:
              k8s-app: kube-dns
        - ipBlock:
            cidr: $DNS_SERVICE_IP/32
      ports:
        - protocol: UDP
          port: 53
        - protocol: TCP
          port: 53
---
# Flow N23: the kubelet probes each pod from a node address. The store probes itself inside the
# pod, so it admits no node address.
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-from-nodes
  namespace: $namespace
spec:
  podSelector:
    matchExpressions:
      - key: app.kubernetes.io/name
        operator: NotIn
        values: [lgtm]
  policyTypes: [Ingress]
  ingress:
    - from:
$(node_peers)
---
# Flow N11 in: every pod of the cluster sends OTLP to the collector.
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: collector
  namespace: $namespace
spec:
  podSelector:
    matchLabels:
      app.kubernetes.io/name: otel-collector
  policyTypes: [Ingress]
  ingress:
    - from:
        - namespaceSelector: {}
      ports:
        - protocol: TCP
          port: 4317
        - protocol: TCP
          port: 4318
EOF
if [[ -n "$store" ]]; then
  cat <<EOF
---
# Flow N10: the collector exports to the telemetry store.
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: collector-egress
  namespace: $namespace
spec:
  podSelector:
    matchLabels:
      app.kubernetes.io/name: otel-collector
  policyTypes: [Egress]
  egress:
    - to:
        - podSelector:
            matchLabels:
              app.kubernetes.io/name: lgtm
      ports:
        - protocol: TCP
          port: $store_port
EOF
fi
