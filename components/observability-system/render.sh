#!/usr/bin/env bash
# Render the observability-system bundle of one cluster, at wave 3: the collector, and the
# NetworkPolicies of the namespace. Namespace observability-system comes from the namespaces bundle.
#
# Every cluster runs the collector of collector.yaml as a StatefulSet on the Kubernetes distribution
# image, with a persistent queue on its own volume. The config has these parts:
#   - receivers: OTLP on 4317 (gRPC) and 4318 (HTTP, for the bundle store only), the prometheus
#     receiver with the jobs of this cluster, and k8s_objects for the Kubernetes events.
#   - processors: memory_limiter, the transform processors that strip every form of the source
#     attributes at every level that the processor reaches, and the resource processor that sets the
#     values of this cluster. A form is the key with any of . _ - as separator, in any case, with
#     separators at the ends. Span links and exemplars are not reachable.
#     transform/otlp also strips source_cluster and destination_cluster. transform/scrape keeps them,
#     because Envoy sets them from the cluster name of Istio, and the gateway checks them again.
#   - one exporter, otlp_grpc, with the limits that the gateway needs: a timeout of 15 s, no end to
#     the retries, client keepalive, 4 consumers, and requests of at most 3,000,000 bytes.
#     COLLECTOR_STORE (management) names the store, and every other cluster exports to its uplink.
#   - the own metrics of the collector go as OTLP to its own port 4317.
# Source attributes by plane (COLLECTOR_PLANE):
#   management   k8s.cluster.name, platform.plane
#   environment  k8s.cluster.name, platform.plane, deployment.environment.name (POC_ENV)
#   cell         k8s.cluster.name, platform.plane, deployment.environment.name, platform.cell
#
# The policies of the namespace are the default deny, DNS for every pod except lgtm (the store has
# no egress), the node addresses for probes (every pod except lgtm, the gateway, the collector and
# the uplink, which each have their own probe rule), flow N11 in (COLLECTOR_SENDERS, the gateway or
# the uplink, and the bundle store on 4318), and flows N10, N15, N16 and N19 out.
# Inputs: DNS_SERVICE_IP, NODE_IPS, API_SERVER_IPS, API_SERVER_PORT and API_SERVICE_IP from
# build/<cluster>/facts.env; CELL_NAME, COLLECTOR_PLANE, COLLECTOR_SENDERS, COLLECTOR_JOBS,
# COLLECTOR_STORE and COLLECTOR_CLUSTER from cells/<cluster>.env; POC_ENV from cells/common.env.
set -euo pipefail
: "${NODE_IPS:?}" "${DNS_SERVICE_IP:?}" "${API_SERVER_IPS:?}" "${API_SERVER_PORT:?}" "${API_SERVICE_IP:?}"

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
namespace=observability-system
K8S_COLLECTOR_IMAGE=docker.io/otel/opentelemetry-collector-k8s:0.164.0@sha256:8f7e5aaac0302f090164d5f9c14e4437d8037c5aaa2d025fc3ad74c1922602eb
# The uplink listens here. Only the collector may reach the port.
UPLINK_ENDPOINT=otel-uplink.observability-system.svc.cluster.local:4319
# The gateway refuses 3,670,016 bytes after its attribute reset, which can add 400 bytes for each
# resource, so a request stays below EXPORT_BYTES_CAP. The gateway also refuses a request of more than
# 1,024 resources, with ResourceExhausted and no RetryInfo, and the OTLP exporter then drops the whole
# batch as a permanent error. The batcher appends the resources of merged requests and bounds bytes
# only. So the byte bound is also the resource bound: every resource carries at least the attributes
# that the resource processor sets, and a batch of at most RESOURCE_BUDGET times that size holds at most
# RESOURCE_BUDGET resources. A record larger than the bound is dropped by the batcher, with a log line.
EXPORT_BYTES_CAP=3000000
RESOURCE_BUDGET=1000
RECEIVE_MAX_MIB=3
# The exporter has one queue for each signal, and the three queues share the volume of 2 GiB. Each
# holds at most 384 MiB, so together they stay below 1.5 GiB. The rest is room for the file storage
# to grow between two compactions.
QUEUE_MAX_BYTES=402653184

die() { printf 'error: observability-system render: %s\n' "$*" >&2; exit 1; }

source "$root/scripts/ko-image.sh"
source "$root/components/lib/addresses.sh"
node_ips="$(ipv4_list NODE_IPS)" || exit 1
api_ips="$(ipv4_list API_SERVER_IPS)" || exit 1
[[ "$DNS_SERVICE_IP" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || die "DNS_SERVICE_IP '$DNS_SERVICE_IP' is not an IPv4 address"
[[ "$API_SERVICE_IP" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || die "API_SERVICE_IP '$API_SERVICE_IP' is not an IPv4 address"
[[ "$API_SERVER_PORT" =~ ^[0-9]+$ ]] || die "API_SERVER_PORT '$API_SERVER_PORT' is not a port number"

cluster="${COLLECTOR_CLUSTER:-${CELL_NAME:-}}"
[[ "$cluster" =~ ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$ ]] || die "the cluster name '$cluster' is not a cluster name. Set CELL_NAME or COLLECTOR_CLUSTER"
plane="${COLLECTOR_PLANE:-}"
case "$plane" in
  management | environment | cell) ;;
  *) die "COLLECTOR_PLANE '$plane' is not management, environment or cell" ;;
esac
if [[ "$plane" != management ]]; then
  [[ "${POC_ENV:-}" =~ ^[a-z0-9][a-z0-9-]{0,30}$ ]] || die "POC_ENV '${POC_ENV:-}' is not a short DNS label"
fi
read -r -a senders <<<"${COLLECTOR_SENDERS:-}"
((${#senders[@]} > 0)) || die "COLLECTOR_SENDERS names no namespace, so no pod could send OTLP"
for s in "${senders[@]}"; do
  [[ "$s" =~ ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$ ]] || die "COLLECTOR_SENDERS entry '$s' is not a namespace name"
done
read -r -a jobs <<<"${COLLECTOR_JOBS:-}"
for j in ${jobs[@]+"${jobs[@]}"}; do
  case "$j" in
    argocd-central | argocd-agent | argocd-agent-principal | spire-server) ;;
    *) die "COLLECTOR_JOBS entry '$j' is not argocd-central, argocd-agent, argocd-agent-principal or spire-server" ;;
  esac
done
has_job() { local j; for j in ${jobs[@]+"${jobs[@]}"}; do [[ "$j" == "$1" ]] && return 0; done; return 1; }

store="${COLLECTOR_STORE:-}"
if [[ -n "$store" ]]; then
  [[ "$store" =~ ^[a-z0-9.-]+:[1-9][0-9]{0,4}$ ]] || die "COLLECTOR_STORE '$store' is not host:port"
  store_port="${store##*:}"
  ((store_port <= 65535)) || die "COLLECTOR_STORE '$store' has a port above 65535"
  [[ "$plane" == management ]] || die "COLLECTOR_STORE is set, and COLLECTOR_PLANE '$plane' is not management"
  exporter_endpoint="$store"
else
  [[ "$plane" != management ]] || die "COLLECTOR_PLANE is management, and COLLECTOR_STORE is not set"
  exporter_endpoint="$UPLINK_ENDPOINT"
fi

# The five source attributes and the Istio destination label, in every flattened form.
RE_ALL='(?i)^[_.-]*(k8s[._-]cluster[._-]name|platform[._-]plane|platform[._-]cell|deployment[._-]environment[._-]name|source[._-]cluster|destination[._-]cluster)[_.-]*$'
RE_SOURCE='(?i)^[_.-]*(k8s[._-]cluster[._-]name|platform[._-]plane|platform[._-]cell|deployment[._-]environment[._-]name)[_.-]*$'

# strip <regex> <context>... prints one statement list for each of the given contexts.
strip() {
  local re="$1" ctx; shift
  for ctx in "$@"; do
    printf '      - context: %s\n        statements: [ '"'"'delete_matching_keys(attributes, "%s")'"'"' ]\n' "$ctx" "$re"
  done
}

# The collector reads $$ as one $ in its config, and the Prometheus relabeling then sees ${1}.
D='$$'

# scrape_head <name> <metrics path> <namespace>... starts a job over the pods of the namespaces.
scrape_head() {
  local name="$1" path="$2" list="" ns; shift 2
  for ns in "$@"; do list+="$ns, "; done
  printf '        - job_name: %s\n          scrape_interval: 30s\n' "$name"
  [[ "$path" == - ]] || printf '          metrics_path: %s\n' "$path"
  printf '          kubernetes_sd_configs:\n            - role: pod\n              namespaces:\n                names: [%s]\n          relabel_configs:\n' "${list%, }"
}
# pod_labels copies pod and namespace into the labels of each data point, and drops pods that do not run.
pod_labels() {
  cat <<'EOF'
            - source_labels: [__meta_kubernetes_pod_phase]
              regex: Pending|Succeeded|Failed|Unknown
              action: drop
            - source_labels: [__meta_kubernetes_pod_name]
              target_label: pod
            - source_labels: [__meta_kubernetes_namespace]
              target_label: namespace
EOF
}
# address_rule <container selector regex> <port> keeps the pods whose app label and container match,
# and scrapes the pod address on the port.
address_rule() {
  cat <<EOF
            - source_labels: [__meta_kubernetes_pod_label_app_kubernetes_io_name, __meta_kubernetes_pod_container_name]
              regex: $1
              action: keep
            - source_labels: [__meta_kubernetes_pod_ip]
              regex: (.+)
              replacement: ${D}1:$2
              target_label: __address__
EOF
}
scrape_jobs() {
  # Envoy of every pod with an istio-proxy container. The sidecar is an init container or a regular one.
  scrape_head envoy /stats/prometheus apps-demo istio-egress
  cat <<'EOF'
            - source_labels: [__meta_kubernetes_pod_container_name, __meta_kubernetes_pod_container_port_number]
              regex: istio-proxy;15090
              action: keep
EOF
  pod_labels
  scrape_head istiod - istio-system
  cat <<EOF
            - source_labels: [__meta_kubernetes_pod_label_app, __meta_kubernetes_pod_container_name]
              regex: istiod;discovery
              action: keep
            - source_labels: [__meta_kubernetes_pod_ip]
              regex: (.+)
              replacement: ${D}1:15014
              target_label: __address__
EOF
  pod_labels
  if has_job argocd-central; then scrape_head argocd - argocd central-view-system; else scrape_head argocd - argocd; fi
  cat <<EOF
            - source_labels: [__meta_kubernetes_pod_label_app_kubernetes_io_name]
              regex: argocd-application-controller|argocd-repo-server|argocd-server
              action: keep
            - source_labels: [__meta_kubernetes_pod_label_app_kubernetes_io_name, __meta_kubernetes_pod_ip]
              regex: argocd-application-controller;(.+)
              replacement: ${D}1:8082
              target_label: __address__
            - source_labels: [__meta_kubernetes_pod_label_app_kubernetes_io_name, __meta_kubernetes_pod_ip]
              regex: argocd-repo-server;(.+)
              replacement: ${D}1:8084
              target_label: __address__
            - source_labels: [__meta_kubernetes_pod_label_app_kubernetes_io_name, __meta_kubernetes_pod_ip]
              regex: argocd-server;(.+)
              replacement: ${D}1:8083
              target_label: __address__
EOF
  pod_labels
  if has_job argocd-agent; then
    scrape_head argocd-agent - argocd
    address_rule 'argocd-agent;argocd-agent' 8181
    pod_labels
  fi
  if has_job argocd-agent-principal; then
    scrape_head argocd-agent-principal - central-view-system
    address_rule 'argocd-agent-principal;argocd-agent-principal' 8000
    pod_labels
  fi
  if has_job spire-server; then
    scrape_head spire-server - spire-system
    address_rule 'spire-server;spire-server' 9988
    pod_labels
  fi
}

# resource_pairs prints the attributes of this cluster, one "<key> <value>" line each, in the order of the
# source attribute table.
resource_pairs() {
  echo "k8s.cluster.name $cluster"
  echo "platform.plane $plane"
  if [[ "$plane" != management ]]; then echo "deployment.environment.name $POC_ENV"; fi
  if [[ "$plane" == cell ]]; then echo "platform.cell $cluster"; fi
}
resource_attributes() {
  local k v
  while read -r k v; do
    printf '      - key: %s\n        value: %s\n        action: upsert\n' "$k" "$v"
  done < <(resource_pairs)
}

# The smallest resource that leaves the collector: each attribute takes its key, its value and 8 bytes of
# tags and lengths.
min_resource=0
while read -r k v; do min_resource=$((min_resource + ${#k} + ${#v} + 8)); done < <(resource_pairs)
EXPORT_MAX_BYTES=$((RESOURCE_BUDGET * min_resource))
((EXPORT_MAX_BYTES <= EXPORT_BYTES_CAP)) || EXPORT_MAX_BYTES=$EXPORT_BYTES_CAP
# The store has no cap on resources, so management exports straight to it in requests up to the cap.
[[ -z "$store" ]] || EXPORT_MAX_BYTES=$EXPORT_BYTES_CAP
EXPORT_MIN_BYTES=$((EXPORT_MAX_BYTES / 2))

config="$(cat <<YAML
extensions:
  file_storage:
    directory: /var/lib/otelcol/queue
    create_directory: true
    timeout: 10s
    compaction:
      directory: /var/lib/otelcol/compaction
      on_start: true
      on_rebound: true
      rebound_needed_threshold_mib: 100
      rebound_trigger_threshold_mib: 10
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317
        max_recv_msg_size_mib: $RECEIVE_MAX_MIB
      http:
        endpoint: 0.0.0.0:4318
  prometheus:
    config:
      scrape_configs:
$(scrape_jobs)
  k8s_objects:
    auth_type: serviceAccount
    objects:
      - name: events
        group: events.k8s.io
        mode: watch
processors:
  memory_limiter:
    check_interval: 1s
    limit_mib: 512
    spike_limit_mib: 128
  transform/otlp:
    error_mode: propagate
    trace_statements:
$(strip "$RE_ALL" resource scope span spanevent)
    metric_statements:
$(strip "$RE_ALL" resource scope datapoint)
    log_statements:
$(strip "$RE_ALL" resource scope log)
  transform/scrape:
    error_mode: propagate
    metric_statements:
$(strip "$RE_SOURCE" resource scope datapoint)
  resource:
    attributes:
$(resource_attributes)
exporters:
  otlp_grpc:
    endpoint: $exporter_endpoint
    tls:
      insecure: true
    timeout: 15s
    keepalive:
      time: 30s
      timeout: 10s
      permit_without_stream: true
    retry_on_failure:
      enabled: true
      initial_interval: 5s
      max_interval: 30s
      max_elapsed_time: 0
    sending_queue:
      enabled: true
      num_consumers: 4
      queue_size: $QUEUE_MAX_BYTES
      sizer: bytes
      storage: file_storage
      batch:
        flush_timeout: 5s
        min_size: $EXPORT_MIN_BYTES
        max_size: $EXPORT_MAX_BYTES
        sizer: bytes
service:
  extensions: [file_storage]
  telemetry:
    logs:
      encoding: json
    metrics:
      level: normal
      readers:
        - periodic:
            interval: 30000
            exporter:
              otlp:
                protocol: grpc
                endpoint: http://127.0.0.1:4317
  pipelines:
    traces:
      receivers: [otlp]
      processors: [memory_limiter, transform/otlp, resource]
      exporters: [otlp_grpc]
    logs:
      receivers: [otlp, k8s_objects]
      processors: [memory_limiter, transform/otlp, resource]
      exporters: [otlp_grpc]
    metrics:
      receivers: [otlp]
      processors: [memory_limiter, transform/otlp, resource]
      exporters: [otlp_grpc]
    metrics/scrape:
      receivers: [prometheus]
      processors: [memory_limiter, transform/scrape, resource]
      exporters: [otlp_grpc]
YAML
)"

# The checksum restarts the pod when the config changes, because the collector reads it at start.
collector="$(CONFIG="$config" IMAGE="$K8S_COLLECTOR_IMAGE" SUM="$(printf '%s' "$config" | sha256)" yq '
  select(.kind != null)
  | (select(.kind != "ClusterRole" and .kind != "ClusterRoleBinding") | .metadata.namespace) = "observability-system"
  | (select(.kind == "ConfigMap" and .metadata.name == "otel-collector") | .data["config.yaml"]) = strenv(CONFIG)
  | (select(.kind == "ConfigMap" and .metadata.name == "otel-collector") | .data["config.yaml"]) style="literal"
  | (select(.kind == "StatefulSet") | .spec.template.spec.containers[0].image) = strenv(IMAGE)
  | (select(.kind == "StatefulSet") | .spec.template.metadata.annotations["poc.internal/collector-config-sha256"]) = strenv(SUM)' "$here/collector.yaml")"
echo "$collector"

node_peers() {
  local ip
  for ip in $node_ips; do
    printf '        - ipBlock:\n            cidr: %s/32\n' "$ip"
  done
}
api_peers() {
  local ip
  for ip in $api_ips; do
    printf '        - ipBlock:\n            cidr: %s/32\n' "$ip"
  done
}
namespace_in() {
  local list="" ns
  for ns in "$@"; do list+="$ns, "; done
  printf '            matchExpressions:\n              - key: kubernetes.io/metadata.name\n                operator: In\n                values: [%s]\n' "${list%, }"
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
# Flow N23: the kubelet probes each pod from a node address. The store and the gateway probe
# themselves inside the pod, so they admit no node address. The collector and the uplink admit a node
# address on their probe port only.
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
        values: [lgtm, telemetry-gateway, otel-collector, otel-uplink]
  policyTypes: [Ingress]
  ingress:
    - from:
$(node_peers)
---
# Flow N11 in: only the namespaces of COLLECTOR_SENDERS send OTLP on 4317, because a pod of any other
# namespace could forge the signals of this cluster through the collector. The bundle store sends
# OTLP over HTTP on 4318, and no other pod may use that port. Add a namespace to COLLECTOR_SENDERS
# when a new workload sends OTLP. A node address reaches the probe port only (flow N23).
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
        - namespaceSelector:
$(namespace_in "${senders[@]}")
      ports:
        - protocol: TCP
          port: 4317
    - from:
        - podSelector:
            matchLabels:
              app.kubernetes.io/name: $([[ -n "$store" ]] && echo telemetry-gateway || echo otel-uplink)
      ports:
        - protocol: TCP
          port: 4317
    - from:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: cell-system
          podSelector:
            matchLabels:
              app.kubernetes.io/name: bundle-store
      ports:
        - protocol: TCP
          port: 4318
    - from:
$(node_peers)
      ports:
        - protocol: TCP
          port: 4317
---
# Flows N10 or N19 (the exporter), N15 (the scrape targets) and N16 (the API server) out.
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
              app.kubernetes.io/name: $([[ -n "$store" ]] && echo lgtm || echo otel-uplink)
      ports:
        - protocol: TCP
          port: ${store_port:-4319}
    - to:
$(api_peers)
      ports:
        - protocol: TCP
          port: $API_SERVER_PORT
    - to:
        - ipBlock:
            cidr: $API_SERVICE_IP/32
      ports:
        - protocol: TCP
          port: 443
    - to:
        - namespaceSelector:
$(namespace_in apps-demo istio-egress)
      ports:
        - protocol: TCP
          port: 15090
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: istio-system
          podSelector:
            matchLabels:
              app: istiod
      ports:
        - protocol: TCP
          port: 15014
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: argocd
          podSelector:
            matchExpressions:
              - key: app.kubernetes.io/name
                operator: In
                values: [argocd-application-controller, argocd-repo-server]
      ports:
        - protocol: TCP
          port: 8082
        - protocol: TCP
          port: 8084
EOF
if has_job argocd-central; then
  cat <<EOF
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: central-view-system
          podSelector:
            matchExpressions:
              - key: app.kubernetes.io/name
                operator: In
                values: [argocd-server, argocd-repo-server]
      ports:
        - protocol: TCP
          port: 8083
        - protocol: TCP
          port: 8084
EOF
fi
if has_job argocd-agent; then
  cat <<EOF
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: argocd
          podSelector:
            matchLabels:
              app.kubernetes.io/name: argocd-agent
      ports:
        - protocol: TCP
          port: 8181
EOF
fi
if has_job argocd-agent-principal; then
  cat <<EOF
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: central-view-system
          podSelector:
            matchLabels:
              app.kubernetes.io/name: argocd-agent-principal
      ports:
        - protocol: TCP
          port: 8000
EOF
fi
if has_job spire-server; then
  cat <<EOF
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: spire-system
          podSelector:
            matchLabels:
              app.kubernetes.io/name: spire-server
      ports:
        - protocol: TCP
          port: 9988
EOF
fi
