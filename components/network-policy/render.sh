#!/usr/bin/env bash
# Render the NetworkPolicies for every namespace that the base cell owns.
# Every namespace denies all traffic by default. The policies below add only what each
# namespace needs. NetworkPolicy is the containment control: a pod with no mesh proxy
# bypasses Istio's egress rules, but it cannot bypass these.
# Inputs come from build/facts.env: POD_CIDR, NODE_IPS, API_SERVER_IPS, API_SERVER_PORT,
# API_SERVICE_IP and DNS_SERVICE_IP.
set -euo pipefail
: "${NODE_IPS:?}" "${API_SERVER_IPS:?}" "${API_SERVER_PORT:?}" "${API_SERVICE_IP:?}" "${DNS_SERVICE_IP:?}"

source "$(cd "$(dirname "$0")/../lib" && pwd)/addresses.sh"
node_ips="$(ipv4_list NODE_IPS)" || exit 1
api_ips="$(ipv4_list API_SERVER_IPS)" || exit 1

NAMESPACES=(argocd cell-system istio-system istio-egress apps-demo apps-sample)
# The policies of observability-system come from components/observability-system/render.sh.

# Private and link-local ranges. The egress gateway may reach any public address on 443, but
# no private address, so it cannot reach other clusters or the host network.
PRIVATE_RANGES=(10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 100.64.0.0/10 169.254.0.0/16 127.0.0.0/8)

# not_agent_selector prints the podSelector that picks every pod of argocd except the Argo CD Agent.
# The agent has its own policy argocd-agent, which holds every rule that it needs.
not_agent_selector() {
  printf '  podSelector:\n    matchExpressions:\n      - key: app.kubernetes.io/name\n        operator: NotIn\n        values: [argocd-agent]\n'
}

# node_selector prints the podSelector of allow-from-nodes in the namespace $1.
node_selector() {
  if [[ "$1" == argocd ]]; then not_agent_selector; else printf '  podSelector: {}\n'; fi
}

node_peers() {
  local ip
  for ip in $node_ips; do
    printf '        - ipBlock:\n            cidr: %s/32\n' "$ip"
  done
}

api_server_rule() {
  local ip
  printf '    - to:\n'
  for ip in $api_ips; do
    printf '        - ipBlock:\n            cidr: %s/32\n' "$ip"
  done
  printf '      ports:\n        - protocol: TCP\n          port: %s\n' "$API_SERVER_PORT"
  printf '    - to:\n        - ipBlock:\n            cidr: %s/32\n' "$API_SERVICE_IP"
  printf '      ports:\n        - protocol: TCP\n          port: 443\n'
}

namespace_peer() {
  printf '        - namespaceSelector:\n            matchLabels:\n              kubernetes.io/metadata.name: %s\n' "$1"
}

# collector_peer prints the peer of flow N15: the collector pod of observability-system. Each metrics
# port admits this peer only.
collector_peer() {
  printf '        - namespaceSelector:\n            matchLabels:\n              kubernetes.io/metadata.name: observability-system\n          podSelector:\n            matchLabels:\n              app.kubernetes.io/name: otel-collector\n'
}

for ns in "${NAMESPACES[@]}"; do
  cat <<EOF
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny
  namespace: $ns
spec:
  podSelector: {}
  policyTypes: [Ingress, Egress]
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-dns
  namespace: $ns
spec:
  podSelector: {}
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
# Kubelet probes and API server webhook calls come from the node addresses.
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-from-nodes
  namespace: $ns
spec:
$(node_selector "$ns")
  policyTypes: [Ingress]
  ingress:
    - from:
$(node_peers)
EOF
done

cat <<EOF
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: argocd
  namespace: argocd
spec:
$(not_agent_selector)
  policyTypes: [Ingress, Egress]
  ingress:
    - from:
        - podSelector: {}
    # N15: the application controller and the repo server.
    - from:
$(collector_peer)
      ports:
        - protocol: TCP
          port: 8082
        - protocol: TCP
          port: 8084
  egress:
    - to:
        - podSelector: {}
    - to:
$(namespace_peer cell-system)
          podSelector:
            matchLabels:
              app.kubernetes.io/name: bundle-store
      ports:
        - protocol: TCP
          port: 5000
    - to:
$(namespace_peer observability-system)
      ports:
        - protocol: TCP
          port: 4317
$(api_server_rule)
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: bundle-store
  namespace: cell-system
spec:
  podSelector:
    matchLabels:
      app.kubernetes.io/name: bundle-store
  policyTypes: [Ingress, Egress]
  ingress:
    - from:
$(namespace_peer argocd)
          podSelector:
            matchLabels:
              app.kubernetes.io/name: argocd-repo-server
      ports:
        - protocol: TCP
          port: 5000
  egress:
    # N11: the registry sends OTLP over HTTP (4318) and the store proxy sends it over gRPC (4317) to the collector.
    - to:
$(namespace_peer observability-system)
          podSelector:
            matchLabels:
              app.kubernetes.io/name: otel-collector
      ports:
        - protocol: TCP
          port: 4317
        - protocol: TCP
          port: 4318
    # N47: the store proxy asks the API server which account owns a token.
$(api_server_rule)
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: istio-system
  namespace: istio-system
spec:
  podSelector: {}
  policyTypes: [Ingress, Egress]
  ingress:
    - from:
        - podSelector: {}
    - from:
        - namespaceSelector: {}
      ports:
        - protocol: TCP
          port: 15010
        - protocol: TCP
          port: 15012
        - protocol: TCP
          port: 15017
    # N15: the metrics of istiod.
    - from:
$(collector_peer)
      ports:
        - protocol: TCP
          port: 15014
  egress:
    - to:
        - podSelector: {}
$(api_server_rule)
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: egress-gateway
  namespace: istio-egress
spec:
  podSelector: {}
  policyTypes: [Ingress, Egress]
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              cell.poc.internal/workloads: "true"
      ports:
        - protocol: TCP
          port: 443
    # N15: the Envoy metrics.
    - from:
$(collector_peer)
      ports:
        - protocol: TCP
          port: 15090
    # N15: the certificate expiry of the Istio agent.
    - from:
$(collector_peer)
      ports:
        - protocol: TCP
          port: 15020
  egress:
    - to:
$(namespace_peer istio-system)
      ports:
        - protocol: TCP
          port: 15012
    - to:
$(namespace_peer observability-system)
      ports:
        - protocol: TCP
          port: 4317
    - to:
        - ipBlock:
            cidr: 0.0.0.0/0
            except:
$(printf '              - %s\n' "${PRIVATE_RANGES[@]}")
      ports:
        - protocol: TCP
          port: 443
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: workloads
  namespace: apps-demo
spec:
  podSelector: {}
  policyTypes: [Ingress, Egress]
  ingress:
    - from:
        - podSelector: {}
    # N15: the Envoy metrics.
    - from:
$(collector_peer)
      ports:
        - protocol: TCP
          port: 15090
    # N15: the certificate expiry of the Istio agent.
    - from:
$(collector_peer)
      ports:
        - protocol: TCP
          port: 15020
  egress:
    - to:
        - podSelector: {}
    - to:
$(namespace_peer istio-system)
      ports:
        - protocol: TCP
          port: 15012
    - to:
$(namespace_peer istio-egress)
      ports:
        - protocol: TCP
          port: 443
    - to:
$(namespace_peer observability-system)
      ports:
        - protocol: TCP
          port: 4317
        - protocol: TCP
          port: 4318
EOF

# apps-sample is the namespace of the app class. Its pods reach each other, DNS, the kubelet probes and
# istiod, which each sidecar needs. The collector reads their Envoy metrics. Every other flow stays closed, so a pod of the app class cannot reach a
# platform workload.
cat <<EOF
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: workloads
  namespace: apps-sample
spec:
  podSelector: {}
  policyTypes: [Ingress, Egress]
  ingress:
    - from:
        - podSelector: {}
    # N15: the Envoy metrics.
    - from:
$(collector_peer)
      ports:
        - protocol: TCP
          port: 15090
    # N15: the certificate expiry of the Istio agent.
    - from:
$(collector_peer)
      ports:
        - protocol: TCP
          port: 15020
  egress:
    - to:
        - podSelector: {}
    - to:
$(namespace_peer istio-system)
      ports:
        - protocol: TCP
          port: 15012
EOF
