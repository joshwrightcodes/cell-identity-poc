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

NAMESPACES=(argocd cell-system istio-system istio-egress observability-system apps-demo)

# Private and link-local ranges. The egress gateway may reach any public address on 443, but
# no private address, so it cannot reach other clusters or the host network.
PRIVATE_RANGES=(10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 100.64.0.0/10 169.254.0.0/16 127.0.0.0/8)

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
  podSelector: {}
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
  podSelector: {}
  policyTypes: [Ingress, Egress]
  ingress:
    - from:
        - podSelector: {}
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
      ports:
        - protocol: TCP
          port: 5000
  egress:
    - to:
$(namespace_peer observability-system)
      ports:
        - protocol: TCP
          port: 4318
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
  name: collector
  namespace: observability-system
spec:
  podSelector: {}
  policyTypes: [Ingress]
  ingress:
    - from:
        - namespaceSelector: {}
      ports:
        - protocol: TCP
          port: 4317
        - protocol: TCP
          port: 4318
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
