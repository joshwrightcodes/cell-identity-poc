#!/usr/bin/env bash
# Render the External Secrets Operator from the vendored chart, with its namespace and NetworkPolicies.
# The controller may reach only DNS, the Kubernetes API and public addresses on port 443. The
# policies deny all ingress, because the controller serves nothing that another pod needs.
# Inputs: EXTERNAL_SECRETS_VERSION from cells/common.env, and API_SERVER_IPS, API_SERVER_PORT,
# API_SERVICE_IP and DNS_SERVICE_IP from build/<cluster>/facts.env.
set -euo pipefail
: "${EXTERNAL_SECRETS_VERSION:?}" "${API_SERVER_IPS:?}" "${API_SERVER_PORT:?}" "${API_SERVICE_IP:?}" "${DNS_SERVICE_IP:?}"

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
namespace=external-secrets
chart="$root/vendor/charts/external-secrets-$EXTERNAL_SECRETS_VERSION/external-secrets"

# Private and link-local ranges. They hold the pod, service and kind networks, the Lima host
# network and loopback, so the controller reaches no other cluster and not the Mac.
PRIVATE_RANGES=(10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 100.64.0.0/10 169.254.0.0/16 127.0.0.0/8)

# Render the chart first, so a chart error prints nothing.
manifests="$(helm template external-secrets "$chart" --namespace "$namespace" --kube-version 1.37.0 \
  --values "$here/values.yaml")"

api_peers="$(for ip in $API_SERVER_IPS; do printf '        - ipBlock:\n            cidr: %s/32\n' "$ip"; done)"

cat <<EOF
apiVersion: v1
kind: Namespace
metadata:
  name: $namespace
  labels:
    istio-injection: disabled
    pod-security.kubernetes.io/enforce: restricted
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
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: controller-egress
  namespace: $namespace
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
    - to:
$api_peers
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
        - ipBlock:
            cidr: 0.0.0.0/0
            except:
$(printf '              - %s\n' "${PRIVATE_RANGES[@]}")
      ports:
        - protocol: TCP
          port: 443
EOF
printf '%s\n' "$manifests"
