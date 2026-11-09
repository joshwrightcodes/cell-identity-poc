#!/usr/bin/env bash
# Render the External Secrets Operator from the vendored chart, with its namespace and NetworkPolicies.
# The controller may reach only DNS and the Kubernetes API. With a secret store, it may also reach
# public addresses on port 443. The policies deny all ingress, because the controller serves
# nothing that another pod needs.
# The controller works in one namespace: EXTERNAL_SECRETS_NAMESPACE, which defaults to the store
# namespace in SECRET_STORE_NAMESPACES. Its Role and RoleBinding live there, so this bundle also
# holds that Namespace, unless a base bundle holds it already: the bundle of a namespace that
# no base bundle holds comes in a later sync wave.
# Inputs: EXTERNAL_SECRETS_VERSION from cells/common.env, EXTERNAL_SECRETS_NAMESPACE and
# SECRET_STORE_NAMESPACES from cells/<cluster>.env, and API_SERVER_IPS, API_SERVER_PORT,
# API_SERVICE_IP and DNS_SERVICE_IP from build/<cluster>/facts.env.
set -euo pipefail
: "${EXTERNAL_SECRETS_VERSION:?}" "${API_SERVER_IPS:?}" "${API_SERVER_PORT:?}" "${API_SERVICE_IP:?}" "${DNS_SERVICE_IP:?}"

fail() { printf 'error: external-secrets render: %s\n' "$*" >&2; exit 1; }

# The controller takes one --namespace, so the cell has one controller namespace. A store in another
# namespace would never become Ready.
read -r -a store_namespaces <<<"${SECRET_STORE_NAMESPACES:-}"
scope="${EXTERNAL_SECRETS_NAMESPACE:-${SECRET_STORE_NAMESPACES:-}}"
read -r -a scopes <<<"$scope"
if ((${#scopes[@]} != 1)) || [[ ! "${scopes[0]}" =~ ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$ ]]; then
  fail "EXTERNAL_SECRETS_NAMESPACE, or SECRET_STORE_NAMESPACES when it is unset, must name exactly one namespace, got '$scope'"
fi
store_namespace="${scopes[0]}"
if ((${#store_namespaces[@]} > 0)) && [[ "${store_namespaces[*]}" != "$store_namespace" ]]; then
  fail "SECRET_STORE_NAMESPACES '${SECRET_STORE_NAMESPACES:-}' must name only the controller namespace EXTERNAL_SECRETS_NAMESPACE '$store_namespace'"
fi

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
namespace=external-secrets
source "$root/components/lib/addresses.sh"
api_ips="$(ipv4_list API_SERVER_IPS)" || exit 1
chart="$root/vendor/charts/external-secrets-$EXTERNAL_SECRETS_VERSION/external-secrets"

# Private and link-local ranges. They hold the pod, service and kind networks, the Lima host
# network and loopback, so the controller reaches no other cluster and not the Mac.
PRIVATE_RANGES=(10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 100.64.0.0/10 169.254.0.0/16 127.0.0.0/8)

# Render the chart first, so a chart error prints nothing.
manifests="$(helm template external-secrets "$chart" --namespace "$namespace" --kube-version 1.37.0 \
  --values "$here/values.yaml" --set "scopedNamespace=$store_namespace")"

api_peers="$(for ip in $api_ips; do printf '        - ipBlock:\n            cidr: %s/32\n' "$ip"; done)"

# The namespaces bundle holds the base namespaces. Two Applications must not hold one Namespace.
base_namespaces=" $(kustomize build "$root/components/namespaces" | yq -N 'select(.kind == "Namespace") | .metadata.name' | tr '\n' ' ') "

cat <<EOF
apiVersion: v1
kind: Namespace
metadata:
  name: $namespace
  labels:
    istio-injection: disabled
    pod-security.kubernetes.io/enforce: restricted
EOF
if [[ "$base_namespaces" != *" $store_namespace "* ]]; then
  cat <<EOF
---
apiVersion: v1
kind: Namespace
metadata:
  name: $store_namespace
  labels:
    istio-injection: disabled
    pod-security.kubernetes.io/enforce: restricted
  annotations:
    # A bundle that drops the namespace, or a deleted Application, must not delete it and the data of
    # the workloads in it.
    argocd.argoproj.io/sync-options: Prune=false,Delete=false
EOF
fi
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
EOF
# Only a cluster with a secret store reaches the secret manager.
if ((${#store_namespaces[@]} > 0)); then
  cat <<EOF
    - to:
        - ipBlock:
            cidr: 0.0.0.0/0
            except:
$(printf '              - %s\n' "${PRIVATE_RANGES[@]}")
      ports:
        - protocol: TCP
          port: 443
EOF
fi
printf '%s\n' "$manifests"
