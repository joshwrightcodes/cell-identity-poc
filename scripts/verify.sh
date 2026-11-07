#!/usr/bin/env bash
# Check each base cell rule against the running cluster. Prints PASS or FAIL per check and
# exits non-zero if any check fails.
source "$(dirname "$0")/lib.sh"
set +e

failures=0
check() {
  local name="$1"; shift
  local detail
  if detail="$("$@" 2>&1)"; then
    printf 'PASS  %s\n' "$name"
  else
    printf 'FAIL  %s\n' "$name"
    [[ -n "$detail" ]] && printf '      %s\n' "${detail//$'\n'/$'\n      '}"
    failures=$((failures + 1))
  fi
}

# curl_from <deployment> <curl args...>: run curl in the curl container of a demo workload.
curl_from() {
  local from="$1"; shift
  k -n apps-demo exec "deploy/$from" -c curl -- curl -sS --max-time 10 "$@"
}

http_code() {
  local from="$1" url="$2"
  curl_from "$from" -o /dev/null -w '%{http_code}' "$url" 2>/dev/null
}

expect_code() {
  local from="$1" url="$2" want="$3" got
  got="$(http_code "$from" "$url")"
  [[ "$got" == "$want" ]] || { echo "$from -> $url: got HTTP '${got:-none}', want $want"; return 1; }
}

expect_no_connection() {
  # curl prints 000 when it cannot connect. Any other output, including none from a failed
  # kubectl exec, is a failure.
  local from="$1" url="$2" got
  got="$(http_code "$from" "$url")"
  [[ "$got" == "000" ]] || { echo "$from -> $url: got '${got:-no output}', want no connection (000)"; return 1; }
}

has_proxy() {
  # Istio adds istio-proxy as a native sidecar (an init container) or as a regular container.
  k -n "$1" get pod -l "app=$2" -o json | jq -e '
    [.items[].spec | (.initContainers // []) + .containers | .[].name] | index("istio-proxy") != null' >/dev/null
}

check_apps_synced() {
  k -n argocd get applications -o json | jq -e --argjson n "$((${#COMPONENTS[@]} + 1))" '
    (.items | length) == $n and
    all(.items[]; .status.sync.status == "Synced" and .status.health.status == "Healthy")' >/dev/null \
    || { k -n argocd get applications; return 1; }
}

check_argocd_local_only() {
  local clusters
  clusters="$(k -n argocd get secrets -l argocd.argoproj.io/secret-type=cluster -o name)"
  [[ -z "$clusters" ]] || { echo "remote cluster secrets: $clusters"; return 1; }
  k -n argocd get applications -o json | jq -e --arg store "oci://$STORE_HOST/bundles/" '
    all(.items[]; .spec.destination.server == "https://kubernetes.default.svc"
      and (.spec.source.repoURL | startswith($store)))' >/dev/null \
    || { echo "an Application has another destination or source"; return 1; }
}

check_platform_outside_mesh() {
  local ns
  for ns in argocd cell-system otel; do
    k -n "$ns" get pods -o json | jq -e '
      [.items[].spec | (.initContainers // []) + .containers | .[].name] | index("istio-proxy") == null' >/dev/null \
      || { echo "$ns has a pod with istio-proxy"; return 1; }
  done
}

check_workloads_in_mesh() {
  local app
  for app in echo client intruder; do
    has_proxy apps-demo "$app" || { echo "$app has no istio-proxy"; return 1; }
  done
  ! has_proxy apps-demo plaintext || { echo "plaintext has istio-proxy"; return 1; }
}

check_trust_domain() {
  local want="spiffe://$CELL_MESH_TRUST_DOMAIN/ns/apps-demo/sa/echo" certs
  certs="$(k -n apps-demo exec deploy/echo -c istio-proxy -- pilot-agent request GET certs)"
  grep -qF "\"$want\"" <<<"$certs" || { echo "echo has no certificate for $want"; return 1; }
}

check_egress_through_gateway() {
  # Count upstream connections from the gateway to example.com. Istio trims most stats from
  # the stats endpoint, but /clusters keeps a cx_total counter for each upstream host.
  gateway_count() {
    k -n istio-egress exec deploy/istio-egressgateway -- pilot-agent request GET clusters \
      | awk -F'::' '$1 == "outbound|443||example.com" && $3 == "cx_total" { n += $4 } END { print n + 0 }'
  }
  local before after
  before="$(gateway_count)"
  expect_code client https://example.com/ 200 || return 1
  after="$(gateway_count)"
  ((after > before)) || { echo "egress gateway connections to example.com: $before before, $after after"; return 1; }
}

check_psa_rejects_privileged() {
  local out
  if out="$(k -n apps-demo run psa-probe --image=docker.io/curlimages/curl:8.23.0 --privileged \
    --dry-run=server -o name 2>&1)"; then
    echo "a privileged pod was admitted: $out"
    return 1
  fi
  grep -q "violates PodSecurity" <<<"$out" || { echo "$out"; return 1; }
}

check_traces_received() {
  local i
  for i in 1 2 3; do expect_code client http://echo/hostname 200 >/dev/null; done
  local end=$((SECONDS + 60))
  # Read the logs into a variable first. With pipefail, grep -q would close the pipe early
  # and turn a match into a failure.
  local logs
  until logs="$(k -n otel logs deploy/otel-collector --since=5m)" && grep -q 'echo.apps-demo' <<<"$logs"; do
    ((SECONDS < end)) || { echo "no span or access log for echo.apps-demo in the collector output"; return 1; }
    sleep 5
  done
}

log "checking cell $CELL_NAME"
k get --raw /readyz >/dev/null 2>&1 || die "cannot reach the API server of $CELL_NAME"
check "Argo CD reports every Application Synced and Healthy" check_apps_synced
check "Argo CD has no remote clusters and reads only the local store" check_argocd_local_only
check "argocd, cell-system and otel run without mesh proxies" check_platform_outside_mesh
check "Demo workloads run with mesh proxies, except plaintext" check_workloads_in_mesh
check "Mesh certificates use the cell trust domain" check_trust_domain
check "client reaches echo over mesh mTLS" expect_code client http://echo/hostname 200
check "intruder is denied by AuthorizationPolicy" expect_code intruder http://echo/hostname 403
check "plaintext cannot reach echo, because mTLS is strict" expect_no_connection plaintext http://echo/hostname
check "client reaches the allowed host through the egress gateway" check_egress_through_gateway
check "client cannot reach a host that is not allowed" expect_no_connection client https://example.org/
check "plaintext cannot reach the internet, because of NetworkPolicy" expect_no_connection plaintext https://example.com/
check "client cannot reach the bundle store" expect_no_connection client "http://$STORE_HOST/v2/"
check "plaintext cannot reach the bundle store" expect_no_connection plaintext "http://$STORE_HOST/v2/"
check "Pod Security rejects a privileged pod in a workload namespace" check_psa_rejects_privileged
check "The collector receives telemetry for echo" check_traces_received

if ((failures > 0)); then
  log "$failures check(s) failed"
  exit 1
fi
log "all checks passed"
