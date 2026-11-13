# Facts about the host service for the render of mgmt-api. Source this file from a render script.
#
# Each helper prints its value on standard output. On failure it prints the reason on standard error
# and returns 1, so the render stops.

HOSTSVC_PIN_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

# hostsvc_serve_script prints the host service script. HOSTSVC_SERVE names another one, for the tests.
hostsvc_serve_script() { printf '%s\n' "${HOSTSVC_SERVE:-$HOSTSVC_PIN_ROOT/scripts/hostsvc-serve.sh}"; }

# hostsvc_address <cluster> prints the one IPv4 address that getent ahostsv4 gives for
# host.docker.internal in the node container of the cluster, with duplicates removed. Pods reach the
# host service there. It fails when the answer holds no address or more than one.
hostsvc_address() {
  local node="$1-control-plane" out ips n
  if ! out="$(docker exec "$node" getent ahostsv4 host.docker.internal 2>&1)"; then
    printf 'error: could not resolve host.docker.internal in %s: %s\n' "$node" "$(tail -n 1 <<<"$out")" >&2
    return 1
  fi
  ips="$(awk '$1 ~ /^([0-9]{1,3}\.){3}[0-9]{1,3}$/ { print $1 }' <<<"$out" | sort -u)"
  n="$(grep -c . <<<"$ips" || true)"
  if ((n != 1)); then
    printf 'error: host.docker.internal gives %s addresses in %s (%s), and the host service policy needs exactly one\n' \
      "$n" "$node" "$(paste -sd' ' - <<<"$ips")" >&2
    return 1
  fi
  printf '%s\n' "$ips"
}

# hostsvc_pin_configmap <namespace> starts the host service when it does not serve, and prints
# ConfigMap hostsvc-pin with the certificate that the service presents, in key hostsvc.crt. The
# certificate is the one that hostsvc pin read with the SHA-256 of the serving line of the log. The
# annotation poc.internal/hostsvc-pin-sha256 holds that SHA-256. A render copies the annotation to
# the pod template, so a new certificate restarts the pod.
hostsvc_pin_configmap() {
  local ns="$1" serve status sha pem
  serve="$(hostsvc_serve_script)"
  "$serve" start >&2 || { printf 'error: the host service does not serve. Run: mise run hostsvc:serve -- start\n' >&2; return 1; }
  status="$("$serve" status)" || return 1
  sha="$(jq -r '.cert_sha256 // ""' <<<"$status")"
  if [[ ! "$sha" =~ ^[0-9a-f]{64}$ ]]; then
    printf 'error: the host service status holds no certificate SHA-256: %s\n' "$status" >&2
    return 1
  fi
  pem="$("$serve" pin)" || return 1
  [[ "$pem" == *"-----BEGIN CERTIFICATE-----"* ]] || { printf 'error: the host service pin is no PEM certificate\n' >&2; return 1; }
  NS="$ns" PEM="$pem" SUM="$sha" yq -n '
    .apiVersion = "v1" | .kind = "ConfigMap" | .metadata.name = "hostsvc-pin" | .metadata.namespace = strenv(NS)
    | .metadata.annotations["poc.internal/hostsvc-pin-sha256"] = strenv(SUM)
    | .data["hostsvc.crt"] = strenv(PEM) | .data["hostsvc.crt"] style="literal"'
}
