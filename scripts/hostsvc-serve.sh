#!/usr/bin/env bash
# The host service on this Mac: hostsvc serve answers the key requests of mgmtd on 127.0.0.1 at
# HOSTSVC_PORT. Pods reach it at the address that host.docker.internal has in the node container.
# Usage: hostsvc-serve.sh start|stop|restart|status|pin
#   start    Fetch the live root of management, check it, and write it to build/hostsvc/mgmt-root.crt.
#            Build build/bin/hostsvc, rotate the log, and run serve with nohup. Write the pid file.
#            Wait up to HOSTSVC_SERVE_WAIT seconds (default 10) until the pid owns the port, and
#            the certificate that the port presents has the SHA-256 of the serving log line.
#            Fail when another process holds the port. Do nothing when the process already serves
#            with the current root and a certificate that stays valid for 14 days or more. Restart
#            it when the root differs or the certificate is about to expire.
#   stop     End the process of the pid file, but only when its command line is build/bin/hostsvc serve.
#   restart  Run stop and start, then CELL=management LINK_ONLY=mgmt-api mise run cell:link, so mgmtd
#            gets the new pin.
#   status   Print one JSON line: running, pid, cert_sha256, root_sha256, expires_soon and the last
#            error line of the log.
#   pin      Print the certificate of the running service as PEM, checked against the serving log line.
# The service makes a new TLS key at each start. It trusts only the root that it read at start. It runs in its
# own process group, so a Ctrl-C of the task that started it leaves it running.
CELL="${CELL:-management}"
source "$(dirname "$0")/lib.sh"
source "$ROOT/components/lib/peer-root.sh"

dir="$BUILD_ROOT/hostsvc"
bin="$BUILD_ROOT/bin/hostsvc"
pidfile="$dir/serve.pid"
logfile="$dir/serve.log"
rootfile="$dir/mgmt-root.crt"
: "${HOSTSVC_PORT:?}"
port="$HOSTSVC_PORT"
addr="127.0.0.1:$port"
wait_seconds="${HOSTSVC_SERVE_WAIT:-10}"
# The certificate lives 90 days. A restart 14 days before its end leaves time for the re-link.
soon_seconds=$((14 * 24 * 3600))

cmd_of() { ps -ww -p "$1" -o command= 2>/dev/null || true; }

# running_pid prints the pid of the host service of the pid file, and nothing when no process with
# the command line "$bin serve" has that pid.
running_pid() {
  local pid
  [[ -f "$pidfile" ]] || return 0
  pid="$(tr -d '[:space:]' <"$pidfile")"
  [[ "$pid" =~ ^[0-9]+$ ]] || return 0
  kill -0 "$pid" 2>/dev/null || return 0
  is_service_cmd "$(cmd_of "$pid")" && echo "$pid"
  return 0
}

# is_service_cmd <command line> succeeds when the command line is "$bin serve", alone or with arguments. A
# wrapper that only names the binary does not match.
is_service_cmd() { [[ "$1" == "$bin serve" || "$1" == "$bin serve "* ]]; }

# port_holders prints every process that listens on the port, on one line. A second listener on another
# address of the same port counts.
port_holders() { { lsof -nP -iTCP:"$port" -sTCP:LISTEN -t 2>/dev/null || true; } | sort -un | paste -sd' ' -; }

# log_field <name> prints a field of the last serving line of the log.
log_field() {
  [[ -f "$logfile" ]] || return 0
  jq -Rr --arg f "$1" 'fromjson? | select(type == "object" and .msg == "serving") | .[$f] // empty' "$logfile" | tail -n 1
}

last_error() {
  [[ -f "$logfile" ]] || return 0
  jq -Rc 'fromjson? | select(type == "object" and .level == "ERROR")' "$logfile" | tail -n 1
}

pin_pem() { "$bin" pin --addr "$addr" --expect-sha256 "$1"; }

# expires_soon succeeds when the certificate of the running service ends within 14 days.
expires_soon() {
  local sha pem not_after
  sha="$(log_field cert_sha256)"
  [[ -n "$sha" ]] || return 1
  pem="$(pin_pem "$sha" 2>/dev/null)" || return 1
  not_after="$(cd "$ROOT" && mise run pki -- info <<<"$pem" 2>/dev/null | jq -r '.not_after // empty | fromdateiso8601')" || return 1
  [[ "$not_after" =~ ^[0-9]+$ ]] || return 1
  ((not_after - $(date -u +%s) < soon_seconds))
}

do_status() {
  local pid running=false soon=false
  pid="$(running_pid)"
  if [[ -n "$pid" ]]; then
    running=true
    ! expires_soon || soon=true
  fi
  jq -nc --argjson running "$running" --arg pid "$pid" --arg cert "$(log_field cert_sha256)" --arg root "$(log_field root_sha256)" \
    --argjson soon "$soon" --arg err "$(last_error)" \
    '{running: $running, pid: (if $pid == "" then null else ($pid | tonumber) end), cert_sha256: $cert, root_sha256: $root, expires_soon: $soon, last_error: $err}'
}

do_pin() {
  local pid sha
  pid="$(running_pid)"
  [[ -n "$pid" ]] || die "the host service does not run. Run: mise run hostsvc:serve -- start"
  sha="$(log_field cert_sha256)"
  [[ "$sha" =~ ^[0-9a-f]{64}$ ]] || die "the log $logfile has no serving line with cert_sha256"
  pin_pem "$sha" || die "the certificate on $addr does not have the SHA-256 $sha of the serving line"
}

do_stop() {
  local pid cmd end
  if [[ ! -f "$pidfile" ]]; then
    log "the host service has no pid file, so nothing stops"
    return 0
  fi
  pid="$(tr -d '[:space:]' <"$pidfile")"
  [[ "$pid" =~ ^[0-9]+$ ]] || die "$pidfile holds '$pid', not a pid. Remove the file if it is stale"
  if ! kill -0 "$pid" 2>/dev/null; then
    rm -f "$pidfile"
    log "process $pid of the host service is gone already"
    return 0
  fi
  cmd="$(cmd_of "$pid")"
  is_service_cmd "$cmd" || die "process $pid is not the host service: its command line is '$cmd', and the host service runs '$bin serve'. Remove $pidfile if it is stale"
  kill "$pid"
  end=$((SECONDS + wait_seconds))
  while kill -0 "$pid" 2>/dev/null; do
    ((SECONDS < end)) || die "process $pid did not stop within ${wait_seconds}s"
    sleep 0.2
  done
  rm -f "$pidfile"
  log "stopped the host service, process $pid"
}

# current_state prints why the running service needs a restart, and nothing when it is current.
current_state() {
  local pid="$1" want_root="$2" sha
  [[ "$(port_holders)" == "$pid" ]] || { echo "process $pid does not hold port $port alone"; return; }
  [[ "$(log_field root_sha256)" == "$want_root" ]] || { echo "it serves another management root than the live one"; return; }
  sha="$(log_field cert_sha256)"
  pin_pem "$sha" >/dev/null 2>&1 || { echo "the certificate on $addr does not have the SHA-256 of the serving line"; return; }
  ! expires_soon || echo "its certificate expires within 14 days"
  return 0
}

do_start() {
  local pid holders root_pem want_root why nofile end sha
  pid="$(running_pid)"
  holders="$(port_holders)"
  if [[ -n "$holders" && "$holders" != "$pid" ]]; then
    die "port $port is held by process $holders ($(cmd_of "${holders%% *}")), and the pid file names ${pid:-no host service}. Stop that process, then run: mise run hostsvc:serve -- start"
  fi
  root_pem="$(peer_root_pem management "$SPIRE_TRUST_DOMAIN_MGMT")" || exit 1
  want_root="$(pem_der_sha256 <<<"$root_pem")"
  [[ "$want_root" =~ ^[0-9a-f]{64}$ ]] || die "could not hash the live management root"
  if [[ -n "$pid" ]]; then
    why="$(current_state "$pid" "$want_root")"
    if [[ -z "$why" ]]; then
      log "the host service serves already, process $pid, with the live management root"
      return 0
    fi
    log "restarting the host service: $why"
    do_stop
  fi
  mkdir -p "$dir" "$(dirname "$bin")"
  # The root is public. The service reads it only at start.
  printf '%s\n' "$root_pem" >"$rootfile.tmp"
  mv "$rootfile.tmp" "$rootfile"
  (cd "$ROOT" && go build -o "$bin" ./cmd/hostsvc) || die "could not build $bin"
  [[ ! -f "$logfile" ]] || mv -f "$logfile" "$logfile.1"
  # serve needs 1104 open files, and the shell of launchd starts with 256.
  ulimit -n 4096 2>/dev/null || true
  nofile="$(ulimit -n)"
  [[ "$nofile" == unlimited || "$nofile" -ge 1104 ]] || die "the limit on open files is $nofile, and the host service needs 1104"
  cd "$ROOT"
  # Job control gives the service its own process group, so a Ctrl-C of the task that started it does not reach it.
  set -m
  nohup "$bin" serve --listen "$addr" --client-bundle "$rootfile" >"$logfile" 2>&1 </dev/null &
  pid=$!
  set +m
  disown "$pid" 2>/dev/null || true
  echo "$pid" >"$pidfile"
  end=$((SECONDS + wait_seconds))
  while :; do
    sha="$(log_field cert_sha256)"
    if kill -0 "$pid" 2>/dev/null; then
      if [[ "$(port_holders)" == "$pid" && -n "$sha" ]] && pin_pem "$sha" >/dev/null 2>&1; then
        log "the host service serves on $addr, process $pid, certificate $sha"
        return 0
      fi
    else
      rm -f "$pidfile"
      die "the host service exited at start. Last log line: $(tail -n 1 "$logfile" 2>/dev/null)"
    fi
    if ((SECONDS >= end)); then
      kill "$pid" 2>/dev/null || true
      rm -f "$pidfile"
      die "after ${wait_seconds}s process $pid does not own port $port with the certificate of its serving line. Last log line: $(tail -n 1 "$logfile" 2>/dev/null)"
    fi
    sleep 0.2
  done
}

SPIRE_TRUST_DOMAIN_MGMT=mgmt.poc.internal
case "${1:-}" in
  start) do_start ;;
  stop) do_stop ;;
  restart)
    do_stop
    do_start
    (cd "$ROOT" && CELL=management LINK_ONLY=mgmt-api mise run cell:link)
    ;;
  status) do_status ;;
  pin) do_pin ;;
  *) die "usage: hostsvc-serve.sh start|stop|restart|status|pin" ;;
esac
