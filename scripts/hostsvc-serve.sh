#!/usr/bin/env bash
# The host service on this Mac: hostsvc serve answers the key requests of mgmtd, the spec pushes of mgmtd and
# the step requests of the cell controller on 127.0.0.1 at HOSTSVC_PORT. Pods reach it at the address that
# host.docker.internal has in the node container.
# Usage: hostsvc-serve.sh start [--force]|stop|restart [--force]|status|pin|sync|steps [--reset]|log --step <id> [--follow]|cancel --cell <c>|--step <id>
#   start    Fetch the live root of management, check it, and write it to build/hostsvc/mgmt-root.crt.
#            Run sync. Build build/bin/hostsvc, rotate the log, and run serve with nohup under env -i,
#            with only HOME, PATH, USER, TMPDIR, DOCKER_HOST and the OTEL_* variables. Write the pid file.
#            Wait up to HOSTSVC_SERVE_WAIT seconds (default 10) until the pid owns the port, and
#            the certificate that the port presents has the SHA-256 of the serving log line.
#            Fail when another process holds the port. Do nothing but sync when the process already serves
#            with the current root and a certificate that stays valid for 14 days or more. Restart
#            it when the root differs or the certificate is about to expire. A restart or a new start
#            refuses while a step runs a stage, unless --force.
#            With POC_STEP_ID set, a step runs this command: it never builds, stops or restarts. It runs
#            sync only, and it fails with the restart command when a restart would be needed.
#   stop     End the process of the pid file, but only when its command line is build/bin/hostsvc serve.
#            Send TERM, wait up to HOSTSVC_STOP_WAIT seconds (default 20), then send KILL.
#   restart  Run stop and start, then CELL=management LINK_ONLY=mgmt-api mise run cell:link, so mgmtd
#            gets the new pin. It refuses while a step runs a stage, unless --force.
#   status   Print one JSON line: running, pid, cert_sha256, root_sha256, expires_soon, the last error line
#            of the log, and dev_root_sha256 (the DER SHA-256 of dev-root.crt), keys (the SHA-256 of the
#            bytes of each key in mgmt-keys), spec_revision (the revision in steps/spec.json) and binary_sha256.
#   pin      Print the certificate of the running service as PEM, checked against the serving log line.
#   sync     Write build/hostsvc/dev-root.crt and the keys of build/hostsvc/mgmt-keys. A key counts only after
#            the cross-check: spec.pub must equal mise run mgmt -- pubkey, and next.pub must equal the staged key
#            of mise run mgmt -- status. While mgmtd-0 is not Ready, the files stay and the command fails.
#            No restart: the server reloads the files within 10 seconds.
#   steps    Print the journal as one JSON line (hostsvc ctl steps). --reset resets a corrupt journal.
#   log      Print the log of a step, or follow it (hostsvc ctl log).
#   cancel   Cancel the open step of a cell or the step with an ID at the host service. An answer that no
#            step is open is no failure.
# The service makes a new TLS key at each start. It trusts only the management root that it read at start,
# and it reloads the dev root and the keys when their files change. It runs in its own process group, so a
# Ctrl-C of the task that started it leaves it running.
CELL="${CELL:-management}"
source "$(dirname "$0")/lib.sh"
source "$ROOT/components/lib/peer-root.sh"
source "$ROOT/components/lib/mgmt-key.sh"

dir="$BUILD_ROOT/hostsvc"
bin="$BUILD_ROOT/bin/hostsvc"
pidfile="$dir/serve.pid"
logfile="$dir/serve.log"
rootfile="$dir/mgmt-root.crt"
devrootfile="$dir/dev-root.crt"
keysdir="$dir/mgmt-keys"
stepsdir="$dir/steps"
sockfile="$dir/admin.sock"
: "${HOSTSVC_PORT:?}"
port="$HOSTSVC_PORT"
addr="127.0.0.1:$port"
wait_seconds="${HOSTSVC_SERVE_WAIT:-10}"
stop_seconds="${HOSTSVC_STOP_WAIT:-20}"
# The certificate lives 90 days. A restart 14 days before its end leaves time for the re-link.
soon_seconds=$((14 * 24 * 3600))
SPIRE_TRUST_DOMAIN_MGMT=mgmt.poc.internal
SPIRE_TRUST_DOMAIN_DEV=dev.env.poc.internal

cmd_of() { ps -ww -p "$1" -o command= 2>/dev/null || true; }

# rel <path> prints the path relative to the repository root when it lies under it. The service runs in the
# repository root, and the path of a unix socket must stay under 104 bytes, which an absolute path in a worktree can exceed.
rel() { if [[ "$1" == "$ROOT/"* ]]; then printf '%s\n' "${1#"$ROOT"/}"; else printf '%s\n' "$1"; fi; }

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

# b64_decode_flag prints the flag of this base64 for decoding.
b64_decode_flag() { if printf 'AA==' | base64 -d >/dev/null 2>&1; then echo -d; else echo -D; fi; }

# key_fingerprints prints the SHA-256 of the raw bytes of each key file of mgmt-keys as a JSON array, sorted.
key_fingerprints() {
  local f flag sums=()
  flag="$(b64_decode_flag)"
  for f in "$keysdir"/*.pub; do
    [[ -f "$f" ]] || continue
    sums+=("$(tr -d '[:space:]' <"$f" | base64 "$flag" | shasum -a 256 | cut -d' ' -f1)")
  done
  printf '%s\n' ${sums[@]+"${sums[@]}"} | jq -Rcn '[inputs | select(length > 0)] | sort'
}

# spec_revision prints the revision of the spec in steps/spec.json as JSON, and null when the file is absent or unreadable.
spec_revision() {
  [[ -f "$stepsdir/spec.json" ]] || { echo null; return 0; }
  jq -c '.envelope | fromjson | .payload | @base64d | fromjson | .revision // null' "$stepsdir/spec.json" 2>/dev/null || echo null
}

do_status() {
  local pid running=false soon=false devroot=""
  pid="$(running_pid)"
  if [[ -n "$pid" ]]; then
    running=true
    ! expires_soon || soon=true
  fi
  [[ ! -f "$devrootfile" ]] || devroot="$(pem_der_sha256 <"$devrootfile")"
  jq -nc --argjson running "$running" --arg pid "$pid" --arg cert "$(log_field cert_sha256)" --arg root "$(log_field root_sha256)" \
    --argjson soon "$soon" --arg err "$(last_error)" --arg dev "$devroot" --argjson keys "$(key_fingerprints)" \
    --argjson rev "$(spec_revision)" --arg bin "$(log_field binary_sha256)" \
    '{running: $running, pid: (if $pid == "" then null else ($pid | tonumber) end), cert_sha256: $cert, root_sha256: $root, expires_soon: $soon,
      last_error: $err, dev_root_sha256: $dev, keys: $keys, spec_revision: $rev, binary_sha256: $bin}'
}

do_pin() {
  local pid sha
  pid="$(running_pid)"
  [[ -n "$pid" ]] || die "the host service does not run. Run: mise run hostsvc:serve -- start"
  sha="$(log_field cert_sha256)"
  [[ "$sha" =~ ^[0-9a-f]{64}$ ]] || die "the log $logfile has no serving line with cert_sha256"
  pin_pem "$sha" || die "the certificate on $addr does not have the SHA-256 $sha of the serving line"
}

# write_if_changed <file> <content> <mode> writes the content with a temporary file and a rename, only when the file
# differs. It returns 1 when the file was current.
write_if_changed() {
  local file="$1" content="$2" mode="$3" tmp
  if [[ -f "$file" ]] && [[ "$(cat "$file")" == "$content" ]]; then return 1; fi
  tmp="$(dirname "$file")/.$(basename "$file").tmp.$$"
  (umask 022; printf '%s\n' "$content" >"$tmp")
  chmod "$mode" "$tmp"
  mv -f "$tmp" "$file"
}

# do_sync writes the dev root and the keys of the service after the cross-check. Nothing is written unless every
# value checks. It fails with the reason, and keeps the files, while mgmtd-0 is not Ready.
do_sync() {
  local ready dev_pem spec_pub next_pub changed=()
  ready="$(kubectl --context kind-management -n mgmt-system get pod mgmtd-0 -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null || true)"
  if [[ "$ready" != True ]]; then
    printf 'error: mgmtd-0 is not Ready, so the key files and the dev root of the host service stay as they are. Start mgmtd with: CELL=management LINK_ONLY=mgmt-api mise run cell:link\n' >&2
    return 1
  fi
  # The dev root exists only while dev-cp does. A cell controller handshake fails while the file is absent.
  dev_pem=""
  if kind get clusters 2>/dev/null | grep -qx dev-cp; then
    dev_pem="$(peer_root_pem dev-cp "$SPIRE_TRUST_DOMAIN_DEV")" || return 1
  fi
  spec_pub="$(mgmt_signing_pub)" || return 1
  next_pub="$(mgmt_signing_next_pub)" || return 1
  mkdir -p "$keysdir"
  if [[ -n "$dev_pem" ]]; then
    if write_if_changed "$devrootfile" "$dev_pem" 0644; then changed+=(dev-root.crt); fi
  else
    log "dev-cp does not exist, so the host service has no dev root yet"
  fi
  if write_if_changed "$keysdir/spec.pub" "$spec_pub" 0644; then changed+=(spec.pub); fi
  if [[ -n "$next_pub" ]]; then
    if write_if_changed "$keysdir/next.pub" "$next_pub" 0644; then changed+=(next.pub); fi
  elif [[ -f "$keysdir/next.pub" ]]; then
    rm -f "$keysdir/next.pub"
    changed+=("next.pub removed")
  fi
  if ((${#changed[@]} > 0)); then
    log "synced the host service files: ${changed[*]}"
  else
    log "the host service files are current"
  fi
}

# stage_entries [cell] prints one line "<id> <cell> <state>" for each journal entry that runs a stage: creating,
# admitting or bootstrapping. While the service runs, the journal is read from the service; otherwise from journal.json.
stage_entries() {
  local json jq_filter='[(.steps // [] | .[] | {id, cell, state}), (.entries // [] | .[].status | {id, cell, state})]
    | .[] | select(.state == "creating" or .state == "admitting" or .state == "bootstrapping")
    | select($cell == "" or .cell == $cell) | "\(.id) \(.cell) \(.state)"'
  if [[ -n "$(running_pid)" && -x "$bin" ]]; then
    json="$(cd "$ROOT" && "$bin" ctl steps --admin-socket "$(rel "$sockfile")" 2>/dev/null)" || json=""
    [[ -n "$json" ]] || return 0
  elif [[ -f "$stepsdir/journal.json" ]]; then
    json="$(cat "$stepsdir/journal.json")"
  else
    return 0
  fi
  jq -r --arg cell "${1:-}" "$jq_filter" <<<"$json" 2>/dev/null || true
}

# refuse_during_stage <force> fails while a step runs a stage, unless force is --force.
refuse_during_stage() {
  local running
  [[ "$1" != --force ]] || return 0
  running="$(stage_entries)"
  [[ -z "$running" ]] || die "a step runs a stage: ${running//$'\n'/; }. Wait until it ends, or cancel it with: mise run hostsvc:serve -- cancel --step <id>. To go on anyway, add --force"
}

do_stop() {
  local pid cmd waited
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
  # The service stops its running stage group within 10 seconds, so 20 seconds leave it time to end its stage and exit.
  waited=0
  while kill -0 "$pid" 2>/dev/null; do
    if ((waited >= stop_seconds * 5)); then
      log "process $pid did not stop within ${stop_seconds}s, so it gets KILL"
      kill -9 "$pid" 2>/dev/null || true
      sleep 0.2
      break
    fi
    sleep 0.2
    waited=$((waited + 1))
  done
  if kill -0 "$pid" 2>/dev/null; then die "process $pid did not end after KILL"; fi
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

# sync_tolerant runs sync for start: a mgmtd that is not Ready (a clean harness, when the mgmt-api render starts the
# service) keeps the files and logs the hint. Only the sync command fails for it.
sync_tolerant() {
  do_sync || log "the sync of the host service files failed. After mgmtd runs, run: mise run hostsvc:serve -- sync"
  return 0
}

do_start() {
  local force="" pid holders root_pem want_root why="" nofile end sha name envs
  [[ "${1:-}" != --force ]] || force=--force
  pid="$(running_pid)"
  holders="$(port_holders)"
  if [[ -n "$holders" && "$holders" != "$pid" ]]; then
    die "port $port is held by process $holders ($(cmd_of "${holders%% *}")), and the pid file names ${pid:-no host service}. Stop that process, then run: mise run hostsvc:serve -- start"
  fi
  root_pem="$(peer_root_pem management "$SPIRE_TRUST_DOMAIN_MGMT")" || exit 1
  want_root="$(pem_der_sha256 <<<"$root_pem")"
  [[ "$want_root" =~ ^[0-9a-f]{64}$ ]] || die "could not hash the live management root"
  if [[ -n "${POC_STEP_ID:-}" ]]; then
    # A step runs this command as a child of the service. A restart would end the parent of the stage.
    sync_tolerant
    if [[ -n "$pid" ]]; then why="$(current_state "$pid" "$want_root")"; else why="the host service does not run"; fi
    if [[ -n "$why" ]]; then
      log "the host service needs a restart: $why"
      die "run mise run hostsvc:serve -- restart after step $POC_STEP_ID"
    fi
    log "the host service serves already, process $pid, with the live management root"
    return 0
  fi
  if [[ -n "$pid" ]]; then
    why="$(current_state "$pid" "$want_root")"
    if [[ -z "$why" ]]; then
      sync_tolerant
      log "the host service serves already, process $pid, with the live management root"
      return 0
    fi
    refuse_during_stage "$force"
    log "restarting the host service: $why"
    do_stop
  else
    refuse_during_stage "$force"
  fi
  mkdir -p "$dir" "$stepsdir" "$keysdir" "$(dirname "$bin")"
  # The root is public. The service reads it only at start.
  printf '%s\n' "$root_pem" >"$rootfile.tmp"
  mv "$rootfile.tmp" "$rootfile"
  sync_tolerant
  (cd "$ROOT" && go build -o "$bin" ./cmd/hostsvc) || die "could not build $bin"
  [[ ! -f "$logfile" ]] || mv -f "$logfile" "$logfile.1"
  # serve needs 1104 open files, and the shell of launchd starts with 256.
  ulimit -n 4096 2>/dev/null || true
  nofile="$(ulimit -n)"
  [[ "$nofile" == unlimited || "$nofile" -ge 1104 ]] || die "the limit on open files is $nofile, and the host service needs 1104"
  # The service runs with a fixed list of variables, so no step child reads a secret from this shell.
  envs=("HOME=$HOME" "PATH=$PATH" "USER=${USER:-$(id -un)}" "TMPDIR=${TMPDIR:-/tmp}")
  [[ -z "${DOCKER_HOST:-}" ]] || envs+=("DOCKER_HOST=$DOCKER_HOST")
  for name in $(compgen -e | grep '^OTEL_' || true); do envs+=("$name=${!name}"); done
  # The service runs in the repository root, and each stage child inherits it: hostsvc create reads harness/topology.yaml there.
  cd "$ROOT"
  # Job control gives the service its own process group, so a Ctrl-C of the task that started it does not reach it.
  set -m
  nohup env -i "${envs[@]}" "$bin" serve --listen "$addr" --client-bundle "$rootfile" \
    --step-client-bundle "$(rel "$devrootfile")" --step-keys-dir "$(rel "$keysdir")" --journal-dir "$(rel "$stepsdir")" \
    --repo-root "$ROOT" --admin-socket "$(rel "$sockfile")" >"$logfile" 2>&1 </dev/null &
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

# ctl <command> [args...] runs hostsvc ctl on the admin socket, from the repository root, because the socket path is relative to it.
ctl() {
  [[ -x "$bin" ]] || die "the host service is not built: $bin is missing. Run: mise run hostsvc:serve -- start"
  (cd "$ROOT" && "$bin" ctl "$1" --admin-socket "$(rel "$sockfile")" "${@:2}")
}

do_cancel() {
  local out rc=0
  out="$(ctl cancel "$@")" || rc=$?
  if ((rc != 0)); then
    # A cancel with no open step is the normal state of a cell that has no step, and cell:down goes on.
    if [[ "$out" == *"no open step"* ]]; then
      log "no open step matches ${*}, so there is nothing to cancel"
      return 0
    fi
    printf '%s\n' "$out"
    return "$rc"
  fi
  printf '%s\n' "$out"
}

case "${1:-}" in
  start) shift; do_start "$@" ;;
  stop) do_stop ;;
  restart)
    [[ -z "${POC_STEP_ID:-}" ]] || die "a restart would end the host service that runs step $POC_STEP_ID. Run the restart after the step ends"
    refuse_during_stage "${2:-}"
    do_stop
    do_start --force
    (cd "$ROOT" && CELL=management LINK_ONLY=mgmt-api mise run cell:link)
    ;;
  status) do_status ;;
  pin) do_pin ;;
  sync) do_sync ;;
  steps)
    case "${2:-}" in
      "") ctl steps ;;
      --reset) ctl reset-journal ;;
      *) die "usage: hostsvc-serve.sh steps [--reset]" ;;
    esac ;;
  log) shift; ctl log "$@" ;;
  cancel) shift; do_cancel "$@" ;;
  *) die "usage: hostsvc-serve.sh start [--force]|stop|restart [--force]|status|pin|sync|steps [--reset]|log --step <id> [--follow]|cancel --cell <c>|--step <id>" ;;
esac
