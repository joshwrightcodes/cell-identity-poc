#!/usr/bin/env bash
# Start the management plane with a fresh state and a new signing key: mise run mgmt -- reset-state.
# Use it when mgmtd refuses to start with state_invalid, or after a lost state. The image has no shell, so the move runs as a Job.
# The steps run in this order:
#   1. Scale mgmtd to 0 and wait until mgmtd-0 is gone.
#   2. Run a one-shot Job with the mgmtd image. Its command mgmtd reset-state renames state.json and ed25519.key on the volume to
#      <name>.reset-<unix time>. It deletes nothing.
#   3. Delete the Job and scale mgmtd to 1.
#   4. Wait until mgmtd-0 is Ready.
# A fresh state starts with a new key, so the plugin of the SPIRE server of dev-cp starts its marks again.
# The script prints one JSON line with the moved files and the next commands: the cell:up of dev-cp, the cell:up of each cell
# of SPIRE_AGENT_CELLS, and the full link of management. A failure prints one JSON error line on standard output.
# After a failure in step 2, and after an interrupt, the script scales mgmtd back to 1. The Job can have moved one file before it failed,
# so the files can be partly moved. Read the moved list in the Job output, or run: mise run mgmt -- status.
# MGMT_RESET_WAIT bounds each wait in seconds (default 180).
export CELL=management
source "$(dirname "$0")/lib.sh"

wait_seconds="${MGMT_RESET_WAIT:-180}"
[[ "$wait_seconds" =~ ^[0-9]+$ ]] || json_fail mgmt-reset-state "MGMT_RESET_WAIT takes a number of seconds" step=read-wait next=""
ns=mgmt-system
job="mgmtd-reset-state-$(date +%s)"
# After a reset the signing key is new, and the ConfigMap mgmt-op-key of each cell holds the old one. Each cell:up pins the
# new key. They come after the cell:up of dev-cp, which pins the key in the gateway, and before the full link.
next=("CELL=dev-cp mise run cell:up")
# The cells are the ones that dev-cp lists in SPIRE_AGENT_CELLS, as dependents_of reads them.
agent_cells="$(sed -n 's/^SPIRE_AGENT_CELLS="\(.*\)"$/\1/p' "$ROOT/cells/dev-cp.env")"
for cell in $agent_cells; do next+=("CELL=$cell mise run cell:up"); done
next+=("CELL=management mise run cell:link")

scale() { "$ROOT/scripts/harness-replicas.sh" "$CELL_NAME" "$ns" statefulset/mgmtd "$1" >/dev/null; }

# poll <seconds> <command...> runs the command every 2 seconds until it succeeds, and returns 1 at the end of the time.
poll() {
  local end=$((SECONDS + $1))
  shift
  until "$@" >/dev/null 2>&1; do
    ((SECONDS < end)) || return 1
    sleep 2
  done
}
# pod_gone is true only when kubectl answers and reports no pod. Any other kubectl error means the state is unknown.
pod_gone() {
  local out
  out="$(k -n "$ns" get pod mgmtd-0 --ignore-not-found -o name 2>/dev/null)" || return 1
  [[ -z "$out" ]]
}
pod_ready() { [[ "$(k -n "$ns" get pod mgmtd-0 -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null)" == True ]]; }

# down is 1 while the script holds mgmtd at 0. The EXIT trap scales it back, so an interrupt or an error cannot leave it there.
down=0 job_created=0 restore_msg=""
restore() {
  if scale 1; then
    down=0
    restore_msg="mgmtd is scaled back to 1"
  else
    restore_msg="could not scale mgmtd back to 1. Run: mise run gate:m4:repair"
  fi
}
cleanup() {
  trap - EXIT
  if ((job_created)); then k -n "$ns" delete job "$job" --ignore-not-found >/dev/null 2>&1 || true; fi
  if ((down)); then scale 1 || true; fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# fail <step> <reason> [next command]: print the error line with the step and the command that goes on.
fail() {
  local step="$1" reason="$2" hint="${3:-}"
  json_fail mgmt-reset-state "$reason" step="$step" next="$hint"
}

image="$(k -n "$ns" get statefulset mgmtd -o jsonpath='{.spec.template.spec.containers[?(@.name=="mgmtd")].image}' 2>/dev/null)" || image=""
[[ -n "$image" ]] || fail read-image "could not read the mgmtd image from StatefulSet mgmtd. Run: CELL=management LINK_ONLY=mgmt-api mise run cell:link"

log "scale mgmtd to 0"
down=1
scale 0 || { restore; fail scale-down "could not scale mgmtd to 0. $restore_msg" "mise run harness:status"; }
poll "$wait_seconds" pod_gone || { restore; fail wait-stop "mgmtd-0 did not stop in ${wait_seconds}s. Nothing moved. $restore_msg" "mise run harness:status"; }

log "move the state and the key aside with Job $job"
job_created=1
kubectl --context "kind-$CELL_NAME" -n "$ns" create -f - >/dev/null <<YAML || { restore; fail create-job "could not create the Job. $restore_msg"; }
apiVersion: batch/v1
kind: Job
metadata:
  name: $job
  namespace: $ns
  labels:
    app.kubernetes.io/name: mgmtd-reset-state
spec:
  backoffLimit: 0
  ttlSecondsAfterFinished: 600
  template:
    metadata:
      labels:
        app.kubernetes.io/name: mgmtd-reset-state
    spec:
      restartPolicy: Never
      automountServiceAccountToken: false
      securityContext:
        runAsNonRoot: true
        runAsUser: 65532
        runAsGroup: 65532
        fsGroup: 65532
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: reset
          image: "$image"
          args: [reset-state, --data-dir=/var/lib/mgmtd]
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop: [ALL]
          volumeMounts:
            - name: state
              mountPath: /var/lib/mgmtd
      volumes:
        - name: state
          persistentVolumeClaim:
            claimName: state-mgmtd-0
YAML

job_state() { k -n "$ns" get job "$job" -o jsonpath='{.status.succeeded}/{.status.failed}' 2>/dev/null || true; }
end=$((SECONDS + wait_seconds))
until [[ "$(job_state)" == 1/* || "$(job_state)" == */1 ]]; do
  if ((SECONDS >= end)); then
    k -n "$ns" delete job "$job" --ignore-not-found >/dev/null 2>&1 || true
    job_created=0
    restore
    fail run-job "the Job did not finish in ${wait_seconds}s. The files can be partly moved. $restore_msg" "mise run mgmt -- status"
  fi
  sleep 2
done
result="$(k -n "$ns" logs "job/$job" 2>/dev/null | tail -n 1)"
succeeded="$(job_state)"
k -n "$ns" delete job "$job" --ignore-not-found >/dev/null 2>&1 || true
job_created=0
if [[ "$succeeded" != 1/* ]]; then
  restore
  fail run-job "the Job failed: ${result:-no output}. The files can be partly moved. $restore_msg" "mise run mgmt -- status"
fi
moved="$(jq -ce '.moved' <<<"$result")" || { restore; fail run-job "the Job printed no moved list: ${result:-no output}. $restore_msg" "mise run mgmt -- status"; }

log "scale mgmtd to 1"
scale 1 || fail scale-up "could not scale mgmtd to 1. The state moved aside" "mise run gate:m4:repair"
down=0
poll "$wait_seconds" pod_ready ||
  fail wait-ready "mgmtd-0 is not Ready. The state moved aside" "mise run harness:status"

printf '%s\n' "${next[@]}" | jq -Rnc --argjson moved "$moved" '{reset: true, moved: $moved, next: [inputs]}'
