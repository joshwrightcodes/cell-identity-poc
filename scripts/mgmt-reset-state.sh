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
# The script prints one JSON line with the moved files and the next commands. A failure prints one JSON error line on standard output.
# After a failure in step 2 the script scales mgmtd back to 1, and the state is as it was. MGMT_RESET_WAIT bounds each wait in seconds (default 180).
export CELL=management
source "$(dirname "$0")/lib.sh"

wait_seconds="${MGMT_RESET_WAIT:-180}"
[[ "$wait_seconds" =~ ^[0-9]+$ ]] || die "MGMT_RESET_WAIT takes a number of seconds"
ns=mgmt-system
job="mgmtd-reset-state-$(date +%s)"
next=("CELL=dev-cp mise run cell:up" "CELL=management mise run cell:link")

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
pod_gone() { ! k -n "$ns" get pod mgmtd-0 >/dev/null 2>&1; }
pod_ready() { [[ "$(k -n "$ns" get pod mgmtd-0 -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null)" == True ]]; }

# fail <step> <reason> [next command]: print the error line with the step and the command that goes on.
fail() {
  local step="$1" reason="$2" hint="${3:-}"
  json_fail mgmt-reset-state "$reason" step="$step" next="$hint"
}

image="$(k -n "$ns" get statefulset mgmtd -o jsonpath='{.spec.template.spec.containers[?(@.name=="mgmtd")].image}' 2>/dev/null)" || image=""
[[ -n "$image" ]] || fail read-image "could not read the mgmtd image from StatefulSet mgmtd. Run: CELL=management LINK_ONLY=mgmt-api mise run cell:link"

log "scale mgmtd to 0"
scale 0 || fail scale-down "could not scale mgmtd to 0" "mise x -- kubectl --context kind-$CELL_NAME -n $ns get statefulset mgmtd"
poll "$wait_seconds" pod_gone ||
  fail wait-stop "mgmtd-0 did not stop. mgmtd is scaled to 0" "scripts/harness-replicas.sh $CELL_NAME $ns statefulset/mgmtd 1"

log "move the state and the key aside with Job $job"
restore() { scale 1 || true; }
kubectl --context "kind-$CELL_NAME" -n "$ns" create -f - >/dev/null <<YAML || { restore; fail create-job "could not create the Job. mgmtd is scaled back to 1"; }
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
    restore
    fail run-job "the Job did not finish in ${wait_seconds}s. mgmtd is scaled back to 1"
  fi
  sleep 2
done
result="$(k -n "$ns" logs "job/$job" 2>/dev/null | tail -n 1)"
succeeded="$(job_state)"
k -n "$ns" delete job "$job" --ignore-not-found >/dev/null 2>&1 || true
if [[ "$succeeded" != 1/* ]]; then
  restore
  fail run-job "the Job failed: ${result:-no output}. mgmtd is scaled back to 1"
fi
moved="$(jq -ce '.moved' <<<"$result")" || { restore; fail run-job "the Job printed no moved list: ${result:-no output}. mgmtd is scaled back to 1"; }

log "scale mgmtd to 1"
scale 1 || fail scale-up "could not scale mgmtd to 1. The state moved aside" "scripts/harness-replicas.sh $CELL_NAME $ns statefulset/mgmtd 1"
poll "$wait_seconds" pod_ready ||
  fail wait-ready "mgmtd-0 is not Ready. The state moved aside. Read: mise x -- kubectl --context kind-$CELL_NAME -n $ns logs mgmtd-0 -c mgmtd"

jq -nc --argjson moved "$moved" --arg c1 "${next[0]}" --arg c2 "${next[1]}" '{reset: true, moved: $moved, next: [$c1, $c2]}'
