#!/usr/bin/env bash
# Start the sidecars of the cluster $CELL again, so each one carries the cluster ID of its cell.
# Istiod rejects a sidecar whose cluster ID differs from its own, and a sidecar that started before
# global.multiCluster.clusterName was set holds the default ID Kubernetes.
#
# The script deletes the pods of every Deployment in each namespace with istio-injection=enabled
# (apps-demo and istio-egress), and waits for new Ready pods. Argo CD tracks these Deployments, and
# kubectl rollout restart would write a pod template annotation that then differs from the bundle.
# Last, it reads ISTIO_META_CLUSTER_ID from the istio-proxy container of every live pod in these
# namespaces, and fails when one differs from the cluster name.
# Standard output holds one JSON line on success, with the cluster, the restarted Deployments and
# the cluster IDs found. A failure prints one JSON error line and exits with status 1.
source "$(dirname "$0")/lib.sh"

injected="$(k get namespaces -l istio-injection=enabled -o jsonpath='{.items[*].metadata.name}')" \
  || json_fail cell:restart-mesh "could not list the injected namespaces of $CELL_NAME" cluster="$CELL_NAME"
[[ -n "$injected" ]] || json_fail cell:restart-mesh "no namespace of $CELL_NAME has istio-injection=enabled" cluster="$CELL_NAME"

restarted=()
for ns in $injected; do
  deployments="$(k -n "$ns" get deployments -o jsonpath='{.items[*].metadata.name}')" \
    || json_fail cell:restart-mesh "could not list the Deployments in $ns" cluster="$CELL_NAME"
  for name in $deployments; do
    selector="$(k -n "$ns" get deployment "$name" -o json | jq -r '.spec.selector.matchLabels | to_entries | map("\(.key)=\(.value)") | join(",")')" \
      || json_fail cell:restart-mesh "could not read deployment/$name in $ns" cluster="$CELL_NAME"
    [[ -n "$selector" ]] || json_fail cell:restart-mesh "deployment/$name in $ns has no label selector" cluster="$CELL_NAME"
    old="$(k -n "$ns" get pods -l "$selector" -o jsonpath='{.items[*].metadata.uid}')"
    k -n "$ns" delete pods -l "$selector" --wait=true --timeout=120s >/dev/null \
      || json_fail cell:restart-mesh "could not delete the pods of deployment/$name in $ns" cluster="$CELL_NAME"
    end=$((SECONDS + 300))
    until uids="$(new_ready_pods "$ns" "$selector" "$old")" && [[ -n "$uids" ]]; do
      ((SECONDS < end)) || json_fail cell:restart-mesh "deployment/$name in $ns has no new Ready pod after 300s" cluster="$CELL_NAME" \
        hint="mise x -- kubectl --context kind-$CELL_NAME -n $ns describe deployment/$name"
      sleep 2
    done
    k -n "$ns" rollout status "deployment/$name" --timeout=300s >&2 \
      || json_fail cell:restart-mesh "deployment/$name in $ns did not finish its rollout" cluster="$CELL_NAME"
    log "restarted deployment/$name in $ns"
    restarted+=("$ns/$name")
  done
done

ids=() bad=()
for ns in $injected; do
  pods="$(k -n "$ns" get pods -o json)" || json_fail cell:restart-mesh "could not list the pods in $ns" cluster="$CELL_NAME"
  while IFS=$'\t' read -r pod id; do
    [[ -n "$pod" ]] || continue
    ids+=("$id")
    [[ "$id" == "$CELL_NAME" ]] || bad+=("$ns/$pod=$id")
  done < <(jq -r '.items[] | select(.metadata.deletionTimestamp == null)
    | .metadata.name as $pod
    | ((.spec.initContainers // []) + .spec.containers)[] | select(.name == "istio-proxy")
    | [$pod, ([.env[]? | select(.name == "ISTIO_META_CLUSTER_ID") | .value][0] // "none")] | @tsv' <<<"$pods")
done
((${#bad[@]} == 0)) || json_fail cell:restart-mesh "a sidecar has a cluster ID other than $CELL_NAME: ${bad[*]}" cluster="$CELL_NAME" \
  hint="check global.multiCluster.clusterName in components/istiod/values.yaml, run CELL=$CELL_NAME mise run cell:up, then run this task again"
((${#ids[@]} > 0)) || json_fail cell:restart-mesh "no pod of $CELL_NAME has an istio-proxy container" cluster="$CELL_NAME"

jq -nc --arg cluster "$CELL_NAME" --argjson restarted "$(printf '%s\n' "${restarted[@]}" | jq -Rcn '[inputs]')" \
  --argjson ids "$(printf '%s\n' "${ids[@]}" | jq -Rcn '[inputs] | unique')" --argjson proxies "${#ids[@]}" \
  '{cluster: $cluster, restarted: $restarted, proxies: $proxies, cluster_ids: $ids}'
