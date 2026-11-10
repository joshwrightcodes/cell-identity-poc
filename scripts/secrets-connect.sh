#!/usr/bin/env bash
# Connect the External Secrets Operator in the cluster $CELL to the secret manager.
# Two settings come from the gitignored .envrc.local. .envrc.local.example shows the form.
#   POC_SECRET_TOKEN_CMD       a command that prints the read-only access token on standard output
#   POC_SECRET_STORE_PROVIDER  the provider block of the SecretStore, as JSON
# direnv loads .envrc.local. When a setting is still unset, the script reads the file itself.
# For each namespace in SECRET_STORE_NAMESPACES from cells/$CELL.env, the script applies Secret
# poc-secrets-token (key token), then SecretStore poc-secrets. A namespaced store reads the token
# only in its own namespace, so each namespace gets its own copy. Last, it forces a sync of each
# ExternalSecret there that uses the store, and waits until each target Secret exists.
# The token stays in memory and reaches kubectl through a pipe.
# These objects live outside every bundle, so Argo CD never prunes them.
source "$(dirname "$0")/lib.sh"

secret=poc-secrets-token
store="$SECRET_STORE"
example="Copy .envrc.local.example to .envrc.local and complete it"

# The cluster must hold a store namespace. Name the clusters that do.
store_namespaces="${SECRET_STORE_NAMESPACES:-}"
if [[ -z "${store_namespaces// /}" ]]; then
  with_store="$(cd "$ROOT/cells" && grep -l '^SECRET_STORE_NAMESPACES=' -- *.env | sed 's/\.env$//' | paste -sd' ' -)"
  die "cells/$CELL.env sets no SECRET_STORE_NAMESPACES, so $CELL has no secret store. Run: CELL=${with_store%% *} mise run secrets:connect"
fi

load_local_settings POC_SECRET_TOKEN_CMD POC_SECRET_STORE_PROVIDER
unset_hint="direnv loads .envrc.local after you run direnv allow, and this script reads it when a setting is unset"
[[ -n "${POC_SECRET_TOKEN_CMD:-}" ]] || die "POC_SECRET_TOKEN_CMD is not set. $example. $unset_hint."
[[ -n "${POC_SECRET_STORE_PROVIDER:-}" ]] || die "POC_SECRET_STORE_PROVIDER is not set. $example. $unset_hint."
jq -e 'type == "object"' <<<"$POC_SECRET_STORE_PROVIDER" >/dev/null 2>&1 \
  || die "POC_SECRET_STORE_PROVIDER is not a JSON object"
jq -e 'length == 1 and (.[] | type == "object")' <<<"$POC_SECRET_STORE_PROVIDER" >/dev/null \
  || die "POC_SECRET_STORE_PROVIDER must hold exactly one provider block"
jq -e --arg name "$secret" '[.. | objects | select(.name == $name and .key == "token")] | length > 0' \
  <<<"$POC_SECRET_STORE_PROVIDER" >/dev/null \
  || die "POC_SECRET_STORE_PROVIDER must refer to key token of Secret $secret"
# A namespaced store reads the token Secret in its own namespace, so a namespace in the reference
# has no use.
provider="$(jq -c --arg name "$secret" '(.. | objects | select(.name == $name and .key == "token")) |= del(.namespace)' \
  <<<"$POC_SECRET_STORE_PROVIDER")"

kubectl config get-contexts "kind-$CELL_NAME" -o name >/dev/null 2>&1 \
  || die "kubeconfig has no context kind-$CELL_NAME, so the cluster does not exist. Run: CELL=$CELL mise run cell:up"

# In a second shell during cell:up, the operator can still be on its way. Wait for its CRD and for
# the rollout of the controller that is scoped to the store namespace, for up to
# SECRETS_CONNECT_ESO_WAIT seconds. A controller of an older bundle ignores SecretStore objects.
eso_wait="${SECRETS_CONNECT_ESO_WAIT:-300}"
eso_ready() {
  k get crd secretstores.external-secrets.io >/dev/null 2>&1 && eso_controller_rolled_out
}
end=$((SECONDS + eso_wait))
until eso_ready; do
  if ((SECONDS >= end)); then
    log "check the operator: mise x -- kubectl --context kind-$CELL_NAME -n argocd-apps get application external-secrets"
    die "the External Secrets Operator in kind-$CELL_NAME has no rolled-out controller scoped to ${store_namespaces%% *} after ${eso_wait}s. Run CELL=$CELL mise run secrets:connect again when it is Healthy."
  fi
  sleep 5
done

# The command runs in a child shell. Its standard error still reaches the terminal.
token="$(bash -c "$POC_SECRET_TOKEN_CMD")" || die "POC_SECRET_TOKEN_CMD failed"
[[ -n "$token" ]] || die "POC_SECRET_TOKEN_CMD printed no token"
encoded="$(printf '%s' "$token" | base64 | tr -d '\n')"

# redact <text> prints the text without the token, in clear or in base64.
redact() {
  local text="${1//"$token"/<redacted>}"
  printf '%s' "${text//"$encoded"/<redacted>}"
}

# apply <what> applies the manifest on standard input. Server-side apply stores no copy of the
# manifest in an annotation.
apply() {
  local out
  out="$(k apply --server-side --field-manager=secrets-connect -f - 2>&1)" || die "could not apply $1: $(redact "$out")"
}

connected_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
for ns in $store_namespaces; do
  # printf is a shell builtin, so the token appears in no process argument list.
  printf '%s' "$token" | jq -Rs --arg name "$secret" --arg ns "$ns" '{
      apiVersion: "v1", kind: "Secret", type: "Opaque",
      metadata: {name: $name, namespace: $ns},
      data: {token: @base64}
    }' | apply "Secret $secret in $ns"
  log "applied Secret $secret in $ns"

  # A new annotation value changes the resource version. The provider keeps one client for each
  # version of the store, so the next sync uses the new token.
  jq -n --argjson provider "$provider" --arg name "$store" --arg ns "$ns" --arg at "$connected_at" '{
      apiVersion: "external-secrets.io/v1", kind: "SecretStore",
      metadata: {name: $name, namespace: $ns, annotations: {"cell.poc.internal/connected-at": $at}},
      spec: {provider: $provider}
    }' | apply "SecretStore $store in $ns"
  log "applied SecretStore $store in $ns"

  if ! k -n "$ns" wait --for=condition=Ready "secretstore/$store" --timeout=60s >/dev/null 2>&1; then
    reason="$(k -n "$ns" get secretstore "$store" -o jsonpath='{.status.conditions[?(@.type=="Ready")].message}' 2>&1 || true)"
    die "SecretStore $ns/$store is not Ready after 60s: $(redact "${reason:-no condition}")"
  fi
  log "SecretStore $ns/$store is Ready"
done

# An ExternalSecret that failed before the store existed waits out its retry backoff. A new
# force-sync value makes ESO sync it now. Each ExternalSecret must then report Ready with a refresh
# time at or after the force sync, and its target Secret must exist, within SECRETS_CONNECT_SYNC_WAIT
# seconds.
sync_wait="${SECRETS_CONNECT_SYNC_WAIT:-120}"
at="$(date +%s)"
targets=()
for ns in $store_namespaces; do
  list="$(k -n "$ns" get externalsecrets.external-secrets.io -o json)" || die "could not list the ExternalSecrets in $ns"
  found=0
  while read -r es target; do
    [[ -n "$es" ]] || continue
    found=1
    k -n "$ns" annotate externalsecret "$es" "force-sync=$at" --overwrite >/dev/null \
      || die "could not force a sync of ExternalSecret $ns/$es"
    log "forced a sync of ExternalSecret $ns/$es"
    targets+=("$ns/$es/$target")
  done < <(jq -r --arg store "$store" '.items[]
    | select(.spec.secretStoreRef.kind == "SecretStore" and .spec.secretStoreRef.name == $store)
    | "\(.metadata.name) \(.spec.target.name // .metadata.name)"' <<<"$list")
  ((found)) || log "no ExternalSecret in $ns uses SecretStore $store"
done

# synced <namespace> <ExternalSecret> succeeds when the ExternalSecret is Ready and refreshed at or
# after the force sync.
synced() {
  k -n "$1" get externalsecret "$2" -o json 2>/dev/null | jq -e --argjson at "$at" '
    any(.status.conditions[]?; .type == "Ready" and .status == "True")
    and ((.status.refreshTime // "1970-01-01T00:00:00Z") | fromdateiso8601) >= $at' >/dev/null
}
for entry in ${targets[@]+"${targets[@]}"}; do
  IFS=/ read -r ns es target <<<"$entry"
  end=$((SECONDS + sync_wait))
  until synced "$ns" "$es" && k -n "$ns" get secret "$target" >/dev/null 2>&1; do
    if ((SECONDS >= end)); then
      reason="$(k -n "$ns" get externalsecret "$es" -o json 2>/dev/null \
        | jq -r '"refreshTime \(.status.refreshTime // "none"), Ready: \([.status.conditions[]? | select(.type == "Ready") | .message] | join("; "))"' || true)"
      die "ExternalSecret $ns/$es did not sync within ${sync_wait}s of the force sync, or Secret $ns/$target is missing: $(redact "${reason:-no status}")"
    fi
    sleep 2
  done
  log "ExternalSecret $ns/$es synced, and Secret $ns/$target exists"
done
