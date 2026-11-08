#!/usr/bin/env bash
# Connect the External Secrets Operator in the cluster $CELL to the secret manager.
# Two settings come from the gitignored .envrc.local. .envrc.local.example shows the form.
#   POC_SECRET_TOKEN_CMD       a command that prints the read-only access token on standard output
#   POC_SECRET_STORE_PROVIDER  the provider block of the ClusterSecretStore, as JSON
# The script applies Secret poc-secrets-token (key token) in external-secrets, then
# ClusterSecretStore poc-secrets. Only the namespaces in SECRET_STORE_NAMESPACES from
# cells/$CELL.env may use the store. Last, it forces a sync of each ExternalSecret there that uses
# the store, and waits until each target Secret exists. The token stays in memory and reaches kubectl through a pipe.
# These two objects live outside every bundle, so Argo CD never prunes them.
source "$(dirname "$0")/lib.sh"

namespace=external-secrets
secret=poc-secrets-token
store=poc-secrets
example="Copy .envrc.local.example to .envrc.local and complete it"

[[ -n "${POC_SECRET_TOKEN_CMD:-}" ]] || die "POC_SECRET_TOKEN_CMD is not set. $example."
[[ -n "${POC_SECRET_STORE_PROVIDER:-}" ]] || die "POC_SECRET_STORE_PROVIDER is not set. $example."
jq -e 'type == "object"' <<<"$POC_SECRET_STORE_PROVIDER" >/dev/null 2>&1 \
  || die "POC_SECRET_STORE_PROVIDER is not a JSON object"
jq -e 'length == 1 and (.[] | type == "object")' <<<"$POC_SECRET_STORE_PROVIDER" >/dev/null \
  || die "POC_SECRET_STORE_PROVIDER must hold exactly one provider block"
jq -e --arg name "$secret" --arg ns "$namespace" \
  '[.. | objects | select(.name == $name and .key == "token" and .namespace == $ns)] | length > 0' \
  <<<"$POC_SECRET_STORE_PROVIDER" >/dev/null \
  || die "POC_SECRET_STORE_PROVIDER must refer to key token of Secret $secret in namespace $namespace"
store_namespaces="${SECRET_STORE_NAMESPACES:-}"
[[ -n "${store_namespaces// /}" ]] || die "cells/$CELL.env sets no SECRET_STORE_NAMESPACES"

if ! k get crd clustersecretstores.external-secrets.io >/dev/null 2>&1 \
  || ! k -n "$namespace" get deployment external-secrets >/dev/null 2>&1; then
  die "the External Secrets Operator is not installed in kind-$CELL_NAME. Run CELL=$CELL mise run cell:up first."
fi

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

# printf is a shell builtin, so the token appears in no process argument list.
printf '%s' "$token" | jq -Rs --arg name "$secret" --arg ns "$namespace" '{
    apiVersion: "v1", kind: "Secret", type: "Opaque",
    metadata: {name: $name, namespace: $ns},
    data: {token: @base64}
  }' | apply "Secret $secret in $namespace"
log "applied Secret $secret in $namespace"

# A new annotation value changes the resource version. The provider keeps one client for each
# version of the store, so the next sync uses the new token.
jq -n --argjson provider "$POC_SECRET_STORE_PROVIDER" --arg name "$store" \
  --arg at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --arg namespaces "$store_namespaces" '{
    apiVersion: "external-secrets.io/v1", kind: "ClusterSecretStore",
    metadata: {name: $name, annotations: {"cell.poc.internal/connected-at": $at}},
    spec: {
      provider: $provider,
      conditions: [{namespaces: ($namespaces | split(" ") | map(select(. != "")))}]
    }
  }' | apply "ClusterSecretStore $store"
log "applied ClusterSecretStore $store"

if ! k wait --for=condition=Ready "clustersecretstore/$store" --timeout=60s >/dev/null 2>&1; then
  reason="$(k get clustersecretstore "$store" -o jsonpath='{.status.conditions[?(@.type=="Ready")].message}' 2>&1 || true)"
  die "ClusterSecretStore $store is not Ready after 60s: $(redact "${reason:-no condition}")"
fi
log "ClusterSecretStore $store is Ready"

# An ExternalSecret that failed before the store existed waits out its retry backoff. A new
# force-sync value makes ESO sync it now. Each ExternalSecret must then report Ready with a refresh
# time at or after the force sync, and its target Secret must exist, in a bounded time.
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
    | select(.spec.secretStoreRef.kind == "ClusterSecretStore" and .spec.secretStoreRef.name == $store)
    | "\(.metadata.name) \(.spec.target.name // .metadata.name)"' <<<"$list")
  ((found)) || log "no ExternalSecret in $ns uses ClusterSecretStore $store"
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
