#!/usr/bin/env bash
# Print the admission policies that keep Argo CD away from the harness of a cluster with a bundle role, as one JSON
# document after the other, separated by lines of ---. The harness applies them outside every Application.
#
#   bundle-guard.sh <role>     role cell or cp (components/lib/bundle-role.sh)
#
# ValidatingAdmissionPolicy bundles-spare-harness (role cell and role cp, resources and subresources) denies each request of the application
# controller of Argo CD that creates, changes or deletes an object in a harness namespace of the role, that touches an
# object whose old version carries the label cell.poc.internal/harness, or that gives an object the label.
# ValidatingAdmissionPolicy bundles-app-limits (role cell only) denies, for an object whose tracking ID starts with the
# name of an app component, a Service that is not ClusterIP or has externalIPs, a Deployment with the sidecar opt-out,
# and an object with the harness label.
# The namespaces and the app components come from internal/bundle/allow.json, so the guards and the apply engine read one list.
# BUNDLE_ALLOW_JSON names another allow-list file, for the tests.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
allow="${BUNDLE_ALLOW_JSON:-$here/../../internal/bundle/allow.json}"
role="${1:-}"
case "$role" in
  cell | cp) ;;
  open) echo "error: bundle-guard: role open has no signed bundle sets, so it has no guard" >&2; exit 1 ;;
  *) echo "usage: bundle-guard.sh cell|cp" >&2; exit 1 ;;
esac

# jq builds the texts. $q is the single quote of a CEL string, because the program itself sits in single quotes.
docs="$(jq -c --arg role "$role" --arg q "'" '
  def s($x): $q + $x + $q;
  def celist: "[" + (map(s(.)) | join(", ")) + "]";
  def policy($name; $constraints; $conditions; $validations):
    {apiVersion: "admissionregistration.k8s.io/v1", kind: "ValidatingAdmissionPolicy", metadata: {name: $name},
     spec: {failurePolicy: "Fail", matchConstraints: {resourceRules: [$constraints]}, matchConditions: $conditions,
            validations: ($validations | map(. + {reason: "Forbidden"}))}},
    {apiVersion: "admissionregistration.k8s.io/v1", kind: "ValidatingAdmissionPolicyBinding", metadata: {name: $name},
     spec: {policyName: $name, validationActions: ["Deny"]}};
  def optout($field):
    "object.spec.template.metadata.\($field)" as $m
    | "(has(\($m)) && \(s("sidecar.istio.io/inject")) in \($m) && \($m)[\(s("sidecar.istio.io/inject"))].lowerAscii() in \(["false", "n", "no", "off"] | celist))";
  .roles[$role] as $r
  | s("cell.poc.internal/harness") as $label
  | s("argocd.argoproj.io/tracking-id") as $track
  | {name: "argocd-controller", expression: "request.userInfo.username == \(s("system:serviceaccount:argocd:argocd-application-controller"))"} as $ctl
  | policy("bundles-spare-harness";
      {apiGroups: ["*"], apiVersions: ["*"], operations: ["CREATE", "UPDATE", "DELETE"], resources: ["*/*"], scope: "*"};
      [$ctl];
      [{expression: "!(request.namespace in \($r.harnessNamespaces | celist))", message: "Argo CD may not change an object in a harness namespace"},
       {expression: "oldObject == null || !has(oldObject.metadata.labels) || !(\($label) in oldObject.metadata.labels)", message: "Argo CD may not change or delete an object that carries the harness label"},
       {expression: "object == null || !has(object.metadata.labels) || !(\($label) in object.metadata.labels)", message: "Argo CD may not give an object the harness label"}]),
    (if $role == "cell" then
      policy("bundles-app-limits";
        {apiGroups: ["*"], apiVersions: ["*"], operations: ["CREATE", "UPDATE"], resources: ["*"], scope: "*"};
        [$ctl, {name: "app-component", expression: "object != null && has(object.metadata.annotations) && \($track) in object.metadata.annotations && (\($r.appComponents | map("object.metadata.annotations[\($track)].startsWith(\(s(. + ":")))") | join(" || ")))"}];
        [{expression: "object.kind != \(s("Service")) || ((!has(object.spec.type) || object.spec.type == \(s("ClusterIP"))) && (!has(object.spec.externalIPs) || size(object.spec.externalIPs) == 0))", message: "An app component may create only a Service of type ClusterIP with no externalIPs"},
         {expression: "object.kind != \(s("Deployment")) || !(has(object.spec.template.metadata) && (\(optout("labels")) || \(optout("annotations"))))", message: "An app component may not opt a Deployment out of the sidecar"},
         {expression: "!has(object.metadata.labels) || !(\($label) in object.metadata.labels)", message: "An app component may not create an object with the harness label"}])
    else empty end)
' "$allow")" || { echo "error: bundle-guard: could not read $allow" >&2; exit 1; }

first=1
while IFS= read -r doc; do
  ((first)) || echo "---"
  first=0
  printf '%s\n' "$doc"
done <<<"$docs"
