# Bundle object policy. Input: one decoded object. Data: data.allow (allow.json), data.context
# ({"role","component"}), data.harness ({"networkPolicies":[{"namespace","name"}]}), the optional
# data.scope ({"cluster":[group/Kind],"namespaced":[group/Kind]}) with the scope of custom kinds, and
# the optional data.serviceAccounts ([{"namespace","name"}]) with the ServiceAccounts that the checked
# component declares.
package bundle.allow

harness_label_key := "cell.poc.internal/harness"

inject_key := "sidecar.istio.io/inject"

# Istio opts a pod out only for the exact value false. The policy also refuses n, no and off in any
# case, as a chosen stricter rule.
opt_out_values := {"false", "n", "no", "off"}

# Keys that move pod traffic past the sidecar or change how the sidecar intercepts it. The policy
# refuses each of them with any value: every key under traffic.sidecar.istio.io/, and the two below,
# compared in lower case.
traffic_prefix := "traffic.sidecar.istio.io"

intercept_keys := {"sidecar.istio.io/interceptionmode", "proxy.istio.io/config"}

sa_token_type := "kubernetes.io/service-account-token"

# The pod fields that name the ServiceAccount of a pod. serviceAccount is the deprecated alias.
account_fields := ["serviceAccountName", "serviceAccount"]

# Kinds that are cluster scoped. A class must name each of them, with its group, in clusterKinds.
builtin_cluster := {
	"Namespace", "Node", "PersistentVolume",
	"apiextensions.k8s.io/CustomResourceDefinition",
	"apiregistration.k8s.io/APIService",
	"rbac.authorization.k8s.io/ClusterRole",
	"rbac.authorization.k8s.io/ClusterRoleBinding",
	"admissionregistration.k8s.io/ValidatingWebhookConfiguration",
	"admissionregistration.k8s.io/MutatingWebhookConfiguration",
	"admissionregistration.k8s.io/ValidatingAdmissionPolicy",
	"admissionregistration.k8s.io/ValidatingAdmissionPolicyBinding",
	"admissionregistration.k8s.io/MutatingAdmissionPolicy",
	"admissionregistration.k8s.io/MutatingAdmissionPolicyBinding",
	"storage.k8s.io/StorageClass", "storage.k8s.io/CSIDriver", "storage.k8s.io/CSINode",
	"storage.k8s.io/VolumeAttachment", "storage.k8s.io/VolumeAttributesClass",
	"scheduling.k8s.io/PriorityClass", "node.k8s.io/RuntimeClass",
	"certificates.k8s.io/CertificateSigningRequest", "certificates.k8s.io/ClusterTrustBundle",
	"flowcontrol.apiserver.k8s.io/FlowSchema", "flowcontrol.apiserver.k8s.io/PriorityLevelConfiguration",
	"networking.k8s.io/IngressClass", "networking.k8s.io/IPAddress", "networking.k8s.io/ServiceCIDR",
	"resource.k8s.io/DeviceClass", "resource.k8s.io/ResourceSlice",
	"policy.networking.k8s.io/AdminNetworkPolicy",
	"policy.networking.k8s.io/BaselineAdminNetworkPolicy",
	"policy.networking.k8s.io/ClusterNetworkPolicy",
	"gateway.networking.k8s.io/GatewayClass",
	"external-secrets.io/ClusterSecretStore", "external-secrets.io/ClusterExternalSecret",
	"external-secrets.io/ClusterPushSecret", "generators.external-secrets.io/ClusterGenerator",
	"authentication.k8s.io/TokenReview", "authorization.k8s.io/SubjectAccessReview",
	"authorization.k8s.io/SelfSubjectAccessReview", "authorization.k8s.io/SelfSubjectRulesReview",
}

# Namespaced kinds of the core group, and the groups whose kinds are namespaced once the cluster
# kinds above are taken out.
builtin_namespaced_core := {
	"ConfigMap", "Secret", "ServiceAccount", "Service", "Pod", "PersistentVolumeClaim", "Endpoints",
	"Event", "LimitRange", "ResourceQuota", "ReplicationController", "PodTemplate",
}

builtin_namespaced_groups := {
	"apps", "batch", "autoscaling", "policy", "coordination.k8s.io", "discovery.k8s.io",
	"events.k8s.io", "networking.k8s.io", "rbac.authorization.k8s.io", "security.istio.io",
	"networking.istio.io", "telemetry.istio.io", "extensions.istio.io",
	"gateway.networking.k8s.io", "external-secrets.io", "generators.external-secrets.io", "argoproj.io",
}

entry(reason, detail) := {
	"msg": concat(":", [reason, detail]),
	"reason": reason,
	"detail": detail,
}

role := data.context.role

component := data.context.component

role_data := data.allow.roles[role]

class_name := role_data.components[component]

class := data.allow.classes[class_name]

child(o, k) := v if {
	is_object(o)
	v := object.get(o, k, null)
	is_object(v)
}

meta := object.get(input, "metadata", {})

name := object.get(meta, "name", "")

ns := v if {
	v := object.get(meta, "namespace", "")
	is_string(v)
} else := ""

default group := ""

group := parts[0] if {
	parts := split(input.apiVersion, "/")
	count(parts) == 2
}

kind_key := concat("/", [group, input.kind]) if group != ""

kind_key := input.kind if group == ""

labels_of(o) := l if {
	l := child(child(o, "metadata"), "labels")
}

annotations_of(o) := a if {
	a := child(child(o, "metadata"), "annotations")
}

template_objs contains t if {
	t := child(child(input, "spec"), "template")
}

template_objs contains t if {
	t := child(child(child(child(input, "spec"), "jobTemplate"), "spec"), "template")
}

# The labels and annotations that reach a pod: the template of a workload, or the Pod itself.
pod_labels contains l if {
	some t in template_objs
	l := labels_of(t)
}

pod_labels contains l if {
	input.kind == "Pod"
	group == ""
	l := labels_of(input)
}

pod_annotations contains a if {
	some t in template_objs
	a := annotations_of(t)
}

pod_annotations contains a if {
	input.kind == "Pod"
	group == ""
	a := annotations_of(input)
}

# The pod specs of the object: the spec of each template, or the spec of the Pod itself.
pod_specs contains s if {
	some t in template_objs
	s := child(t, "spec")
}

pod_specs contains s if {
	input.kind == "Pod"
	group == ""
	s := child(input, "spec")
}

all_labels contains l if {
	l := labels_of(input)
}

all_labels contains l if {
	some l in pod_labels
}

all_annotations contains a if {
	a := annotations_of(input)
}

all_annotations contains a if {
	some a in pod_annotations
}

cluster_scoped if builtin_cluster[kind_key]

cluster_scoped if {
	some e in data.scope.cluster
	e == kind_key
}

namespaced_known if builtin_namespaced_core[kind_key]

namespaced_known if {
	group != ""
	builtin_namespaced_groups[group]
}

namespaced_known if {
	some e in data.scope.namespaced
	e == kind_key
}

listed_cluster if {
	some e in class.clusterKinds
	e == kind_key
}

listed_namespaced if {
	some e in class.namespacedKinds
	e == kind_key
}

listed_namespaced if {
	some e in class.namespacedKinds
	e == "*"
}

ns_allowed if {
	some n in class.objectNamespaces
	n == ns
}

guarded_ns if {
	some g in role_data.meshGuarded
	g == ns
}

appproject_ok if {
	component == "argocd"
	some p in role_data.appProjects
	p == name
}

# An AppProject that allow.json locks, such as default, may come only with exactly its locked spec.
appproject_ok if {
	component == "argocd"
	data.allow.lockedAppProjects[name]
}

locked_spec_differs if {
	locked := data.allow.lockedAppProjects[name]
	object.get(input, "spec", null) != locked
}

is_netpol if {
	input.kind == "NetworkPolicy"
	group == "networking.k8s.io"
}

deny contains entry("component_not_allowed", "component_unknown") if {
	not class_name
}

deny contains entry("component_not_allowed", "harness_namespace") if {
	class_name
	some h in role_data.harnessNamespaces
	h == ns
}

deny contains entry("component_not_allowed", "harness_namespace") if {
	class_name
	input.kind == "Namespace"
	some h in role_data.harnessNamespaces
	h == name
}

deny contains entry("component_not_allowed", "harness_label") if {
	class_name
	some l in all_labels
	some k, _ in l
	k == harness_label_key
}

deny contains entry("component_not_allowed", "harness_object") if {
	class_name
	some o in role_data.harnessClusterObjects
	o.kind == input.kind
	o.name == name
}

deny contains entry("component_not_allowed", "kind") if {
	class_name
	cluster_scoped
	not listed_cluster
}

deny contains entry("component_not_allowed", "kind") if {
	class_name
	not cluster_scoped
	namespaced_known
	not listed_namespaced
}

deny contains entry("component_not_allowed", "kind") if {
	class_name
	kind_key in {"argoproj.io/Application", "argoproj.io/ApplicationSet"}
}

deny contains entry("component_not_allowed", "kind") if {
	class_name
	kind_key == "argoproj.io/AppProject"
	not appproject_ok
}

deny contains entry("component_not_allowed", "appproject_spec") if {
	class_name
	kind_key == "argoproj.io/AppProject"
	component == "argocd"
	locked_spec_differs
}

deny contains entry("component_not_allowed", "kind_unknown_scope") if {
	class_name
	not cluster_scoped
	not namespaced_known
}

deny contains entry("component_not_allowed", "cluster_kind_namespaced") if {
	class_name
	cluster_scoped
	ns != ""
}

deny contains entry("component_not_allowed", "namespace_missing") if {
	class_name
	not cluster_scoped
	namespaced_known
	ns == ""
}

deny contains entry("component_not_allowed", "namespace") if {
	class_name
	not cluster_scoped
	namespaced_known
	ns != ""
	listed_namespaced
	not ns_allowed
}

deny contains entry("component_not_allowed", "namespace") if {
	class_name
	kind_key == "Namespace"
	listed_cluster
	not name_allowed
}

name_allowed if {
	some n in class.objectNamespaces
	n == name
}

deny contains entry("component_not_allowed", "layout") if {
	class_name
	s := object.get(input, "spec", null)
	s != null
	not is_object(s)
}

deny contains entry("component_not_allowed", "layout") if {
	class_name
	some t in template_objs
	m := object.get(t, "metadata", null)
	m != null
	not is_object(m)
}

deny contains entry("component_not_allowed", "layout") if {
	class_name
	some t in template_objs
	m := child(t, "metadata")
	some field in ["labels", "annotations"]
	v := object.get(m, field, null)
	v != null
	not is_object(v)
}

deny contains entry("component_not_allowed", "service_type") if {
	class.serviceClusterIPOnly
	input.kind == "Service"
	group == ""
	spec := child(input, "spec")
	t := object.get(spec, "type", "ClusterIP")
	t != "ClusterIP"
}

deny contains entry("component_not_allowed", "service_type") if {
	class.serviceClusterIPOnly
	input.kind == "Service"
	group == ""
	spec := child(input, "spec")
	ips := object.get(spec, "externalIPs", [])
	is_array(ips)
	count(ips) > 0
}

opted_out(m) if {
	v := m[inject_key]
	is_string(v)
	opt_out_values[lower(v)]
}

deny contains entry("component_not_allowed", "mesh_opt_out") if {
	class.noSidecarOptOut
	some l in all_labels
	opted_out(l)
}

deny contains entry("component_not_allowed", "mesh_opt_out") if {
	class.noSidecarOptOut
	some a in all_annotations
	opted_out(a)
}

traffic_key(k) if {
	parts := split(k, "/")
	count(parts) == 2
	parts[0] == traffic_prefix
}

intercept_key(k) if intercept_keys[lower(k)]

all_meta contains m if {
	some m in all_labels
}

all_meta contains m if {
	some m in all_annotations
}

deny contains entry("component_not_allowed", "mesh_opt_out") if {
	class.noSidecarOptOut
	some m in all_meta
	some k, _ in m
	traffic_key(k)
}

deny contains entry("component_not_allowed", "mesh_opt_out") if {
	class.noSidecarOptOut
	some m in all_meta
	some k, _ in m
	intercept_key(k)
}

# A token Secret of a ServiceAccount gives an API token with no expiry, so no class may hold one.
deny contains entry("component_not_allowed", "service_account_token") if {
	class_name
	input.kind == "Secret"
	group == ""
	object.get(input, "type", "") == sa_token_type
}

declared_account(n) if {
	some a in data.serviceAccounts
	a.namespace == ns
	a.name == n
}

account_ok(v) if v == ""

account_ok(v) if v == "default"

account_ok(v) if {
	is_string(v)
	declared_account(v)
}

deny contains entry("component_not_allowed", "foreign_service_account") if {
	class.ownServiceAccountsOnly
	some s in pod_specs
	some f in account_fields
	v := object.get(s, f, null)
	v != null
	not account_ok(v)
}

# A guarded namespace keeps injection off: the Namespace carries istio-injection disabled and no
# istio.io/rev label, and no pod asks for a sidecar.
deny contains entry("policy_blocks_planes", "mesh_injection") if {
	class_name
	input.kind == "Namespace"
	group == ""
	some g in role_data.meshGuarded
	g == name
	not namespace_injection_disabled
}

namespace_injection_disabled if {
	l := labels_of(input)
	l["istio-injection"] == "disabled"
}

deny contains entry("policy_blocks_planes", "mesh_injection") if {
	class_name
	input.kind == "Namespace"
	group == ""
	some g in role_data.meshGuarded
	g == name
	some k, _ in labels_of(input)
	k == "istio.io/rev"
}

deny contains entry("policy_blocks_planes", "mesh_injection") if {
	class_name
	guarded_ns
	some l in pod_labels
	l[inject_key] == "true"
}

deny contains entry("policy_blocks_planes", "mesh_injection") if {
	class_name
	guarded_ns
	some l in pod_labels
	some k, _ in l
	k == "istio.io/rev"
}

deny contains entry("policy_blocks_planes", concat("/", [ns, name])) if {
	class_name
	is_netpol
	some h in data.harness.networkPolicies
	h.namespace == ns
	h.name == name
}

deny contains entry("policy_blocks_planes", concat("/", [ns, name])) if {
	class_name
	is_netpol
	some h in role_data.planePolicies
	h.namespace == ns
	h.name == name
}
