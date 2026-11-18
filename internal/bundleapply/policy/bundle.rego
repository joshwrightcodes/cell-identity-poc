# Bundle object policy. Input: one decoded object. Data: data.allow (allow.json), data.context
# ({"role","component"}) and data.harness ({"networkPolicies":[{"namespace","name"}]}).
package bundle.allow

harness_label_key := "cell.poc.internal/harness"

inject_key := "sidecar.istio.io/inject"

never_kinds := {"AdminNetworkPolicy", "BaselineAdminNetworkPolicy", "ClusterNetworkPolicy"}

opt_out_values := {"false", "n", "no", "off"}

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

meta := object.get(input, "metadata", {})

name := object.get(meta, "name", "")

ns := object.get(meta, "namespace", "")

default group := ""

group := parts[0] if {
	parts := split(input.apiVersion, "/")
	count(parts) == 2
}

kind_key := concat("/", [group, input.kind]) if group != ""

kind_key := input.kind if group == ""

labels_of(o) := l if {
	m := object.get(o, "metadata", {})
	l := object.get(m, "labels", {})
	is_object(l)
}

annotations_of(o) := a if {
	m := object.get(o, "metadata", {})
	a := object.get(m, "annotations", {})
	is_object(a)
}

template := t if {
	spec := object.get(input, "spec", {})
	is_object(spec)
	t := object.get(spec, "template", {})
	is_object(t)
}

listed_cluster if {
	some e in class.clusterKinds
	e == input.kind
}

listed_cluster if {
	some e in class.clusterKinds
	e == kind_key
}

listed_explicit if {
	some e in class.namespacedKinds
	e == kind_key
}

listed_wildcard if {
	some e in class.namespacedKinds
	e == "*"
	not never_kind
}

never_kind if input.kind in never_kinds

listed_namespaced if listed_explicit

listed_namespaced if listed_wildcard

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
	some k, _ in labels_of(input)
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
	ns == ""
	not listed_cluster
	not listed_explicit
}

deny contains entry("component_not_allowed", "kind") if {
	class_name
	ns != ""
	not listed_cluster
	not listed_namespaced
}

deny contains entry("component_not_allowed", "namespace_missing") if {
	class_name
	ns == ""
	not listed_cluster
	listed_explicit
}

deny contains entry("component_not_allowed", "namespace") if {
	class_name
	ns != ""
	listed_cluster
}

deny contains entry("component_not_allowed", "namespace") if {
	class_name
	ns != ""
	not listed_cluster
	not ns_allowed
}

ns_allowed if {
	some n in class.objectNamespaces
	n == ns
}

deny contains entry("component_not_allowed", "service_type") if {
	class.serviceClusterIPOnly
	input.kind == "Service"
	group == ""
	spec := object.get(input, "spec", {})
	is_object(spec)
	t := object.get(spec, "type", "ClusterIP")
	t != "ClusterIP"
}

deny contains entry("component_not_allowed", "service_type") if {
	class.serviceClusterIPOnly
	input.kind == "Service"
	group == ""
	spec := object.get(input, "spec", {})
	is_object(spec)
	ips := object.get(spec, "externalIPs", [])
	is_array(ips)
	count(ips) > 0
}

opted_out(m) if {
	is_object(m)
	v := m[inject_key]
	is_string(v)
	opt_out_values[lower(v)]
}

deny contains entry("component_not_allowed", "mesh_opt_out") if {
	class.noSidecarOptOut
	opted_out(labels_of(input))
}

deny contains entry("component_not_allowed", "mesh_opt_out") if {
	class.noSidecarOptOut
	opted_out(annotations_of(input))
}

deny contains entry("component_not_allowed", "mesh_opt_out") if {
	class.noSidecarOptOut
	opted_out(labels_of(template))
}

deny contains entry("component_not_allowed", "mesh_opt_out") if {
	class.noSidecarOptOut
	opted_out(annotations_of(template))
}

deny contains entry("policy_blocks_planes", "mesh_injection") if {
	class_name
	input.kind == "Namespace"
	some g in role_data.meshGuarded
	g == name
	labels_of(input)["istio-injection"] == "enabled"
}

deny contains entry("policy_blocks_planes", "mesh_injection") if {
	class_name
	input.kind == "Namespace"
	some g in role_data.meshGuarded
	g == name
	some k, _ in labels_of(input)
	k == "istio.io/rev"
}

deny contains entry("policy_blocks_planes", concat("/", [ns, name])) if {
	class_name
	input.kind == "NetworkPolicy"
	group == "networking.k8s.io"
	some h in data.harness.networkPolicies
	h.namespace == ns
	h.name == name
}
