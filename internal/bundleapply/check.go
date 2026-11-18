// Package bundleapply applies signed bundle sets. This file holds the object model, the decoder and
// the embedded Rego policy that checks every object of a bundle.
package bundleapply

import (
	"bufio"
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/storage"
	"github.com/open-policy-agent/opa/v1/storage/inmem"
	yamlv3 "go.yaml.in/yaml/v3"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
	"sigs.k8s.io/yaml"

	"github.com/joshwrightcodes/cell-identity-poc/internal/bundle"
	"github.com/joshwrightcodes/cell-identity-poc/internal/op"
)

//go:embed policy/bundle.rego
var policySource string

// Object is one decoded Kubernetes object of a bundle.
type Object struct {
	APIVersion, Kind, Namespace, Name string
	Labels                            map[string]string
	Raw                               map[string]any
}

// ObjectRef names one namespaced object.
type ObjectRef struct {
	Namespace, Name string
}

// HarnessRefs lists the live objects that the policy protects, read from the cluster.
type HarnessRefs struct {
	NetworkPolicies []ObjectRef
}

// Refusal is the reason why a bundle is not allowed. Reason and Detail are the values of the shared
// names, and Object names the offending object.
type Refusal struct {
	Reason, Detail, Object string
}

func (r *Refusal) Error() string {
	s := r.Reason
	if r.Detail != "" {
		s += ":" + r.Detail
	}
	if r.Object != "" {
		s += " (" + r.Object + ")"
	}
	return s
}

func (o Object) ref() string {
	if o.Namespace != "" {
		return o.Kind + "/" + o.Namespace + "/" + o.Name
	}
	return o.Kind + "/" + o.Name
}

func layout(detail string) *Refusal {
	return &Refusal{Reason: op.ReasonComponentNotAllowed, Detail: detail}
}

// Decode reads the documents of manifests. A document of kind List gives a Refusal with detail
// list. Any other document with an items field gives items_list, because Argo CD expands every
// object that has an items array and the policy checks only the outer object. More than maxObjects
// objects give too_large, and a document that is not an object with apiVersion, kind and a name
// gives layout.
func Decode(manifests []byte, maxObjects int) ([]Object, error) {
	if !plainText(manifests) {
		return nil, layout("layout")
	}
	rd := utilyaml.NewYAMLReader(bufio.NewReader(bytes.NewReader(manifests)))
	var objs []Object
	for {
		doc, err := rd.Read()
		if errors.Is(err, io.EOF) {
			return objs, nil
		}
		if err != nil {
			return nil, layout("layout")
		}
		if !singlePlainDocument(doc) {
			return nil, layout("layout")
		}
		var raw map[string]any
		if err := yaml.Unmarshal(doc, &raw); err != nil {
			return nil, layout("layout")
		}
		if len(raw) == 0 {
			continue
		}
		if k, _ := raw["kind"].(string); k == "List" {
			return nil, layout("list")
		}
		if _, has := raw["items"]; has {
			return nil, layout("items_list")
		}
		o, ok := toObject(raw)
		if !ok {
			return nil, layout("layout")
		}
		if len(objs) >= maxObjects {
			return nil, layout("too_large")
		}
		objs = append(objs, o)
	}
}

func toObject(raw map[string]any) (Object, bool) {
	o := Object{Raw: raw}
	var ok bool
	if o.APIVersion, ok = raw["apiVersion"].(string); !ok || o.APIVersion == "" {
		return Object{}, false
	}
	if o.Kind, ok = raw["kind"].(string); !ok || o.Kind == "" {
		return Object{}, false
	}
	meta, ok := raw["metadata"].(map[string]any)
	if !ok {
		return Object{}, false
	}
	if o.Name, ok = meta["name"].(string); !ok || o.Name == "" {
		return Object{}, false
	}
	if v, present := meta["namespace"]; present {
		if v == nil {
			delete(meta, "namespace")
		} else if o.Namespace, ok = v.(string); !ok {
			return Object{}, false
		}
	}
	if strings.Count(o.APIVersion, "/") > 1 {
		return Object{}, false
	}
	for _, field := range []string{"labels", "annotations"} {
		v, present := meta[field]
		if !present || v == nil {
			continue
		}
		m, ok := v.(map[string]any)
		if !ok {
			return Object{}, false
		}
		for _, val := range m {
			if _, ok := val.(string); !ok {
				return Object{}, false
			}
		}
		if field == "labels" {
			o.Labels = make(map[string]string, len(m))
			for k, val := range m {
				o.Labels[k] = val.(string)
			}
		}
	}
	return o, true
}

// allowedBuiltins is the complete list of builtins that the policy may call. Anything else fails
// to compile. The list holds the comparison operators, membership, and string and object helpers.
var allowedBuiltins = map[string]bool{
	"eq": true, "assign": true, "equal": true, "neq": true,
	"lt": true, "lte": true, "gt": true, "gte": true,
	"internal.member_2": true, "internal.member_3": true,
	"count": true, "concat": true, "split": true, "lower": true,
	"object.get": true, "is_object": true, "is_array": true, "is_string": true,
}

func capabilities() *ast.Capabilities {
	base := ast.CapabilitiesForThisVersion()
	caps := *base
	caps.Builtins = nil
	for _, b := range base.Builtins {
		if allowedBuiltins[b.Name] {
			caps.Builtins = append(caps.Builtins, b)
		}
	}
	caps.AllowNet = []string{}
	return &caps
}

// Checker evaluates the embedded policy for one role.
type Checker struct {
	role  string
	store storage.Store
	query rego.PreparedEvalQuery
	mu    sync.Mutex
	// extra holds the scope of custom kinds that the caller learned from other components of the set
	// or from live discovery, as group/Kind.
	extraCluster, extraNamespaced []string
}

// AddScopes records the scope of kinds that no object of the checked component declares, for
// example the CRDs of other components of the set. Each kind is written group/Kind, and a kind of
// the core group is written without a group.
func (c *Checker) AddScopes(cluster, namespaced []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.extraCluster = append(c.extraCluster, cluster...)
	c.extraNamespaced = append(c.extraNamespaced, namespaced...)
}

// NewChecker prepares the embedded policy once, with the limited builtins and strict builtin errors.
func NewChecker(role string, p bundle.Policy, h HarnessRefs) (*Checker, error) {
	return newChecker(role, p, h, policySource)
}

func newChecker(role string, p bundle.Policy, h HarnessRefs, module string) (*Checker, error) {
	allow, err := toData(p)
	if err != nil {
		return nil, err
	}
	nps := make([]any, 0, len(h.NetworkPolicies))
	for _, r := range h.NetworkPolicies {
		nps = append(nps, map[string]any{"namespace": r.Namespace, "name": r.Name})
	}
	st := inmem.NewFromObject(map[string]any{
		"allow":   allow,
		"context": map[string]any{"role": role, "component": ""},
		"harness": map[string]any{"networkPolicies": nps},
		"scope":   map[string]any{"cluster": []any{}, "namespaced": []any{}},
	})
	q, err := rego.New(
		rego.Module("bundle.rego", module),
		rego.Query("data.bundle.allow.deny"),
		rego.Store(st),
		rego.Capabilities(capabilities()),
		rego.StrictBuiltinErrors(true),
		rego.Strict(true),
	).PrepareForEval(context.Background())
	if err != nil {
		return nil, fmt.Errorf("bundleapply: prepare policy: %w", err)
	}
	return &Checker{role: role, store: st, query: q}, nil
}

func toData(p bundle.Policy) (map[string]any, error) {
	b, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	return m, nil
}

// detailRank orders the denials of one object: the lowest rank is reported. A detail that is not
// listed ranks last. A plane policy name (reason policy_blocks_planes with a namespace and name as
// detail) has the rank of the key planePolicy.
var detailRank = map[string]int{
	"component_unknown": 0, "harness_object": 1, "planePolicy": 2, "harness_namespace": 3,
	"harness_label": 4, "mesh_injection": 5, "kind": 6, "kind_unknown_scope": 7,
	"cluster_kind_namespaced": 8, "namespace_missing": 9, "namespace": 10, "layout": 11,
	"service_type": 12, "mesh_opt_out": 13,
}

const lastRank = 1 << 20

type denial struct{ msg, reason, detail string }

func rank(d denial) int {
	key := d.detail
	if d.reason == op.ReasonPolicyBlocksPlanes && d.detail != "mesh_injection" {
		key = "planePolicy"
	}
	if r, ok := detailRank[key]; ok {
		return r
	}
	return lastRank
}

func policyError(o Object) *Refusal {
	return &Refusal{Reason: op.ReasonComponentNotAllowed, Detail: "policy_error", Object: o.ref()}
}

// crdKinds returns the group/Kind of each custom resource that the CRDs among objs define, by scope.
func crdKinds(objs []Object) (cluster, namespaced []string) {
	for _, o := range objs {
		if o.Kind != "CustomResourceDefinition" || !strings.HasPrefix(o.APIVersion, "apiextensions.k8s.io/") {
			continue
		}
		spec, _ := o.Raw["spec"].(map[string]any)
		names, _ := spec["names"].(map[string]any)
		group, _ := spec["group"].(string)
		kind, _ := names["kind"].(string)
		scope, _ := spec["scope"].(string)
		if group == "" || kind == "" {
			continue
		}
		switch scope {
		case "Cluster":
			cluster = append(cluster, group+"/"+kind)
		case "Namespaced":
			namespaced = append(namespaced, group+"/"+kind)
		}
	}
	return cluster, namespaced
}

// Check evaluates the policy for each object of component and returns the first refusal in input
// order, as a *Refusal. Of several denials for one object, the most specific one wins. An
// evaluation error or an empty result gives the refusal policy_error. Only a fault of the store or
// a canceled context gives a plain error.
func (c *Checker) Check(ctx context.Context, component string, objs []Object) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	txn, err := c.store.NewTransaction(ctx, storage.WriteParams)
	if err != nil {
		return err
	}
	defer c.store.Abort(ctx, txn)
	if err := c.store.Write(ctx, txn, storage.AddOp, storage.MustParsePath("/context"),
		map[string]any{"role": c.role, "component": component}); err != nil {
		return err
	}
	cl, ns := crdKinds(objs)
	cl = append(cl, c.extraCluster...)
	ns = append(ns, c.extraNamespaced...)
	if err := c.store.Write(ctx, txn, storage.AddOp, storage.MustParsePath("/scope"),
		map[string]any{"cluster": toAny(cl), "namespaced": toAny(ns)}); err != nil {
		return err
	}
	if len(objs) == 0 {
		rs, err := c.query.Eval(ctx, rego.EvalTransaction(txn), rego.EvalInput(map[string]any{}))
		if err != nil && ctx.Err() != nil {
			return ctx.Err()
		}
		ds, derr := denials(rs, err)
		if derr != nil {
			return policyError(Object{})
		}
		for _, d := range ds {
			if d.detail == "component_unknown" {
				return &Refusal{Reason: d.reason, Detail: d.detail}
			}
		}
		return nil
	}
	for _, o := range objs {
		rs, err := c.query.Eval(ctx, rego.EvalTransaction(txn), rego.EvalInput(o.Raw))
		if err != nil && ctx.Err() != nil {
			return ctx.Err()
		}
		ds, derr := denials(rs, err)
		if derr != nil {
			return policyError(o)
		}
		if len(ds) == 0 {
			continue
		}
		sort.Slice(ds, func(i, j int) bool {
			if ri, rj := rank(ds[i]), rank(ds[j]); ri != rj {
				return ri < rj
			}
			return ds[i].msg < ds[j].msg
		})
		return &Refusal{Reason: ds[0].reason, Detail: ds[0].detail, Object: o.ref()}
	}
	return nil
}

func toAny(in []string) []any {
	out := make([]any, 0, len(in))
	for _, s := range in {
		out = append(out, s)
	}
	return out
}

func denials(rs rego.ResultSet, evalErr error) ([]denial, error) {
	if evalErr != nil {
		return nil, evalErr
	}
	if len(rs) == 0 || len(rs[0].Expressions) == 0 {
		return nil, errors.New("empty result")
	}
	list, ok := rs[0].Expressions[0].Value.([]any)
	if !ok {
		return nil, errors.New("deny is not a set")
	}
	out := make([]denial, 0, len(list))
	for _, e := range list {
		m, ok := e.(map[string]any)
		if !ok {
			return nil, errors.New("deny entry is not an object")
		}
		d := denial{}
		d.msg, _ = m["msg"].(string)
		d.reason, _ = m["reason"].(string)
		d.detail, _ = m["detail"].(string)
		out = append(out, d)
	}
	return out, nil
}

// plainText reports whether the bytes hold only text that every YAML reader splits into lines in
// the same way: valid UTF-8 with no byte order mark, no NUL byte, no lone carriage return, no
// NEL, line separator or paragraph separator, and no line that starts a YAML document end marker.
func plainText(b []byte) bool {
	if !utf8.Valid(b) || bytes.IndexByte(b, 0) >= 0 || bytes.Contains(b, []byte("\xef\xbb\xbf")) {
		return false
	}
	for i := 0; i < len(b); i++ {
		if b[i] == '\r' && (i+1 >= len(b) || b[i+1] != '\n') {
			return false
		}
	}
	for _, r := range string(b) {
		if r == '\u0085' || r == '\u2028' || r == '\u2029' {
			return false
		}
	}
	for _, line := range bytes.Split(b, []byte("\n")) {
		if bytes.HasPrefix(line, []byte("...")) && (len(line) == 3 || line[3] == ' ' || line[3] == '\t' || line[3] == '\r') {
			return false
		}
	}
	return true
}

// singlePlainDocument reports whether chunk is zero or one YAML document that starts with a block
// construct and holds no anchor, alias, merge key, tag or duplicate key.
func singlePlainDocument(chunk []byte) bool {
	first := bytes.TrimLeftFunc(chunk, unicode.IsSpace)
	if len(first) > 0 && (first[0] == '{' || first[0] == '[') {
		return false
	}
	dec := yamlv3.NewDecoder(bytes.NewReader(chunk))
	var n yamlv3.Node
	if err := dec.Decode(&n); err != nil {
		return errors.Is(err, io.EOF)
	}
	var again yamlv3.Node
	if err := dec.Decode(&again); !errors.Is(err, io.EOF) {
		return false
	}
	return plainNode(&n)
}

func plainNode(n *yamlv3.Node) bool {
	if n.Anchor != "" || n.Kind == yamlv3.AliasNode || n.Style&yamlv3.TaggedStyle != 0 {
		return false
	}
	if n.Kind == yamlv3.MappingNode {
		seen := make(map[string]bool, len(n.Content)/2)
		for i := 0; i+1 < len(n.Content); i += 2 {
			k := n.Content[i]
			if k.Kind == yamlv3.ScalarNode {
				if k.Tag == "!!merge" || seen[k.Value] {
					return false
				}
				seen[k.Value] = true
			}
		}
	}
	for _, c := range n.Content {
		if !plainNode(c) {
			return false
		}
	}
	return true
}

// DecodeCanonical decodes manifests and refuses them unless they are the canonical form of their own
// objects (bundle.Canonical). Only that form reads the same in every YAML and JSON reader, so the
// objects that the policy sees are the objects that Argo CD applies.
func DecodeCanonical(manifests []byte, maxObjects int) ([]Object, error) {
	objs, err := Decode(manifests, maxObjects)
	if err != nil {
		return nil, err
	}
	raws := make([]map[string]any, len(objs))
	for i, o := range objs {
		raws[i] = o.Raw
	}
	canon, err := bundle.Canonical(raws)
	if err != nil {
		return nil, layout("layout")
	}
	if !bytes.Equal(canon, manifests) {
		return nil, layout("not_canonical")
	}
	return objs, nil
}
