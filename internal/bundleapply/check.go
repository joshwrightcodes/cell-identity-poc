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
	"sync"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/storage"
	"github.com/open-policy-agent/opa/v1/storage/inmem"
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
// list, more than maxObjects objects give too_large, and a document that is not an object with
// apiVersion, kind and a name gives layout.
func Decode(manifests []byte, maxObjects int) ([]Object, error) {
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
	if v, present := meta["namespace"]; present && v != nil {
		if o.Namespace, ok = v.(string); !ok {
			return Object{}, false
		}
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
	})
	q, err := rego.New(
		rego.Module("bundle.rego", module),
		rego.Query("data.bundle.allow.deny"),
		rego.Store(st),
		rego.Capabilities(capabilities()),
		rego.StrictBuiltinErrors(true),
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

// detailRank orders the denials of one object: the lowest rank is reported.
var detailRank = map[string]int{
	"component_unknown": 0, "harness_object": 1, "harness_namespace": 2, "harness_label": 3,
	"mesh_injection": 4, "kind": 6, "namespace_missing": 7, "namespace": 8,
	"service_type": 9, "mesh_opt_out": 10,
}

type denial struct{ msg, reason, detail string }

func rank(d denial) int {
	if d.reason == op.ReasonPolicyBlocksPlanes && d.detail != "mesh_injection" {
		return 5
	}
	return detailRank[d.detail]
}

// Check evaluates the policy for each object of component and returns the first refusal in input
// order, as a *Refusal. Of several denials for one object, the most specific one wins.
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
	if len(objs) == 0 {
		objs = []Object{{}}
	}
	for _, o := range objs {
		rs, err := c.query.Eval(ctx, rego.EvalTransaction(txn), rego.EvalInput(o.Raw))
		if err != nil {
			return fmt.Errorf("bundleapply: evaluate policy: %w", err)
		}
		ds, err := denials(rs)
		if err != nil {
			return err
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

func denials(rs rego.ResultSet) ([]denial, error) {
	if len(rs) == 0 || len(rs[0].Expressions) == 0 {
		return nil, nil
	}
	list, ok := rs[0].Expressions[0].Value.([]any)
	if !ok {
		return nil, errors.New("bundleapply: policy deny is not a set")
	}
	out := make([]denial, 0, len(list))
	for _, e := range list {
		m, ok := e.(map[string]any)
		if !ok {
			return nil, errors.New("bundleapply: policy deny entry is not an object")
		}
		d := denial{}
		d.msg, _ = m["msg"].(string)
		d.reason, _ = m["reason"].(string)
		d.detail, _ = m["detail"].(string)
		out = append(out, d)
	}
	return out, nil
}
