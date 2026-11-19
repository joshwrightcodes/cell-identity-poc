package bundleapply

import (
	"cmp"
	"encoding/json"
	"reflect"
	"slices"
	"strings"

	"github.com/joshwrightcodes/cell-identity-poc/internal/bundle"
	"github.com/joshwrightcodes/cell-identity-poc/internal/op"
)

const detailProject = "appproject_spec"

// ExpectedAppProjectSpec returns the spec that the AppProject name must have in a cluster of role.
// The engine refuses an AppProject of a bundle with any other spec.
func ExpectedAppProjectSpec(role, name string, p bundle.Policy) (map[string]any, error) {
	return bundle.ExpectedAppProjectSpec(role, name, p)
}

// checkAppProjects refuses an AppProject object whose spec differs from ExpectedAppProjectSpec, or,
// for a name that allow.json locks, from its locked spec exactly.
func checkAppProjects(role string, p bundle.Policy, objs []Object) *Refusal {
	for _, o := range objs {
		if o.Kind != "AppProject" || !strings.HasPrefix(o.APIVersion, "argoproj.io/") {
			continue
		}
		refuse := &Refusal{Reason: op.ReasonComponentNotAllowed, Detail: detailProject, Object: o.ref()}
		if locked, ok := p.LockedAppProjects[o.Name]; ok {
			if !reflect.DeepEqual(plain(locked), plain(o.Raw["spec"])) {
				return refuse
			}
			continue
		}
		want, err := ExpectedAppProjectSpec(role, o.Name, p)
		if err != nil {
			return refuse
		}
		got, _ := o.Raw["spec"].(map[string]any)
		if !reflect.DeepEqual(normalise(want), normalise(got)) {
			return refuse
		}
	}
	return nil
}

// plain converts v to plain JSON values and keeps everything else as it is: order, empty lists and
// empty objects.
func plain(v any) any {
	b, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	var out any
	if err := json.Unmarshal(b, &out); err != nil {
		return nil
	}
	return out
}

// normalise converts v to plain JSON values, drops empty lists and objects, and sorts every list
// by the JSON form of its entries, so that order and empty fields do not matter.
func normalise(v any) any {
	b, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	var plain any
	if err := json.Unmarshal(b, &plain); err != nil {
		return nil
	}
	return prune(plain)
}

func prune(v any) any {
	switch x := v.(type) {
	case map[string]any:
		out := map[string]any{}
		for k, e := range x {
			if e = prune(e); e != nil {
				out[k] = e
			}
		}
		if len(out) == 0 {
			return nil
		}
		return out
	case []any:
		out := make([]any, 0, len(x))
		for _, e := range x {
			out = append(out, prune(e))
		}
		slices.SortFunc(out, func(a, b any) int {
			ja, _ := json.Marshal(a)
			jb, _ := json.Marshal(b)
			return cmp.Compare(string(ja), string(jb))
		})
		if len(out) == 0 {
			return nil
		}
		return out
	default:
		return v
	}
}
