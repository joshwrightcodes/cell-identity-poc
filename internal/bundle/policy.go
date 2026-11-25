package bundle

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"fmt"
	"sync"

	"github.com/joshwrightcodes/cell-identity-poc/internal/record"
)

//go:embed allow.json
var allowJSON []byte

// ObjectRef names one cluster object by kind and name.
type ObjectRef struct {
	Kind string `json:"kind"`
	Name string `json:"name"`
}

// Class is what a component of that class may contain and where it may sync. A namespaced kind of
// "*" stands for every namespaced kind, and a kind with a group is written group/Kind.
// OwnServiceAccountsOnly lets a pod of the class run only as default or as a ServiceAccount that the
// same component declares in the namespace of the pod. NoReservedObjects refuses the objects that
// cluster controllers create in every namespace, which no Application tracks. NamespaceKinds limits a
// namespace of ObjectNamespaces to the kinds that it lists for that namespace, as group/Kind.
type Class struct {
	Project                string              `json:"project"`
	ObjectNamespaces       []string            `json:"objectNamespaces"`
	DestinationNamespaces  []string            `json:"destinationNamespaces"`
	ClusterKinds           []string            `json:"clusterKinds"`
	NamespacedKinds        []string            `json:"namespacedKinds"`
	NamespaceKinds         map[string][]string `json:"namespaceKinds,omitempty"`
	ServiceClusterIPOnly   bool                `json:"serviceClusterIPOnly,omitempty"`
	NoSidecarOptOut        bool                `json:"noSidecarOptOut,omitempty"`
	OwnServiceAccountsOnly bool                `json:"ownServiceAccountsOnly,omitempty"`
	NoReservedObjects      bool                `json:"noReservedObjects,omitempty"`
}

// PolicyRef names one namespaced object.
type PolicyRef struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
}

// Role maps the components of a cluster role to classes and names the harness objects that no
// bundle may touch.
type Role struct {
	Components            map[string]string `json:"components"`
	HarnessNamespaces     []string          `json:"harnessNamespaces"`
	HarnessClusterObjects []ObjectRef       `json:"harnessClusterObjects"`
	MeshGuarded           []string          `json:"meshGuarded"`
	AppComponents         []string          `json:"appComponents"`
	AppProjects           []string          `json:"appProjects"`
	PlanePolicies         []PolicyRef       `json:"planePolicies"`
}

// Policy is the allow-list data. The Rego policy reads it as data.allow. The role open is the
// cluster management. It lists no component, so it has no signed root: management keeps the harness
// publish, and CheckSet and ComposeRoot refuse every component for that role.
type Policy struct {
	Version int              `json:"version"`
	Classes map[string]Class `json:"classes"`
	Roles   map[string]Role  `json:"roles"`
	// LockedAppProjects gives, by name, the exact spec of an AppProject that the argocd component
	// carries as is, such as default. Any other spec for that name is refused.
	LockedAppProjects map[string]map[string]any `json:"lockedAppProjects"`
}

var (
	defaultOnce   sync.Once
	defaultPolicy Policy
	defaultErr    error
)

// DefaultPolicy returns the embedded allow.json. It panics if the embedded data is invalid, which
// a test catches.
func DefaultPolicy() Policy {
	defaultOnce.Do(func() { defaultPolicy, defaultErr = ParsePolicy(allowJSON) })
	if defaultErr != nil {
		panic("bundle: embedded allow.json: " + defaultErr.Error())
	}
	return defaultPolicy
}

// ParsePolicy decodes allow.json data strictly and checks that every component names a class.
func ParsePolicy(data []byte) (Policy, error) {
	var p Policy
	if err := record.DecodeStrict(data, &p); err != nil {
		return Policy{}, err
	}
	if p.Version != 1 {
		return Policy{}, fmt.Errorf("%w allow: version %d is not 1", record.ErrDecode, p.Version)
	}
	for role, r := range p.Roles {
		for comp, class := range r.Components {
			if _, ok := p.Classes[class]; !ok {
				return Policy{}, fmt.Errorf("%w allow: component %q of role %q names the unknown class %q", record.ErrDecode, comp, role, class)
			}
		}
	}
	return p, nil
}

// AllowSHA256 returns the lowercase hex SHA-256 of the embedded allow.json.
func AllowSHA256() string {
	sum := sha256.Sum256(allowJSON)
	return hex.EncodeToString(sum[:])
}

// ClassOf returns the class of component in role. The role and the component name fix the class.
func (p Policy) ClassOf(role, component string) (Class, bool) {
	r, ok := p.Roles[role]
	if !ok {
		return Class{}, false
	}
	name, ok := r.Components[component]
	if !ok {
		return Class{}, false
	}
	c, ok := p.Classes[name]
	return c, ok
}
