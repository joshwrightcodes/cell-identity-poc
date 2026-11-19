package mgmt

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/joshwrightcodes/cell-identity-poc/internal/record"
	"github.com/joshwrightcodes/cell-identity-poc/internal/spec"
	"github.com/joshwrightcodes/cell-identity-poc/internal/step"
)

const maxIntentFile = 1 << 20

var envRE = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)

var reservedNames = []string{"cp", "dev-cp", "management", "rogue"}

// Intent is the catalog: the cells that the portal may request, and the service accounts that each
// one may present. A cell is in the intent of the plane only while the catalog lists it and a
// portal request holds it.
type Intent struct {
	Env         string         `json:"env"`
	BindSubject record.Subject `json:"bindSubject"`
	Cells       []IntentCell   `json:"cells"`
	// ControlPlane is the name of the environment control plane as a bundle target. Empty means
	// DefaultControlPlane.
	ControlPlane string `json:"controlPlane,omitempty"`
}

// DefaultControlPlane is the name of the control plane when the intent names none.
const DefaultControlPlane = "dev-cp"

// ControlPlaneName returns the name of the control plane as a bundle target.
func (in Intent) ControlPlaneName() string {
	if in.ControlPlane == "" {
		return DefaultControlPlane
	}
	return in.ControlPlane
}

// IntentCell is one cell of the catalog. Cluster describes the cluster that a step creates.
type IntentCell struct {
	Name     string           `json:"name"`
	Subjects []record.Subject `json:"subjects"`
	Cluster  step.ClusterRef  `json:"cluster"`
}

// LoadIntent reads and validates the intent file at path. The decode is strict.
func LoadIntent(path string) (Intent, error) {
	f, err := os.Open(path)
	if err != nil {
		return Intent{}, fmt.Errorf("open intent: %w", err)
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxIntentFile+1))
	if err != nil {
		return Intent{}, fmt.Errorf("read intent: %w", err)
	}
	if len(data) > maxIntentFile {
		return Intent{}, errors.New("intent file is too large")
	}
	var in Intent
	if err := record.DecodeStrict(data, &in); err != nil {
		return Intent{}, fmt.Errorf("intent: %w", err)
	}
	if err := in.validate(); err != nil {
		return Intent{}, fmt.Errorf("intent: %w", err)
	}
	return in, nil
}

func (in Intent) validate() error {
	if len(in.Env) > 63 || !envRE.MatchString(in.Env) {
		return errors.New("env is not a DNS label")
	}
	if in.BindSubject.Namespace == "" || in.BindSubject.ServiceAccount == "" {
		return errors.New("bindSubject needs a namespace and a service account")
	}
	if in.ControlPlane != "" && !spec.ValidName(in.ControlPlane) {
		return fmt.Errorf("controlPlane %q is not a DNS label of at most %d characters", in.ControlPlane, spec.MaxNameLength)
	}
	seen := map[string]bool{}
	_, probe, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("make probe key: %w", err)
	}
	for _, c := range in.Cells {
		switch {
		case !spec.ValidName(c.Name):
			return fmt.Errorf("cell name %q is not a DNS label of at most %d characters", c.Name, spec.MaxNameLength)
		case slices.Contains(reservedNames, c.Name):
			return fmt.Errorf("cell name %q is reserved", c.Name)
		case seen[c.Name]:
			return fmt.Errorf("cell %q appears twice", c.Name)
		}
		seen[c.Name] = true
		if c.Name == in.ControlPlaneName() {
			return fmt.Errorf("cell name %q is the control plane", c.Name)
		}
		if c.Cluster == (step.ClusterRef{}) {
			return fmt.Errorf("cell %q has no cluster", c.Name)
		}
		now := time.Now().UTC().Truncate(time.Second)
		if _, err := step.Sign(step.Step{
			ID: step.NewID(), Env: in.Env, Cell: c.Name, Kind: step.KindCellCreate, Version: 1, KeyEpoch: 1,
			IssuedAt: now, ExpiresAt: now.Add(step.DefaultTTL), Cluster: c.Cluster, BootstrapSHA256: step.TestDigest,
		}, probe); err != nil {
			return fmt.Errorf("cell %q has an invalid cluster: %w", c.Name, err)
		}
		if !slices.Contains(c.Subjects, in.BindSubject) {
			return fmt.Errorf("cell %q does not list the bind subject", c.Name)
		}
		subjects := map[record.Subject]bool{}
		for _, s := range c.Subjects {
			if s.Namespace == "" || s.ServiceAccount == "" || strings.ContainsAny(s.Namespace+s.ServiceAccount, " \t\n") {
				return fmt.Errorf("cell %q has an invalid subject", c.Name)
			}
			if subjects[s] {
				return fmt.Errorf("cell %q lists a subject twice", c.Name)
			}
			subjects[s] = true
		}
	}
	return nil
}

// sortedSubjects returns a sorted copy, the order that a record carries.
func sortedSubjects(in []record.Subject) []record.Subject {
	out := slices.Clone(in)
	slices.SortFunc(out, func(a, b record.Subject) int {
		if c := strings.Compare(a.Namespace, b.Namespace); c != 0 {
			return c
		}
		return strings.Compare(a.ServiceAccount, b.ServiceAccount)
	})
	return out
}

// catalogCell returns the catalog entry of a cell.
func (p *Plane) catalogCell(name string) (IntentCell, bool) {
	ic, ok := p.catalog[name]
	return ic, ok
}

// cellIn returns the intent entry of a cell in the state st: the catalog lists it and a request
// holds it.
func (p *Plane) cellIn(st *State, name string) (IntentCell, bool) {
	ic, ok := p.catalog[name]
	if !ok || st.Requests[name] == nil {
		return IntentCell{}, false
	}
	return ic, true
}

// intentNames returns the names of the intent cells of st in order.
func (p *Plane) intentNames(st *State) []string {
	out := []string{}
	for _, name := range sortedKeys(p.catalog) {
		if st.Requests[name] != nil {
			out = append(out, name)
		}
	}
	return out
}
