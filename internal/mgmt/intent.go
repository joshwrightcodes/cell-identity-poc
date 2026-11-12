package mgmt

import (
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"slices"
	"strings"

	"github.com/joshwrightcodes/cell-identity-poc/internal/record"
	"github.com/joshwrightcodes/cell-identity-poc/internal/spec"
)

const maxIntentFile = 1 << 20

var envRE = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)

var reservedNames = []string{"cp", "dev-cp", "management", "rogue"}

// Intent says which cells the environment holds and which service accounts each one may present.
type Intent struct {
	Env         string         `json:"env"`
	BindSubject record.Subject `json:"bindSubject"`
	Cells       []IntentCell   `json:"cells"`
}

// IntentCell is one cell of the intent.
type IntentCell struct {
	Name     string           `json:"name"`
	Subjects []record.Subject `json:"subjects"`
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
	seen := map[string]bool{}
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
