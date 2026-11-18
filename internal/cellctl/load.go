// Package cellctl is the cell controller: it loads the signed provisioning steps that envd keeps in
// a ConfigMap, verifies them under its own pin, sends them to the host service and reports their
// progress in a second ConfigMap.
package cellctl

import (
	"crypto/ed25519"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmtapi"
	"github.com/joshwrightcodes/cell-identity-poc/internal/spec"
	"github.com/joshwrightcodes/cell-identity-poc/internal/step"
)

const (
	// SpecKey is the key of the spec envelope in the steps ConfigMap.
	SpecKey = "spec-envelope.json"
	// StepSuffix ends the key of each step envelope in the steps ConfigMap.
	StepSuffix = ".step.json"

	maxEnvelope = 16 << 10
	// maxUnindexed bounds the refusals that one read makes for steps that the spec does not index.
	maxUnindexed = 32
)

// Verified is a step that passed every check, with the envelope bytes that the host service gets.
type Verified struct {
	Step     step.Step
	Envelope []byte
}

// Load verifies the content of the steps ConfigMap. It trusts keys only. It returns the verified
// steps in the order (issuedAt, cell), the revision of the spec that it accepted, and the refusals.
//
// A refusal of the spec itself has no step ID. It is one entry with an empty ID and Cell, and the
// detail signature_invalid, payload_invalid, env_mismatch or revision_old. In that case Load
// returns no steps and the revision mark unchanged. A refusal of one step names the step ID and the
// cell, and has the detail of the first check that failed. Load keeps no state, so a refusal ends
// at the next read that verifies.
func Load(data map[string]string, env string, keys []ed25519.PublicKey, mark spec.Revision, now time.Time) (steps []Verified, rev spec.Revision, refused []mgmtapi.StepStatus) {
	specRefusal := func(detail string) ([]Verified, spec.Revision, []mgmtapi.StepStatus) {
		return nil, mark, []mgmtapi.StepStatus{refusal("", "", detail)}
	}
	raw, ok := data[SpecKey]
	if !ok {
		return specRefusal(step.DetailPayloadInvalid)
	}
	s, _, err := spec.Verify([]byte(raw), keys)
	switch {
	case err != nil:
		return specRefusal(step.DetailOf(err))
	case s.Env != env:
		return specRefusal(step.DetailEnvMismatch)
	case s.Revision.Compare(mark) < 0:
		return specRefusal(step.DetailRevisionOld)
	}

	indexed := make(map[string]bool, len(s.Steps))
	ids := make(map[string]bool, len(s.Steps))
	for _, e := range s.Steps {
		indexed[e.Name] = true
		ids[e.StepID] = true
		if d := checkEntry(e, data, env, keys, now, &steps); d != "" {
			refused = append(refused, refusal(e.StepID, e.Name, d))
		}
	}

	var names []string
	for k := range data {
		if name, ok := strings.CutSuffix(k, StepSuffix); ok && !indexed[name] {
			names = append(names, k)
		}
	}
	slices.Sort(names)
	n := 0
	for _, k := range names {
		id, cell, _, err := step.Peek([]byte(data[k]))
		if err != nil || ids[id] || n >= maxUnindexed {
			continue
		}
		n++
		refused = append(refused, refusal(id, cell, step.DetailStepUnindexed))
	}

	sort.SliceStable(steps, func(i, j int) bool {
		a, b := steps[i].Step, steps[j].Step
		if !a.IssuedAt.Equal(b.IssuedAt) {
			return a.IssuedAt.Before(b.IssuedAt)
		}
		return a.Cell < b.Cell
	})
	return steps, s.Revision, refused
}

// checkEntry checks the envelope of one index entry and appends the verified step to out. It
// returns the refusal detail, or "" when the step is good.
func checkEntry(e spec.StepEntry, data map[string]string, env string, keys []ed25519.PublicKey, now time.Time, out *[]Verified) string {
	raw, ok := data[e.Name+StepSuffix]
	if !ok {
		return step.DetailStepMissing
	}
	if len(raw) > maxEnvelope {
		return step.DetailPayloadInvalid
	}
	st, payload, err := step.Verify([]byte(raw), keys)
	switch {
	case err != nil:
		return step.DetailOf(err)
	case st.Cell != e.Name:
		return step.DetailPayloadInvalid
	case st.ID != e.StepID, step.PayloadSHA256(payload) != e.StepSHA256:
		return step.DetailStepUnindexed
	}
	if err := step.Check(st, env, now); err != nil {
		return step.DetailOf(err)
	}
	*out = append(*out, Verified{Step: st, Envelope: []byte(raw)})
	return ""
}

func refusal(id, cell, detail string) mgmtapi.StepStatus {
	return mgmtapi.StepStatus{ID: id, Cell: cell, State: mgmtapi.StepRefused, Reason: step.Code, Detail: detail}
}
