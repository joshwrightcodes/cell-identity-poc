package hostsvc

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/joshwrightcodes/cell-identity-poc/internal/record"
	"github.com/joshwrightcodes/cell-identity-poc/internal/spec"
	"github.com/joshwrightcodes/cell-identity-poc/internal/step"
)

func detailOfCheck(t *testing.T, err error) string {
	t.Helper()
	var se *step.Error
	if !errors.As(err, &se) {
		t.Fatalf("error %v is not a step refusal", err)
	}
	return se.Detail
}

// stripSignatures returns the envelope with no signature.
func stripSignatures(t *testing.T, envelope []byte) []byte {
	t.Helper()
	var m map[string]json.RawMessage
	if err := json.Unmarshal(envelope, &m); err != nil {
		t.Fatal(err)
	}
	m["signatures"] = json.RawMessage("[]")
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// tamper changes the payload of an envelope and keeps its signature.
func tamper(t *testing.T, envelope []byte, from, to string) []byte {
	t.Helper()
	var m map[string]json.RawMessage
	if err := json.Unmarshal(envelope, &m); err != nil {
		t.Fatal(err)
	}
	var p string
	_ = json.Unmarshal(m["payload"], &p)
	raw, _ := base64.StdEncoding.DecodeString(p)
	if !bytes.Contains(raw, []byte(from)) {
		t.Fatalf("payload has no %q", from)
	}
	raw = bytes.Replace(raw, []byte(from), []byte(to), 1)
	m["payload"], _ = json.Marshal(base64.StdEncoding.EncodeToString(raw))
	out, _ := json.Marshal(m)
	return out
}

func TestStepVerifierOrder(t *testing.T) {
	_, roguePriv := newKey(t)
	tests := []struct {
		name   string
		detail string // empty means accepted
		make   func(e *stepEnv) []byte
	}{
		{"good", "", func(e *stepEnv) []byte { _, env := e.indexed("dev-cell-1", nil); return env }},
		{"unsigned", step.DetailSignatureInvalid, func(e *stepEnv) []byte {
			s, env := e.newStep("dev-cell-1", nil)
			e.putSpec([]spec.StepEntry{e.indexOf(s, env)}, nil)
			return stripSignatures(t, env)
		}},
		{"rogue_key", step.DetailSignatureInvalid, func(e *stepEnv) []byte {
			s, env := e.newStepKey(roguePriv, "dev-cell-1", nil)
			e.putSpec([]spec.StepEntry{e.indexOf(s, env)}, nil)
			return env
		}},
		{"tampered", step.DetailSignatureInvalid, func(e *stepEnv) []byte {
			_, env := e.indexed("dev-cell-1", nil)
			return tamper(t, env, `"cell":"dev-cell-1"`, `"cell":"dev-cell-2"`)
		}},
		{"op_envelope", step.DetailPayloadInvalid, func(e *stepEnv) []byte {
			env, err := record.SignEnvelope("application/vnd.poc.op+json", []byte(`{}`), e.priv)
			if err != nil {
				t.Fatal(err)
			}
			return env
		}},
		{"spec_envelope", step.DetailPayloadInvalid, func(e *stepEnv) []byte {
			env, err := spec.Sign(spec.Spec{Env: "dev", Revision: spec.Revision{Epoch: 1, Counter: 1}}, e.priv)
			if err != nil {
				t.Fatal(err)
			}
			return env
		}},
		{"other_env", step.DetailEnvMismatch, func(e *stepEnv) []byte {
			s, env := e.newStep("dev-cell-1", func(s *step.Step) { s.Env = "prod" })
			e.putSpec([]spec.StepEntry{e.indexOf(s, env)}, nil)
			return env
		}},
		{"expired", step.DetailExpired, func(e *stepEnv) []byte {
			s, env := e.newStep("dev-cell-1", func(s *step.Step) { s.ExpiresAt = s.IssuedAt.Add(step.MinTTL) })
			e.putSpec([]spec.StepEntry{e.indexOf(s, env)}, nil)
			e.clock.Advance(step.MinTTL + time.Second)
			return env
		}},
		{"not_yet_valid", step.DetailNotYetValid, func(e *stepEnv) []byte {
			s, env := e.newStep("dev-cell-1", func(s *step.Step) {
				s.IssuedAt = e.clock.Now().Add(2 * time.Minute)
				s.ExpiresAt = s.IssuedAt.Add(time.Hour)
			})
			e.putSpec([]spec.StepEntry{e.indexOf(s, env)}, nil)
			return env
		}},
		{"unknown_cell", step.DetailCellUnknown, func(e *stepEnv) []byte {
			s, env := e.newStep("dev-cell-1", func(s *step.Step) { s.Cell = "nowhere" })
			e.putSpec([]spec.StepEntry{e.indexOf(s, env)}, nil)
			return env
		}},
		{"not_a_cell", step.DetailCellUnknown, func(e *stepEnv) []byte {
			s, env := e.newStep("dev-cp", nil)
			e.putSpec([]spec.StepEntry{e.indexOf(s, env)}, nil)
			return env
		}},
		{"cluster_mismatch", step.DetailClusterMismatch, func(e *stepEnv) []byte {
			s, env := e.newStep("dev-cell-1", func(s *step.Step) { s.Cluster.PodSubnet = "10.99.0.0/16" })
			e.putSpec([]spec.StepEntry{e.indexOf(s, env)}, nil)
			return env
		}},
		{"bootstrap_mismatch", step.DetailBootstrapMismatch, func(e *stepEnv) []byte {
			s, env := e.newStep("dev-cell-1", func(s *step.Step) { s.BootstrapSHA256 = strings.Repeat("b", 64) })
			e.putSpec([]spec.StepEntry{e.indexOf(s, env)}, nil)
			return env
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := newStepEnv(t)
			env := tc.make(e)
			_, err := e.ver.Check(env, false)
			if tc.detail == "" {
				if err != nil {
					t.Fatalf("Check = %v, want nil", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("Check = nil, want %s", tc.detail)
			}
			if got := detailOfCheck(t, err); got != tc.detail {
				t.Errorf("detail = %s, want %s", got, tc.detail)
			}
		})
	}
}

func TestStepVerifierDigestOnlyAfterSignature(t *testing.T) {
	_, rogue := newKey(t)
	e := newStepEnv(t)
	s, env := e.newStepKey(rogue, "dev-cell-1", nil)
	e.putSpec([]spec.StepEntry{e.indexOf(s, env)}, nil)
	for name, bad := range map[string][]byte{
		"rogue":    env,
		"unsigned": stripSignatures(t, env),
		"garbage":  []byte("not json"),
	} {
		if _, err := e.ver.Check(bad, false); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
	if n := e.digests.Load(); n != 0 {
		t.Errorf("Digest ran %d times for steps that did not verify, want 0", n)
	}
	_, good := e.indexed("dev-cell-1", nil)
	if _, err := e.ver.Check(good, false); err != nil {
		t.Fatal(err)
	}
	if n := e.digests.Load(); n != 1 {
		t.Errorf("Digest ran %d times for a good step, want 1", n)
	}
}

func TestStepVerifierDigestCache(t *testing.T) {
	e := newStepEnv(t)
	_, env := e.indexed("dev-cell-1", nil)
	for range 2 {
		if _, err := e.ver.Check(env, true); err != nil {
			t.Fatal(err)
		}
	}
	if n := e.digests.Load(); n != 1 {
		t.Errorf("two cached checks ran Digest %d times, want 1", n)
	}
	if _, err := e.ver.Check(env, false); err != nil {
		t.Fatal(err)
	}
	if n := e.digests.Load(); n != 2 {
		t.Errorf("an uncached check made %d calls in all, want 2", n)
	}
	if _, err := e.ver.Check(env, true); err != nil {
		t.Fatal(err)
	}
	if n := e.digests.Load(); n != 2 {
		t.Errorf("a cached check right after an uncached one made %d calls, want 2", n)
	}
	e.clock.Advance(11 * time.Second)
	if _, err := e.ver.Check(env, true); err != nil {
		t.Fatal(err)
	}
	if n := e.digests.Load(); n != 3 {
		t.Errorf("a cached check after 11 s made %d calls, want 3", n)
	}
	// A changed digest shows after the cache expires, and at once for an uncached check.
	e.digest.Store(strings.Repeat("c", 64))
	if _, err := e.ver.Check(env, true); err != nil {
		t.Errorf("cached check within 10 s: %v", err)
	}
	if _, err := e.ver.Check(env, false); detailOfCheck(t, err) != step.DetailBootstrapMismatch {
		t.Errorf("uncached check = %v, want bootstrap_mismatch", err)
	}
}

func TestStepVerifierTwoKeys(t *testing.T) {
	e := newStepEnv(t)
	newPub, newPriv := newKey(t)
	e.setKeys(e.pub, newPub)
	s1, env1 := e.newStep("dev-cell-1", nil)
	s2, env2 := e.newStepKey(newPriv, "dev-cell-2", nil)
	e.putSpec([]spec.StepEntry{e.indexOf(s1, env1), e.indexOf(s2, env2)}, nil)
	for name, env := range map[string][]byte{"old key": env1, "new key": env2} {
		if _, err := e.ver.Check(env, false); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	e.setKeys(newPub)
	if _, err := e.ver.Check(env1, false); detailOfCheck(t, err) != step.DetailSignatureInvalid {
		t.Errorf("old key after removal = %v, want signature_invalid", err)
	}
	if _, err := e.ver.Check(env2, false); err != nil {
		t.Errorf("new key after removal of the old: %v", err)
	}
}

func TestStepVerifierIndex(t *testing.T) {
	t.Run("unindexed", func(t *testing.T) {
		e := newStepEnv(t)
		_, env := e.newStep("dev-cell-1", nil)
		if _, err := e.ver.Check(env, false); detailOfCheck(t, err) != step.DetailSpecBehind {
			t.Fatalf("at issuedAt: %v, want spec_behind", err)
		}
		e.clock.Advance(119 * time.Second)
		if _, err := e.ver.Check(env, false); detailOfCheck(t, err) != step.DetailSpecBehind {
			t.Fatalf("at 119 s: %v, want spec_behind", err)
		}
		e.clock.Advance(2 * time.Second)
		if _, err := e.ver.Check(env, false); detailOfCheck(t, err) != step.DetailStepUnindexed {
			t.Fatalf("after 2 min: %v, want step_unindexed", err)
		}
	})
	t.Run("other_sha", func(t *testing.T) {
		e := newStepEnv(t)
		s, env := e.newStep("dev-cell-1", nil)
		e.putSpec([]spec.StepEntry{{Name: s.Cell, StepID: s.ID, StepSHA256: strings.Repeat("e", 64)}}, nil)
		if _, err := e.ver.Check(env, false); detailOfCheck(t, err) != step.DetailSpecBehind {
			t.Fatalf("within 2 min: %v, want spec_behind", err)
		}
		e.clock.Advance(3 * time.Minute)
		if _, err := e.ver.Check(env, false); detailOfCheck(t, err) != step.DetailStepUnindexed {
			t.Fatalf("after 2 min: %v, want step_unindexed", err)
		}
	})
	t.Run("other_cell_entry", func(t *testing.T) {
		e := newStepEnv(t)
		s, env := e.newStep("dev-cell-1", nil)
		ent := e.indexOf(s, env)
		ent.Name = "dev-cell-2"
		e.putSpec([]spec.StepEntry{ent}, nil)
		if _, err := e.ver.Check(env, false); err == nil {
			t.Fatal("a step indexed under another cell passed")
		}
	})
	t.Run("dropped_id", func(t *testing.T) {
		e := newStepEnv(t)
		s, env := e.indexed("dev-cell-1", nil)
		if _, err := e.ver.Check(env, false); err != nil {
			t.Fatal(err)
		}
		e.putSpec(nil, nil)
		_ = s
		if _, err := e.ver.Check(env, false); detailOfCheck(t, err) != step.DetailStepUnindexed {
			t.Fatalf("a dropped ID within 2 min: %v, want step_unindexed at once", err)
		}
	})
	t.Run("dropped_id_forgotten_after_256", func(t *testing.T) {
		e := newStepEnv(t)
		s, env := e.indexed("dev-cell-1", nil)
		e.putSpec(nil, nil)
		for range 257 {
			s2, env2 := e.newStep("dev-cell-2", nil)
			e.putSpec([]spec.StepEntry{e.indexOf(s2, env2)}, nil)
		}
		e.putSpec(nil, nil)
		_ = s
		if _, err := e.ver.Check(env, false); detailOfCheck(t, err) != step.DetailSpecBehind {
			t.Fatalf("an ID that left the memory of 256: %v, want the plan rule spec_behind", err)
		}
	})
}
