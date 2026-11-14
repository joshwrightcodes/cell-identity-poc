package cellctl

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/joshwrightcodes/cell-identity-poc/internal/envd"
	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmtapi"
	"github.com/joshwrightcodes/cell-identity-poc/internal/spec"
	"github.com/joshwrightcodes/cell-identity-poc/internal/step"
)

var t0 = time.Unix(1_800_000_000, 0).UTC()

// world holds the signing keys and the clock of a test.
type world struct {
	t     *testing.T
	pub   ed25519.PublicKey
	priv  ed25519.PrivateKey
	rogue ed25519.PrivateKey
	env   string
}

func newWorld(t *testing.T) *world {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, rogue, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &world{t: t, pub: pub, priv: priv, rogue: rogue, env: "dev"}
}

func (w *world) keys() []ed25519.PublicKey { return []ed25519.PublicKey{w.pub} }

// item is a signed step with its envelope.
type item struct {
	s   step.Step
	env []byte
}

// step returns a valid step for cell, issued a minute before t0 plus offset.
func (w *world) step(cell string, offset time.Duration) step.Step {
	return step.Step{
		ID: step.NewID(), Env: w.env, Cell: cell, Kind: step.KindCellCreate, Version: 1, KeyEpoch: 1,
		IssuedAt: t0.Add(-time.Minute + offset), ExpiresAt: t0.Add(6*time.Hour + offset),
		Cluster:         step.ClusterRef{PodSubnet: "10.20.0.0/16", ServiceSubnet: "10.21.0.0/16", Issuer: "https://" + cell + ".example:6443"},
		BootstrapSHA256: step.TestDigest,
	}
}

func (w *world) sign(s step.Step) item {
	w.t.Helper()
	env, err := step.Sign(s, w.priv)
	if err != nil {
		w.t.Fatal(err)
	}
	return item{s: s, env: env}
}

func (w *world) item(cell string, offset time.Duration) item { return w.sign(w.step(cell, offset)) }

func payloadOf(t *testing.T, env []byte) []byte {
	t.Helper()
	var e struct{ Payload string }
	if err := json.Unmarshal(env, &e); err != nil {
		t.Fatal(err)
	}
	b, err := base64.StdEncoding.DecodeString(e.Payload)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func (w *world) entry(it item) spec.StepEntry {
	return spec.StepEntry{Name: it.s.Cell, StepID: it.s.ID, StepSHA256: step.PayloadSHA256(payloadOf(w.t, it.env))}
}

func (w *world) specEnv(counter uint64, key ed25519.PrivateKey, entries ...spec.StepEntry) string {
	w.t.Helper()
	env, err := spec.Sign(spec.Spec{Env: w.env, Revision: spec.Revision{Epoch: 1, Counter: counter}, Steps: entries}, key)
	if err != nil {
		w.t.Fatal(err)
	}
	return string(env)
}

// data builds the content of the steps ConfigMap for a good spec that indexes every item.
func (w *world) data(counter uint64, items ...item) map[string]string {
	w.t.Helper()
	var entries []spec.StepEntry
	for _, it := range items {
		entries = append(entries, w.entry(it))
	}
	sortEntries(entries)
	d := map[string]string{SpecKey: w.specEnv(counter, w.priv, entries...)}
	for _, it := range items {
		d[it.s.Cell+StepSuffix] = string(it.env)
	}
	return d
}

func sortEntries(e []spec.StepEntry) {
	for i := range e {
		for j := i + 1; j < len(e); j++ {
			if e[j].Name < e[i].Name {
				e[i], e[j] = e[j], e[i]
			}
		}
	}
}

func TestKeyNamesMatchEnvd(t *testing.T) {
	if SpecKey != envd.SpecKey || StepSuffix != envd.StepSuffix || maxEnvelope != envd.MaxStepBytes {
		t.Fatal("the steps ConfigMap keys differ from the ones envd writes")
	}
}

type want struct{ id, cell, detail string }

// refusalRow is one way that the steps ConfigMap can be wrong. build returns the content, the
// refusals that Load must give and the number of steps that still verify.
type refusalRow struct {
	name  string
	mark  spec.Revision
	steps int
	build func() (map[string]string, []want)
}

func refusalRows(t *testing.T, w *world) []refusalRow {
	good := w.item("dev-cell-1", 0)
	other := w.item("dev-cell-2", time.Second)
	one := spec.Revision{Epoch: 1, Counter: 1}
	modified := func(cell string, mut func(*step.Step), detail string) func() (map[string]string, []want) {
		return func() (map[string]string, []want) {
			s := w.step(cell, 0)
			mut(&s)
			return w.data(2, w.sign(s)), []want{{s.ID, s.Cell, detail}}
		}
	}
	return []refusalRow{
		{"good", one, 1, func() (map[string]string, []want) { return w.data(2, good), nil }},
		{"unsigned_spec", one, 0, func() (map[string]string, []want) {
			d := w.data(2, good)
			d[SpecKey] = w.specEnv(2, w.rogue, w.entry(good))
			return d, []want{{"", "", step.DetailSignatureInvalid}}
		}},
		{"older_spec", spec.Revision{Epoch: 1, Counter: 5}, 0, func() (map[string]string, []want) {
			return w.data(2, good), []want{{"", "", step.DetailRevisionOld}}
		}},
		{"unindexed_step", one, 1, func() (map[string]string, []want) {
			d := w.data(2, good)
			d[other.s.Cell+StepSuffix] = string(other.env)
			return d, []want{{other.s.ID, other.s.Cell, step.DetailStepUnindexed}}
		}},
		{"step_digest", one, 0, func() (map[string]string, []want) {
			e := w.entry(good)
			e.StepSHA256 = strings.Repeat("0", 64)
			d := w.data(2, good)
			d[SpecKey] = w.specEnv(2, w.priv, e)
			return d, []want{{good.s.ID, good.s.Cell, step.DetailStepUnindexed}}
		}},
		{"step_id_differs", one, 0, func() (map[string]string, []want) {
			e := w.entry(good)
			e.StepID = step.NewID()
			d := w.data(2, good)
			d[SpecKey] = w.specEnv(2, w.priv, e)
			return d, []want{{e.StepID, good.s.Cell, step.DetailStepUnindexed}}
		}},
		{"step_missing", one, 0, func() (map[string]string, []want) {
			d := w.data(2, good)
			delete(d, good.s.Cell+StepSuffix)
			return d, []want{{good.s.ID, good.s.Cell, step.DetailStepMissing}}
		}},
		{"step_unsigned", one, 0, func() (map[string]string, []want) {
			d := w.data(2, good)
			body := base64.StdEncoding.EncodeToString(payloadOf(t, good.env))
			d[good.s.Cell+StepSuffix] = `{"payloadType":"` + step.PayloadType + `","payload":"` + body + `","signatures":[]}`
			return d, []want{{good.s.ID, good.s.Cell, step.DetailSignatureInvalid}}
		}},
		{"step_rogue_key", one, 0, func() (map[string]string, []want) {
			rogue, err := step.Sign(good.s, w.rogue)
			if err != nil {
				t.Fatal(err)
			}
			d := w.data(2, good)
			d[good.s.Cell+StepSuffix] = string(rogue)
			return d, []want{{good.s.ID, good.s.Cell, step.DetailSignatureInvalid}}
		}},
		{"step_other_env", one, 0, modified("dev-cell-1", func(s *step.Step) { s.Env = "prod" }, step.DetailEnvMismatch)},
		{"step_expired", one, 0, modified("dev-cell-1", func(s *step.Step) {
			s.IssuedAt, s.ExpiresAt = t0.Add(-7*time.Hour), t0.Add(-time.Hour)
		}, step.DetailExpired)},
		{"step_not_yet_valid", one, 0, modified("dev-cell-1", func(s *step.Step) {
			s.IssuedAt, s.ExpiresAt = t0.Add(10*time.Minute), t0.Add(time.Hour)
		}, step.DetailNotYetValid)},
		{"step_wrong_key_name", one, 0, func() (map[string]string, []want) {
			// The index names dev-cell-1, and its key holds the step of dev-cell-2.
			e := w.entry(other)
			e.Name = "dev-cell-1"
			return map[string]string{
				SpecKey:                   w.specEnv(2, w.priv, e),
				"dev-cell-1" + StepSuffix: string(other.env),
			}, []want{{other.s.ID, "dev-cell-1", step.DetailPayloadInvalid}}
		}},
	}
}

func TestLoadRefuses(t *testing.T) {
	w := newWorld(t)
	for _, row := range refusalRows(t, w) {
		t.Run(row.name, func(t *testing.T) {
			d, wantRefused := row.build()
			steps, rev, refused := Load(d, "dev", w.keys(), row.mark, t0)
			if len(steps) != row.steps {
				t.Errorf("%d steps, want %d", len(steps), row.steps)
			}
			var got []want
			for _, r := range refused {
				if r.State != mgmtapi.StepRefused || r.Reason != step.Code {
					t.Errorf("refused entry %+v", r)
				}
				if r.ID != "" && !mgmtapi.ValidStepStatus(r) {
					t.Errorf("entry %+v is not a valid step status", r)
				}
				got = append(got, want{r.ID, r.Cell, r.Detail})
			}
			if !reflect.DeepEqual(got, wantRefused) {
				t.Errorf("refused %+v, want %+v", got, wantRefused)
			}
			specLevel := len(wantRefused) == 1 && wantRefused[0].id == ""
			if specLevel && rev != row.mark {
				t.Errorf("a refused spec moved the mark to %+v", rev)
			}
			if !specLevel && rev != (spec.Revision{Epoch: 1, Counter: 2}) {
				t.Errorf("revision %+v", rev)
			}
		})
	}
}

func TestLoadRefusalClears(t *testing.T) {
	w := newWorld(t)
	a := w.item("dev-cell-1", 0)
	d := w.data(2, a)
	full := d[a.s.Cell+StepSuffix]
	delete(d, a.s.Cell+StepSuffix)
	steps, _, refused := Load(d, "dev", w.keys(), spec.Revision{}, t0)
	if len(steps) != 0 || len(refused) != 1 || refused[0].Detail != step.DetailStepMissing {
		t.Fatalf("first read: %d steps, %+v", len(steps), refused)
	}
	d[a.s.Cell+StepSuffix] = full
	steps, _, refused = Load(d, "dev", w.keys(), spec.Revision{}, t0)
	if len(steps) != 1 || len(refused) != 0 {
		t.Fatalf("second read: %d steps, %+v", len(steps), refused)
	}
}

func TestLoadOrdersByIssuedAtThenCell(t *testing.T) {
	w := newWorld(t)
	late := w.item("dev-cell-1", 2*time.Second)
	b := w.item("dev-cell-3", time.Second)
	c := w.item("dev-cell-2", time.Second)
	steps, _, refused := Load(w.data(2, late, b, c), "dev", w.keys(), spec.Revision{}, t0)
	if len(refused) != 0 || len(steps) != 3 {
		t.Fatalf("%d steps, %+v", len(steps), refused)
	}
	got := []string{steps[0].Step.Cell, steps[1].Step.Cell, steps[2].Step.Cell}
	if !reflect.DeepEqual(got, []string{"dev-cell-2", "dev-cell-3", "dev-cell-1"}) {
		t.Fatalf("order %v", got)
	}
	if string(steps[2].Envelope) != string(late.env) {
		t.Error("envelope bytes differ from the ConfigMap")
	}
}

func TestLoadNeedsASpec(t *testing.T) {
	w := newWorld(t)
	_, _, refused := Load(map[string]string{}, "dev", w.keys(), spec.Revision{}, t0)
	if len(refused) != 1 || refused[0].ID != "" || refused[0].Detail != step.DetailPayloadInvalid {
		t.Fatalf("%+v", refused)
	}
	_, _, refused = Load(w.data(2), "dev", nil, spec.Revision{}, t0)
	if len(refused) != 1 || refused[0].Detail != step.DetailSignatureInvalid {
		t.Fatalf("no key: %+v", refused)
	}
	_, _, refused = Load(w.data(2), "other", w.keys(), spec.Revision{}, t0)
	if len(refused) != 1 || refused[0].Detail != step.DetailEnvMismatch {
		t.Fatalf("wrong env: %+v", refused)
	}
}

func encodeKey(k []byte) string { return base64.StdEncoding.EncodeToString(k) + "\n" }
