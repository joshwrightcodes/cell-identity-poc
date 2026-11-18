package hostsvc

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"

	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmtapi"
	"github.com/joshwrightcodes/cell-identity-poc/internal/spec"
	"github.com/joshwrightcodes/cell-identity-poc/internal/step"
)

const (
	cellControllerID = "spiffe://dev.env.poc.internal/cp/cell-controller"
	mgmtAPIID        = "spiffe://mgmt.poc.internal/api"
)

var requestIDRE = regexp.MustCompile(`^[0-9a-f]{16}$`)

func (ae *actorEnv) stepHandler() http.Handler {
	return NewStepHandler(ae.ver, ae.a, jsonLogger(ae.logs), ae.clock.Now)
}

func request(h http.Handler, method, path string, body []byte, peer string) *httptest.ResponseRecorder {
	ctx := context.Background()
	if peer != "" {
		ctx = context.WithValue(ctx, peerCtxKey{}, spiffeid.RequireFromString(peer))
	}
	req := httptest.NewRequestWithContext(ctx, method, path, bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func putStep(h http.Handler, id string, body []byte) *httptest.ResponseRecorder {
	return request(h, http.MethodPut, mgmtapi.StepPath(id), body, cellControllerID)
}

// checkDenied checks that the answer is a Denied body with a request ID and nothing else.
func checkDenied(t *testing.T, rec *httptest.ResponseRecorder, status int, retryAfter string) {
	t.Helper()
	if rec.Code != status {
		t.Errorf("status = %d, want %d (body %s)", rec.Code, status, rec.Body.String())
	}
	if got := rec.Header().Get("Retry-After"); got != retryAfter {
		t.Errorf("Retry-After = %q, want %q", got, retryAfter)
	}
	var m map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatalf("body %q: %v", rec.Body.String(), err)
	}
	if len(m) != 2 || m["error"] != mgmtapi.DeniedError || !requestIDRE.MatchString(m["request_id"].(string)) {
		t.Errorf("body = %v, want only error denied and a 16 hex request_id", m)
	}
}

func TestStepHandlerAccepts(t *testing.T) {
	ae := newActorEnv(t, nil)
	h := ae.stepHandler()
	s, env := ae.indexed("dev-cell-1", nil)
	rec := putStep(h, s.ID, env)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	var st mgmtapi.StepStatus
	if err := json.Unmarshal(rec.Body.Bytes(), &st); err != nil || st.ID != s.ID || st.State != mgmtapi.StepQueued || !mgmtapi.ValidStepStatus(st) {
		t.Errorf("answer = %+v %v", st, err)
	}
	if rec2 := putStep(h, s.ID, env); rec2.Code != http.StatusOK {
		t.Errorf("repeated PUT = %d", rec2.Code)
	}
	if n := len(ae.j.List()); n != 1 {
		t.Errorf("entries = %d, want 1", n)
	}
	get := request(h, http.MethodGet, mgmtapi.StepPath(s.ID), nil, cellControllerID)
	if get.Code != http.StatusOK || !strings.Contains(get.Body.String(), s.ID) {
		t.Errorf("GET = %d %s", get.Code, get.Body.String())
	}
}

func TestStepHandlerRefusals(t *testing.T) {
	_, rogue := newKey(t)
	type row struct {
		name       string
		status     int
		retryAfter string
		make       func(ae *actorEnv) (id string, body []byte)
	}
	indexedWith := func(s step.Step, env []byte) func(ae *actorEnv) {
		return func(ae *actorEnv) { ae.putSpec([]spec.StepEntry{ae.indexOf(s, env)}, nil) }
	}
	_ = indexedWith
	rows := []row{
		{"unsigned", 403, "", func(ae *actorEnv) (string, []byte) {
			s, env := ae.indexed("dev-cell-1", nil)
			return s.ID, stripSignatures(t, env)
		}},
		{"rogue_key", 403, "", func(ae *actorEnv) (string, []byte) {
			s, env := ae.newStepKey(rogue, "dev-cell-1", nil)
			ae.putSpec([]spec.StepEntry{ae.indexOf(s, env)}, nil)
			return s.ID, env
		}},
		{"tampered", 403, "", func(ae *actorEnv) (string, []byte) {
			s, env := ae.indexed("dev-cell-1", nil)
			return s.ID, tamper(t, env, `"cell":"dev-cell-1"`, `"cell":"dev-cell-2"`)
		}},
		{"other_env", 403, "", func(ae *actorEnv) (string, []byte) {
			s, env := ae.newStep("dev-cell-1", func(s *step.Step) { s.Env = "prod" })
			ae.putSpec([]spec.StepEntry{ae.indexOf(s, env)}, nil)
			return s.ID, env
		}},
		{"unknown_cell", 403, "", func(ae *actorEnv) (string, []byte) {
			s, env := ae.newStep("dev-cell-1", func(s *step.Step) { s.Cell = "nowhere" })
			ae.putSpec([]spec.StepEntry{ae.indexOf(s, env)}, nil)
			return s.ID, env
		}},
		{"not_a_cell", 403, "", func(ae *actorEnv) (string, []byte) {
			s, env := ae.newStep("dev-cp", nil)
			ae.putSpec([]spec.StepEntry{ae.indexOf(s, env)}, nil)
			return s.ID, env
		}},
		{"cluster_mismatch", 403, "", func(ae *actorEnv) (string, []byte) {
			s, env := ae.newStep("dev-cell-1", func(s *step.Step) { s.Cluster.Issuer = "https://other.example" })
			ae.putSpec([]spec.StepEntry{ae.indexOf(s, env)}, nil)
			return s.ID, env
		}},
		{"bootstrap_mismatch", 403, "", func(ae *actorEnv) (string, []byte) {
			s, env := ae.newStep("dev-cell-1", func(s *step.Step) { s.BootstrapSHA256 = strings.Repeat("9", 64) })
			ae.putSpec([]spec.StepEntry{ae.indexOf(s, env)}, nil)
			return s.ID, env
		}},
		{"expired", 403, "", func(ae *actorEnv) (string, []byte) {
			s, env := ae.newStep("dev-cell-1", func(s *step.Step) { s.ExpiresAt = s.IssuedAt.Add(step.MinTTL) })
			ae.putSpec([]spec.StepEntry{ae.indexOf(s, env)}, nil)
			ae.clock.Advance(step.MinTTL)
			return s.ID, env
		}},
		{"spec_behind", 503, "30", func(ae *actorEnv) (string, []byte) {
			s, env := ae.newStep("dev-cell-1", nil)
			return s.ID, env
		}},
		{"unindexed", 403, "", func(ae *actorEnv) (string, []byte) {
			s, env := ae.newStep("dev-cell-1", nil)
			ae.clock.Advance(3 * time.Minute)
			return s.ID, env
		}},
		{"dropped_id", 403, "", func(ae *actorEnv) (string, []byte) {
			s, env := ae.indexed("dev-cell-1", nil)
			ae.putSpec(nil, nil)
			return s.ID, env
		}},
		{"garbage", 403, "", func(ae *actorEnv) (string, []byte) { return strings.Repeat("a", 32), []byte("garbage") }},
	}
	for _, tc := range rows {
		t.Run(tc.name, func(t *testing.T) {
			ae := newActorEnv(t, nil)
			h := ae.stepHandler()
			id, body := tc.make(ae)
			checkDenied(t, putStep(h, id, body), tc.status, tc.retryAfter)
			if n := len(ae.j.List()); n != 0 {
				t.Errorf("a refused step reached the actor: %d entries", n)
			}
		})
	}
	t.Run("conflict", func(t *testing.T) {
		ae := newActorEnv(t, nil)
		h := ae.stepHandler()
		s, env := ae.indexed("dev-cell-1", nil)
		if rec := putStep(h, s.ID, env); rec.Code != 200 {
			t.Fatal(rec.Body.String())
		}
		// Same ID, other content: the other body is indexed too, so only the journal can refuse it.
		s2 := s
		s2.BootstrapSHA256 = s.BootstrapSHA256
		s2.ExpiresAt = s.ExpiresAt.Add(time.Hour)
		env2, err := step.Sign(s2, ae.priv)
		if err != nil {
			t.Fatal(err)
		}
		ae.putSpec([]spec.StepEntry{ae.indexOf(s2, env2)}, nil)
		checkDenied(t, putStep(h, s.ID, env2), 403, "")
		if !strings.Contains(ae.logs.String(), `"step_conflict"`) {
			t.Errorf("log lacks step_conflict: %s", ae.logs.String())
		}
	})
	t.Run("queue_full", func(t *testing.T) {
		ae := newActorEnv(t, func(c *ActorConfig) { c.QueueCap = 1 })
		h := ae.stepHandler()
		s1, e1 := ae.newStep("dev-cell-1", nil)
		s2, e2 := ae.newStep("dev-cell-2", nil)
		ae.putSpec([]spec.StepEntry{ae.indexOf(s1, e1), ae.indexOf(s2, e2)}, nil)
		if rec := putStep(h, s1.ID, e1); rec.Code != 200 {
			t.Fatal(rec.Body.String())
		}
		checkDenied(t, putStep(h, s2.ID, e2), 503, "60")
		if !strings.Contains(ae.logs.String(), `"queue_full"`) {
			t.Errorf("log lacks queue_full: %s", ae.logs.String())
		}
	})
	t.Run("journal_corrupt", func(t *testing.T) {
		ae := newActorEnv(t, nil)
		h := ae.stepHandler()
		s, env := ae.indexed("dev-cell-1", nil)
		ae.j.mu.Lock()
		ae.j.corrupt = true
		ae.j.mu.Unlock()
		checkDenied(t, putStep(h, s.ID, env), 503, "")
		checkDenied(t, request(h, http.MethodGet, mgmtapi.StepPath(s.ID), nil, cellControllerID), 503, "")
	})
	t.Run("method", func(t *testing.T) {
		ae := newActorEnv(t, nil)
		checkDenied(t, request(ae.stepHandler(), http.MethodDelete, mgmtapi.StepPath(strings.Repeat("a", 32)), nil, cellControllerID), 405, "")
	})
}

func TestStepHandlerBodyLimit(t *testing.T) {
	ae := newActorEnv(t, nil)
	h := ae.stepHandler()
	s, env := ae.indexed("dev-cell-1", nil)
	big := append(bytes.Clone(env), bytes.Repeat([]byte(" "), maxStepBody)...)
	checkDenied(t, putStep(h, s.ID, big), 403, "")
	if len(ae.j.List()) != 0 {
		t.Error("an oversize body reached the actor")
	}
	if rec := putStep(h, s.ID, env); rec.Code != 200 {
		t.Errorf("a body within the limit: %d", rec.Code)
	}
}

func TestStepHandlerPathIDMismatch(t *testing.T) {
	ae := newActorEnv(t, nil)
	h := ae.stepHandler()
	s, env := ae.indexed("dev-cell-1", nil)
	checkDenied(t, putStep(h, strings.Repeat("0", 32), env), 403, "")
	checkDenied(t, putStep(h, "short", env), 403, "")
	if len(ae.j.List()) != 0 {
		t.Error("a mismatched path reached the actor")
	}
	if rec := putStep(h, s.ID, env); rec.Code != 200 {
		t.Errorf("matching path: %d", rec.Code)
	}
}

func TestStepHandlerRateLimit(t *testing.T) {
	ae := newActorEnv(t, nil)
	h := ae.stepHandler()
	id := strings.Repeat("1", 32)
	for i := 1; i <= 20; i++ {
		if rec := putStep(h, id, []byte("x")); rec.Code != 403 {
			t.Fatalf("PUT %d = %d, want 403 from the verifier", i, rec.Code)
		}
	}
	checkDenied(t, putStep(h, id, []byte("x")), 503, "60")
	// A different peer has its own bucket.
	other := request(h, http.MethodPut, mgmtapi.StepPath(id), []byte("x"), "spiffe://dev.env.poc.internal/cp/other")
	if other.Code != 403 {
		t.Errorf("other peer = %d, want its own bucket", other.Code)
	}
	ae.clock.Advance(3 * time.Second)
	s, env := ae.indexed("dev-cell-1", nil)
	if rec := putStep(h, s.ID, env); rec.Code != 200 {
		t.Errorf("PUT 3 s later = %d, want one verified", rec.Code)
	}
	checkDenied(t, putStep(h, id, []byte("x")), 503, "60")
	ae.clock.Advance(30 * time.Second)
	for i := 0; i < 10; i++ {
		if rec := putStep(h, id, []byte("x")); rec.Code != 403 {
			t.Fatalf("after 30 s, PUT %d = %d", i, rec.Code)
		}
	}
	checkDenied(t, putStep(h, id, []byte("x")), 503, "60")
}

func TestStepHandlerGetUnknown(t *testing.T) {
	ae := newActorEnv(t, nil)
	h := ae.stepHandler()
	checkDenied(t, request(h, http.MethodGet, mgmtapi.StepPath(strings.Repeat("a", 32)), nil, cellControllerID), 404, "")
	checkDenied(t, request(h, http.MethodGet, mgmtapi.StepPath("nope"), nil, cellControllerID), 404, "")
}

func TestRotatePutBeforeSpec(t *testing.T) {
	ae := newActorEnv(t, nil)
	h := ae.stepHandler()
	s, env := ae.indexed("dev-cell-1", nil)
	if rec := putStep(h, s.ID, env); rec.Code != 200 {
		t.Fatal(rec.Body.String())
	}
	s2, env2 := ae.rotated(s)
	// The re-signed envelope comes before the spec that indexes it, and two minutes after issuedAt.
	ae.clock.Advance(5 * time.Minute)
	checkDenied(t, putStep(h, s.ID, env2), 503, "30")
	if got, _ := ae.j.Get(s.ID); got.EnvelopeSHA256 != envelopeDigest(env) || got.KeyEpoch != 1 {
		t.Error("the journal changed before the spec arrived")
	}
	// The same envelope and a lower epoch answer with the status, whatever the index says.
	ae.putSpec([]spec.StepEntry{ae.indexOf(s2, env2)}, nil)
	if rec := putStep(h, s.ID, env); rec.Code != 200 {
		t.Errorf("old envelope after the spec moved on: %d %s", rec.Code, rec.Body.String())
	}
	if rec := putStep(h, s.ID, env2); rec.Code != 200 {
		t.Fatalf("re-signed envelope after the spec: %d %s", rec.Code, rec.Body.String())
	}
	if got, _ := ae.j.Get(s.ID); got.EnvelopeSHA256 != envelopeDigest(env2) || got.KeyEpoch != 2 {
		t.Errorf("entry after the swap: %+v", got)
	}
}

func TestSpecHandlerBodyLimit(t *testing.T) {
	ae := newActorEnv(t, nil)
	h := NewSpecHandler(ae.spec, jsonLogger(ae.logs))
	put := func(body []byte) *httptest.ResponseRecorder {
		return request(h, http.MethodPut, mgmtapi.HostSpecPath, body, mgmtAPIID)
	}
	env := signSpecAt(t, ae.priv, "dev", 1, 3, 0)
	checkDenied(t, put(append(bytes.Clone(env), bytes.Repeat([]byte(" "), maxSpecBody)...)), 403, "")
	if _, ok := ae.spec.Current(); ok {
		t.Error("an oversize spec was kept")
	}
	if rec := put(env); rec.Code != 200 {
		t.Fatalf("a good spec: %d %s", rec.Code, rec.Body.String())
	}
	if rec := put(env); rec.Code != 200 {
		t.Errorf("the same spec again: %d", rec.Code)
	}
	checkDenied(t, put(signSpecAt(t, ae.priv, "dev", 1, 2, 0)), 403, "")
	checkDenied(t, put([]byte("nope")), 403, "")
	checkDenied(t, request(h, http.MethodGet, mgmtapi.HostSpecPath, nil, mgmtAPIID), 405, "")
}
