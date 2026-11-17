//go:build e2e

package e2e

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"os/exec"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmtapi"
	"github.com/joshwrightcodes/cell-identity-poc/internal/spec"
	"github.com/joshwrightcodes/cell-identity-poc/internal/step"
)

var sixteenHex = regexp.MustCompile(`^[0-9a-f]{16}$`)

// TestM6CellsRequested: after the M5 state moved into the catalog, both cells are requested. A request that the migration made has
// the request ID migrated, and a portal request has 16 hex characters. The live spec holds no step, because no step exists yet.
func TestM6CellsRequested(t *testing.T) {
	status := mgmtStatus(t)
	for _, cell := range clustersWith(t, agentCellSet) {
		var got *struct {
			requested bool
			id        string
		}
		for _, c := range status.Cells {
			if c.Name == cell {
				got = &struct {
					requested bool
					id        string
				}{c.Requested, c.RequestID}
			}
		}
		if got == nil || !got.requested {
			t.Errorf("cell %s is not requested at mgmtd: %+v", cell, got)
			continue
		}
		if got.id != "migrated" && !sixteenHex.MatchString(got.id) {
			t.Errorf("cell %s has the request ID %q, want migrated or 16 hexadecimal characters", cell, got.id)
		}
	}
	raw, err := base64.StdEncoding.DecodeString(mgmtSigningPub(t))
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := fetchSpec(t, envdCert(t))
	if err != nil {
		t.Fatal(err)
	}
	s, _, err := spec.Verify(bundle.Spec, []ed25519.PublicKey{raw})
	if err != nil {
		t.Fatalf("the spec does not verify: %v", err)
	}
	if len(s.Steps) != 0 || len(bundle.Steps) != 0 {
		t.Errorf("the live spec holds steps %v and envelopes for %d cells, want none", s.Steps, len(bundle.Steps))
	}
}

// TestM6HostServiceStepRoute: the step route admits only the cell controller, and the key and spec routes only mgmtd. The log of the
// host service holds peer_not_allowed for the refusal, and the body holds only denied and a request ID.
func TestM6HostServiceStepRoute(t *testing.T) {
	controller := cellControllerCert(t)
	api := mgmtAPICert(t)
	missing := step.NewID()

	t.Run("the cell controller reads an unknown step as 404", func(t *testing.T) {
		a := hostDo(t, hostClient(t, controller, false), http.MethodGet, mgmtapi.StepPath(missing), nil)
		if a.Code != http.StatusNotFound || a.denied() == "" {
			t.Fatalf("got %d %s, want 404 with the Denied body", a.Code, a.Body)
		}
	})

	t.Run("mgmtd is refused on the step route", func(t *testing.T) {
		a := hostDo(t, hostClient(t, api, false), http.MethodGet, mgmtapi.StepPath(missing), nil)
		rid := a.denied()
		if a.Code != http.StatusForbidden || rid == "" {
			t.Fatalf("got %d %s, want 403 with the Denied body", a.Code, a.Body)
		}
		if line := hostLog(t, rid); !strings.Contains(line, `"reason":"peer_not_allowed"`) {
			t.Fatalf("the log of the host service for request %s is %q, want the reason peer_not_allowed", rid, line)
		}
	})

	t.Run("the cell controller is refused on the key route and the spec route", func(t *testing.T) {
		client := hostClient(t, controller, false)
		for name, a := range map[string]hostAnswer{
			"keys": hostDo(t, client, http.MethodGet, mgmtapi.KeysPath("dev-cell-1"), nil),
			"spec": hostDo(t, client, http.MethodPut, mgmtapi.HostSpecPath, strings.NewReader("{}")),
		} {
			if a.Code != http.StatusForbidden || a.denied() == "" {
				t.Errorf("%s route: got %d %s, want 403 with the Denied body", name, a.Code, a.Body)
			}
		}
	})

	t.Run("other peers fail the handshake", func(t *testing.T) {
		gateway := svidCertOf(t, cpClusterName, "spiffe://dev.env.poc.internal/cp/gateway")
		if err := handshakeRefused(&gateway); err != nil {
			t.Errorf("the SVID of cp/gateway: %v", err)
		}
		if err := handshakeRefused(nil); err != nil {
			t.Errorf("no certificate: %v", err)
		}
		// A forged certificate for cp/cell-controller, presented from the Mac under a CA that the host service never saw, fails the
		// handshake. This shows the trust check of the server. It does not show the reach from a pod in rogue, because no tool of the
		// harness presents a certificate from a pod: that case is a residual for the records of Task 11.
		forged := foreignCert(t, "dev.env.poc.internal", cellControllerID)
		if err := handshakeRefused(&forged); err != nil {
			t.Errorf("a certificate for cp/cell-controller under another CA: %v", err)
		}
	})
}

// svidCertOf mints an SVID for id in cluster as a TLS certificate.
func svidCertOf(t *testing.T, cluster, id string) tls.Certificate {
	t.Helper()
	_, cert := svidFor(t, cluster, id)
	return cert
}

// TestM6HostServiceKnowsSpec: the host service holds the spec that mgmtd signed last, within 60 s.
func TestM6HostServiceKnowsSpec(t *testing.T) {
	signed := mgmtStatus(t).Signed
	deadline := time.Now().Add(60 * time.Second)
	for {
		out, err := exec.Command("mise", "run", "hostsvc:serve", "--", "status").Output()
		if err != nil {
			t.Fatalf("mise run hostsvc:serve -- status: %v", err)
		}
		var st struct {
			SpecRevision *spec.Revision `json:"spec_revision"`
		}
		if err := json.Unmarshal(bytes.TrimSpace(out), &st); err != nil {
			t.Fatalf("hostsvc:serve -- status is no object: %v\n%s", err, out)
		}
		if st.SpecRevision != nil && *st.SpecRevision == signed {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("after 60 s the host service has the spec revision %v, and mgmtd signed %v", st.SpecRevision, signed)
		}
		time.Sleep(3 * time.Second)
	}
}

// detailGap keeps two refusals with the same detail at least 11 s apart. The handlers log a refusal with one detail at most once in
// each 10 s window, so a later subtest of a group would find no log line.
type detailGap struct {
	mu   sync.Mutex
	last map[string]time.Time
}

func (g *detailGap) wait(detail string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.last == nil {
		g.last = map[string]time.Time{}
	}
	if prev, ok := g.last[detail]; ok {
		if d := 11*time.Second - time.Since(prev); d > 0 {
			time.Sleep(d)
		}
	}
	g.last[detail] = time.Now()
}

// stripSignatures returns the envelope with an empty signature list.
func stripSignatures(t *testing.T, envelope []byte) []byte {
	t.Helper()
	var env map[string]json.RawMessage
	if err := json.Unmarshal(envelope, &env); err != nil {
		t.Fatal(err)
	}
	env["signatures"] = json.RawMessage("[]")
	out, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// TestM6UnsignedStepRefused: each subtest sends one step with cell dev-cell-2 to the host service. The answer is 403 with only
// denied and a request ID. The log holds the detail as the reason. The journal gets no entry, and no cluster appears or goes.
func TestM6UnsignedStepRefused(t *testing.T) {
	cert := cellControllerCert(t)
	before := kindClusters(t)
	gap := &detailGap{}

	// refuse sends the envelope and checks the refusal. id is the step ID in the path.
	refuse := func(t *testing.T, id string, envelope []byte, detail string) {
		t.Helper()
		gap.wait(detail)
		a := putStep(t, cert, id, envelope)
		rid := a.denied()
		if a.Code != http.StatusForbidden || rid == "" {
			t.Fatalf("got %d %s, want 403 with the Denied body", a.Code, a.Body)
		}
		var body map[string]any
		if err := json.Unmarshal(a.Body, &body); err != nil || len(body) != 2 || body["error"] != "denied" || !sixteenHex.MatchString(body["requestId"].(string)) {
			t.Fatalf("the body is %s, want only error denied and a request ID of 16 hexadecimal characters", a.Body)
		}
		if line := hostLog(t, rid); !strings.Contains(line, `"reason":"`+detail+`"`) {
			t.Fatalf("the log of the host service for request %s is %q, want the reason %s", rid, line, detail)
		}
		if _, ok := hostSteps(t)[id]; ok {
			t.Fatalf("the journal of the host service holds the refused step %s", id)
		}
		if after := kindClusters(t); !slices.Equal(after, before) {
			t.Fatalf("the clusters changed: %v, was %v", after, before)
		}
	}
	signed := func(t *testing.T, mutate func(*step.Step)) (step.Step, []byte) {
		t.Helper()
		s := testStep(t, m6TestCell)
		if mutate != nil {
			mutate(&s)
		}
		return s, stepSign(t, s)
	}

	t.Run("unsigned", func(t *testing.T) {
		s, env := signed(t, nil)
		refuse(t, s.ID, stripSignatures(t, env), step.DetailSignatureInvalid)
	})
	t.Run("rogue_key", func(t *testing.T) {
		_, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		s := testStep(t, m6TestCell)
		env, err := step.Sign(s, key)
		if err != nil {
			t.Fatal(err)
		}
		refuse(t, s.ID, env, step.DetailSignatureInvalid)
	})
	t.Run("tampered", func(t *testing.T) {
		s, env := signed(t, nil)
		var e struct {
			PayloadType string            `json:"payloadType"`
			Payload     string            `json:"payload"`
			Signatures  []json.RawMessage `json:"signatures"`
		}
		if err := json.Unmarshal(env, &e); err != nil {
			t.Fatal(err)
		}
		raw, err := base64.StdEncoding.DecodeString(e.Payload)
		if err != nil {
			t.Fatal(err)
		}
		var body map[string]any
		if err := json.Unmarshal(raw, &body); err != nil {
			t.Fatal(err)
		}
		body["expiresAt"] = time.Now().Add(20 * time.Hour).UTC().Format(time.RFC3339)
		raw, _ = json.Marshal(body)
		e.Payload = base64.StdEncoding.EncodeToString(raw)
		tampered, _ := json.Marshal(e)
		refuse(t, s.ID, tampered, step.DetailSignatureInvalid)
	})
	t.Run("op_envelope", func(t *testing.T) {
		_, env := opSign(t, m6TestCell, "m6-not-a-step", 10*time.Minute)
		refuse(t, step.NewID(), env, step.DetailPayloadInvalid)
	})
	t.Run("spec_envelope", func(t *testing.T) {
		bundle, err := fetchSpec(t, envdCert(t))
		if err != nil {
			t.Fatal(err)
		}
		refuse(t, step.NewID(), bundle.Spec, step.DetailPayloadInvalid)
	})
	t.Run("other_env", func(t *testing.T) {
		s, env := signed(t, func(s *step.Step) { s.Env = "other" })
		refuse(t, s.ID, env, step.DetailEnvMismatch)
	})
	t.Run("unknown_cell", func(t *testing.T) {
		s, env := signed(t, func(s *step.Step) { s.Cell = "no-such-cell" })
		refuse(t, s.ID, env, step.DetailCellUnknown)
	})
	t.Run("not_a_cell", func(t *testing.T) {
		s, env := signed(t, func(s *step.Step) { s.Cell = "rogue" })
		refuse(t, s.ID, env, step.DetailCellUnknown)
	})
	t.Run("cluster_mismatch", func(t *testing.T) {
		s, env := signed(t, func(s *step.Step) { s.Cluster.PodSubnet = "10.99.0.0/16" })
		refuse(t, s.ID, env, step.DetailClusterMismatch)
	})
	t.Run("expired", func(t *testing.T) {
		s, env := signed(t, func(s *step.Step) {
			now := time.Now().UTC().Truncate(time.Second)
			s.IssuedAt, s.ExpiresAt = now.Add(-2*time.Hour), now.Add(-time.Hour)
		})
		refuse(t, s.ID, env, step.DetailExpired)
	})
	// unindexed: a signed step that no spec indexes. The index check comes after the static checks. The host service answers 503
	// spec_behind (Retry-After 30) until 2 minutes after issuedAt, and then 403 step_unindexed.
	t.Run("unindexed", func(t *testing.T) {
		s, env := signed(t, nil)
		first := putStepOnce(t, cert, s.ID, env)
		if first.Code != http.StatusServiceUnavailable || first.RetryAfter != "30" || first.denied() == "" {
			t.Fatalf("the first PUT got %d (Retry-After %q) %s, want 503 spec_behind with Retry-After 30", first.Code, first.RetryAfter, first.Body)
		}
		if line := hostLog(t, first.denied()); !strings.Contains(line, `"reason":"spec_behind"`) {
			t.Fatalf("the log for request %s is %q, want spec_behind", first.denied(), line)
		}
		if d := time.Until(s.IssuedAt.Add(2*time.Minute + 5*time.Second)); d > 0 {
			time.Sleep(d)
		}
		refuse(t, s.ID, env, step.DetailStepUnindexed)
	})
}

// TestM6PortalRefusals: the portal refuses a cell outside the catalog, counts a request for a requested cell as a success, and has no
// step to retry or cancel for a cell that has none.
func TestM6PortalRefusals(t *testing.T) {
	reasonOf := func(t *testing.T, m map[string]any, err error) string {
		t.Helper()
		if err == nil {
			t.Fatalf("the portal accepted the command: %v", m)
		}
		r, _ := m["reason"].(string)
		return r
	}
	t.Run("a cell outside the catalog", func(t *testing.T) {
		m, err := portal(t, "request", "--cell", "rogue")
		if got := reasonOf(t, m, err); got != "cell_unknown" {
			t.Fatalf("reason %q, want cell_unknown (%v)", got, err)
		}
	})
	t.Run("a cell that is requested already", func(t *testing.T) {
		before := mgmtStatus(t).Signed
		m, err := portal(t, "request", "--cell", "dev-cell-1")
		if err != nil {
			t.Fatalf("request for a requested cell failed: %v", err)
		}
		already, _ := m["alreadyRequested"].([]any)
		if len(already) != 1 || already[0] != "dev-cell-1" {
			t.Fatalf("answer %v, want alreadyRequested [dev-cell-1]", m)
		}
		if after := mgmtStatus(t).Signed; after != before {
			t.Fatalf("the signed revision moved from %v to %v, but a request for a requested cell changes nothing", before, after)
		}
	})
	t.Run("retry with no step", func(t *testing.T) {
		m, err := portal(t, "retry", "--cell", "dev-cell-1")
		if got := reasonOf(t, m, err); got != "no_step" {
			t.Fatalf("reason %q, want no_step (%v)", got, err)
		}
	})
	t.Run("cancel with no step", func(t *testing.T) {
		m, err := portal(t, "cancel", "--cell", "dev-cell-1")
		if got := reasonOf(t, m, err); got != "no_step" {
			t.Fatalf("reason %q, want no_step (%v)", got, err)
		}
	})
}

// TestM6StepRouteFlood: a peer that floods the step route does not starve the key route, and it does not starve the key check of
// mgmtd. It runs in two phases, because the router applies the cap of 4 requests in flight for one peer before the token bucket:
//
//  1. After a wait of 61 s (the bucket is full at 20 tokens), 10 PUTs hold a slot with a slow body for 5 s. At most 4 pass the cap, so at
//     least 6 get 503 at once. While they hold their slots, a key read of mgmtd answers 200 within 2 s, and mgmt -- keycheck answers
//     neither issuer_unavailable nor issuer_untrusted.
//  2. After the slow PUTs end (their slots are free), 40 PUTs run on one connection, one after the other (the listener negotiates no HTTP/2).
//     Each passes the cap, so the bucket decides. The 4 slow PUTs that passed the cap took 4 tokens, so 16 are left, and one token returns
//     each 3 s. The run takes a few seconds, so the bound is: at least 14 answers of 403 (the tokens, less a margin for a slow run) and at
//     most 23 (20 tokens plus the refill of a run of up to 9 s). The other answers are 503 with Retry-After 60, and the log of the host
//     service holds the reason rate_limited for at least one of them. With no bucket, all 40 would get 403; with a cap that is checked
//     after the bucket, the first phase would give fewer than 6 answers of 503.
func TestM6StepRouteFlood(t *testing.T) {
	controller := cellControllerCert(t)
	api := mgmtAPICert(t)
	s := testStep(t, m6TestCell)
	unsigned := stripSignatures(t, stepSign(t, s))
	t.Log("waiting 61 s for the bucket of the cell controller to fill")
	time.Sleep(61 * time.Second)

	type result struct {
		answer hostAnswer
		err    error
		took   time.Duration
	}
	slow := make([]result, 10)
	var wg sync.WaitGroup
	for i := range slow {
		wg.Add(1)
		go func() {
			defer wg.Done()
			pr, pw := io.Pipe()
			go func() {
				_, _ = pw.Write(unsigned[:10])
				time.Sleep(5 * time.Second)
				_, _ = pw.Write(unsigned[10:])
				_ = pw.Close()
			}()
			begin := time.Now()
			a, err := hostDoErr(hostClient(t, controller, false), http.MethodPut, mgmtapi.StepPath(s.ID), pr)
			slow[i] = result{a, err, time.Since(begin)}
		}()
	}
	time.Sleep(500 * time.Millisecond)

	keysDone := make(chan result, 1)
	go func() {
		begin := time.Now()
		a, err := hostDoErr(hostClient(t, api, false), http.MethodGet, mgmtapi.KeysPath("dev-cell-1"), nil)
		keysDone <- result{a, err, time.Since(begin)}
	}()
	keys := <-keysDone
	if keys.err != nil || keys.answer.Code != http.StatusOK || keys.took > 2*time.Second {
		t.Errorf("the key read during the flood: %+v, want 200 within 2 s", keys)
	}
	out, _ := mgmtCtlErr("keycheck", "--cell", "dev-cell-1")
	if strings.Contains(out, "issuer_unavailable") || strings.Contains(out, "issuer_untrusted") {
		t.Errorf("mgmt -- keycheck during the flood: %s", out)
	}
	wg.Wait()

	var fast []hostAnswer
	one := hostClient(t, controller, true)
	for range 40 {
		a, err := hostDoErr(one, http.MethodPut, mgmtapi.StepPath(s.ID), bytes.NewReader(unsigned))
		if err != nil {
			t.Fatalf("a flood PUT failed: %v", err)
		}
		fast = append(fast, a)
	}

	busy := 0
	for i, r := range slow {
		if r.err != nil {
			t.Errorf("slow PUT %d: %v", i, r.err)
			continue
		}
		if r.answer.Code == http.StatusServiceUnavailable && r.took < 2*time.Second {
			busy++
		}
	}
	if busy < 6 {
		t.Errorf("%d of the 10 slow PUTs got 503 at once, want at least 6 (at most 4 in flight for one peer)", busy)
	}
	denied403, busy503 := 0, 0
	rateLimited := false
	for _, a := range fast {
		switch a.Code {
		case http.StatusForbidden:
			denied403++
		case http.StatusServiceUnavailable:
			busy503++
			if a.RetryAfter != "60" {
				t.Errorf("a 503 has Retry-After %q, want 60", a.RetryAfter)
			}
			if !rateLimited && strings.Contains(hostLog(t, a.denied()), `"reason":"rate_limited"`) {
				rateLimited = true
			}
		default:
			t.Errorf("a flood PUT got %d %s, want 403 or 503", a.Code, a.Body)
		}
	}
	if denied403 > 23 || denied403 < 14 {
		t.Errorf("%d answers of 403, want 14 to 23: the bucket must stop the rest before any signature check, and the tokens must pass", denied403)
	}
	if !rateLimited {
		t.Errorf("no 503 of the 40 PUTs has the reason rate_limited in the log of the host service")
	}
	t.Logf("flood: %d answers of 403 and %d of 503 for the 40 PUTs, %d of 10 slow PUTs answered 503 at once", denied403, busy503, busy)
}
