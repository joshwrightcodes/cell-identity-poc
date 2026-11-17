package executor

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	mrand "math/rand/v2"
	"slices"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clienttesting "k8s.io/client-go/testing"

	"github.com/joshwrightcodes/cell-identity-poc/internal/gwapi"
	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmtapi"
	"github.com/joshwrightcodes/cell-identity-poc/internal/op"
	"github.com/joshwrightcodes/cell-identity-poc/internal/proof"
	"github.com/joshwrightcodes/cell-identity-poc/internal/telemetry"
)

func resultOf(t *testing.T, f gwapi.Frame) op.Result {
	t.Helper()
	if f.Item == nil {
		t.Fatalf("frame %+v has no item", f)
	}
	var res op.Result
	if err := json.Unmarshal(f.Item.Body, &res); err != nil {
		t.Fatal(err)
	}
	return res
}

func TestStreamHelloThenClaim(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newFixture(t)
		defer f.stop()
		// Two applied operations give the records the fences (3,7) and (2,9).
		for _, fe := range []op.Fence{fence(3, 7), fence(2, 9)} {
			if res := f.exec.Execute(t.Context(), f.rig.sign(f.rig.operation(testKind, "{}")), fe); res.Outcome != op.OutcomeApplied {
				t.Fatalf("seed %+v", res)
			}
		}
		f.start()
		waitFor(t, 5*time.Second, "a claim", func() bool { return len(f.g.frames(gwapi.TypeClaim)) > 0 })

		f.g.mu.Lock()
		first, second := f.g.seen[0], f.g.seen[1]
		bindings := slices.Clone(f.g.bindings)
		f.g.mu.Unlock()
		if first.f.Type != gwapi.TypeHello || second.f.Type != gwapi.TypeClaim {
			t.Fatalf("first frames %q then %q, want hello then claim", first.f.Type, second.f.Type)
		}
		if first.f.LastFence != fence(3, 7) {
			t.Fatalf("lastFence %+v, want the highest fence in the records (3,7)", first.f.LastFence)
		}
		if len(bindings) != 1 || tokenAudience(first.f.Token) != proof.HelloAudience("cell-1", bindings[0]) {
			t.Fatalf("hello token %q does not hold the hello audience for binding %v", first.f.Token, bindings)
		}
	})
}

func TestStreamOneClaimInFlight(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newFixture(t)
		defer f.stop()
		f.g.handler = func(s *gwStream) {
			// The gateway reads claims and does not answer the first one for 25 s.
			answered := false
			s.loop(func(fr gwapi.Frame) bool {
				if fr.Type == gwapi.TypeClaim && !answered {
					answered = true
					go func() {
						time.Sleep(25 * time.Second)
						_ = s.send(gwapi.Frame{Type: gwapi.TypeNone})
					}()
					return true
				}
				return false
			})
		}
		f.start()
		time.Sleep(24 * time.Second)
		if n := len(f.g.frames(gwapi.TypeClaim)); n != 1 {
			t.Fatalf("%d claims while the first is unanswered, want 1", n)
		}
		waitFor(t, 20*time.Second, "a claim after the answer", func() bool { return len(f.g.frames(gwapi.TypeClaim)) >= 2 })
	})
}

func TestStreamClaimRate(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newFixture(t)
		defer f.stop()
		f.g.handler = func(s *gwStream) {
			// Each answer comes with new work, so the cell would claim as fast as it may.
			claims := 0
			s.loop(func(fr gwapi.Frame) bool {
				if fr.Type != gwapi.TypeClaim {
					return false
				}
				// Fake time stands still while a stream claims without a gap. Stop answering then.
				if claims++; claims > 100 {
					t.Error("more than 100 claims: the claim rate is not limited")
					return true
				}
				_ = s.send(gwapi.Frame{Type: gwapi.TypeNone})
				_ = s.send(gwapi.Frame{Type: gwapi.TypeWork})
				_ = s.send(gwapi.Frame{Type: gwapi.TypeWork})
				return true
			})
		}
		f.start()
		time.Sleep(3 * time.Second)
		claims := f.g.frames(gwapi.TypeClaim)
		if len(claims) < 10 {
			t.Fatalf("%d claims in 3 s, want about 15 for the rate of 5 a second", len(claims))
		}
		if len(claims) > 16 {
			t.Fatalf("%d claims in 3 s, want at most 16", len(claims))
		}
		for i := 1; i < len(claims); i++ {
			if gap := claims[i].at.Sub(claims[i-1].at); gap < 190*time.Millisecond {
				t.Fatalf("claims %d and %d are %v apart, want at least 200ms", i-1, i, gap)
			}
		}
	})
}

func TestStreamWaitsForSVID(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var mu sync.Mutex
		calls := 0
		f := newFixture(t)
		inner := f.cfg.TLS
		f.cfg.TLS = func() (*tlsConfig, error) {
			mu.Lock()
			defer mu.Unlock()
			if calls++; calls <= 3 {
				return nil, errNoSVID
			}
			return inner()
		}
		var sleeps []time.Duration
		f.cfg.Sleep = func(ctx context.Context, d time.Duration) error {
			mu.Lock()
			sleeps = append(sleeps, d)
			mu.Unlock()
			return sleepFake(ctx, d)
		}
		f.start()
		defer f.stop()
		waitFor(t, 2*time.Minute, "a hello", func() bool { return len(f.g.frames(gwapi.TypeHello)) > 0 })
		mu.Lock()
		defer mu.Unlock()
		if len(sleeps) != 3 || calls != 4 {
			t.Fatalf("%d sleeps and %d TLS calls, want 3 and 4", len(sleeps), calls)
		}
		if f.g.mintedCount() != 1 {
			t.Fatalf("%d tokens before the SVID, want only the hello token", f.g.mintedCount())
		}
	})
}

func TestStreamRefusesWrongGatewayID(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newFixture(t)
		other := newGatewayWithCA(t, f.g.ca, "spiffe://dev.env.poc.internal/cp/other")
		f.cfg.dial = other.dial
		f.start()
		time.Sleep(2 * time.Minute)
		f.cancel()
		<-f.done
		other.close()
		f.g.close()
		other.mu.Lock()
		defer other.mu.Unlock()
		if other.dials < 3 {
			t.Fatalf("%d dials, want the stream to keep trying", other.dials)
		}
		if other.streams != 0 || len(other.seen) != 0 || len(other.minted) != 0 {
			t.Fatalf("the wrong gateway saw %d streams, %d frames, %d tokens", other.streams, len(other.seen), len(other.minted))
		}
		if f.g.mintedCount() != 0 {
			t.Fatalf("%d tokens were minted for the wrong gateway", f.g.mintedCount())
		}
	})
}

func TestStreamReconnectsWithBackoff(t *testing.T) {
	first := func(seed uint64) (time.Duration, []time.Duration) {
		var firstSleep []time.Duration
		synctest.Test(t, func(t *testing.T) {
			f := newFixture(t)
			rng := mrand.New(mrand.NewPCG(seed, 7))
			var mu sync.Mutex
			f.cfg.Rand = rng.Float64
			ctx, cancel := context.WithCancel(context.Background())
			f.cfg.Sleep = func(c context.Context, d time.Duration) error {
				mu.Lock()
				firstSleep = append(firstSleep, d)
				n := len(firstSleep)
				mu.Unlock()
				if n >= 9 {
					cancel()
				}
				return sleepFake(c, d)
			}
			// The gateway welcomes each stream and refuses it as full at once.
			f.g.handler = func(s *gwStream) { _ = s.send(gwapi.Frame{Type: gwapi.TypeRefused, Reason: gwapi.ReasonReplicaCap}) }
			f.done = make(chan error, 1)
			f.cancel = cancel
			go func() { f.done <- RunStream(ctx, f.cfg) }()
			<-ctx.Done()
			f.stop()
		})
		return firstSleep[0], firstSleep
	}
	a, sleeps := first(1)
	b, _ := first(2)
	if a == b {
		t.Fatalf("two seeds gave the same first sleep %v", a)
	}
	for i, d := range sleeps {
		if d < time.Second || d > 30*time.Second {
			t.Fatalf("sleep %d is %v, want between 1s and 30s", i, d)
		}
	}
	if sleeps[len(sleeps)-1] < 15*time.Second {
		t.Fatalf("the backoff did not grow: %v", sleeps)
	}
	// From the sixth failure on the base is the cap, and the jitter stays.
	if distinct := len(slices.Compact(slices.Sorted(slices.Values(sleeps[6:])))); distinct < 2 {
		t.Fatalf("the sleeps at the cap are all equal: %v", sleeps[6:])
	}
}

// The binding is read from each new connection. A hello that reused the first binding would fail
// the check of the gateway on the second stream.
func TestStreamHelloBindingSurvivesRedial(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newFixture(t)
		defer f.stop()
		f.g.handler = func(s *gwStream) {} // each stream ends after the welcome
		f.start()
		waitFor(t, 2*time.Minute, "three streams", func() bool { return f.g.streamCount() >= 3 })
		f.g.mu.Lock()
		defer f.g.mu.Unlock()
		if f.g.helloBad != 0 {
			t.Fatalf("%d hellos failed the binding check", f.g.helloBad)
		}
		if len(f.g.bindings) < 3 || f.g.bindings[0] == f.g.bindings[1] || f.g.bindings[1] == f.g.bindings[2] {
			t.Fatalf("bindings %v, want a different binding for each connection", f.g.bindings)
		}
	})
}

func TestStreamReconnectsOnSilentGateway(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newFixture(t)
		defer f.stop()
		f.start()
		waitFor(t, 5*time.Second, "the first stream", func() bool { return len(f.g.frames(gwapi.TypeClaim)) > 0 })
		start := time.Now()
		f.g.mu.Lock()
		f.g.conns[0].freeze()
		f.g.mu.Unlock()
		waitFor(t, 45*time.Second, "a second stream", func() bool { return len(f.g.frames(gwapi.TypeHello)) >= 2 })
		t.Logf("the second hello came %v after the gateway went silent", time.Since(start))
	})
}

func TestStreamReconnectsOnSVIDUpdate(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newFixture(t)
		var sleeps int
		var mu sync.Mutex
		f.cfg.Sleep = func(ctx context.Context, d time.Duration) error {
			mu.Lock()
			sleeps++
			mu.Unlock()
			return sleepFake(ctx, d)
		}
		defer f.stop()
		f.start()
		waitFor(t, 5*time.Second, "the first stream", func() bool { return len(f.g.frames(gwapi.TypeClaim)) > 0 })
		f.updates <- struct{}{}
		waitFor(t, 5*time.Second, "a second hello", func() bool { return len(f.g.frames(gwapi.TypeHello)) >= 2 })
		mu.Lock()
		defer mu.Unlock()
		if sleeps != 0 {
			t.Fatalf("%d backoff sleeps, want none for a new SVID", sleeps)
		}
	})
}

// failingClaims makes every ConfigMap create fail, so each claim ends as a local lease_lost.
func failingClaims(f *streamFixture) {
	f.rig.client.PrependReactor("create", "configmaps", func(clienttesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("the API server is down")
	})
}

func fillStore(t *testing.T, f *streamFixture) {
	t.Helper()
	for i := range maxRecords {
		cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s%032x", recordPrefix, i),
			Namespace: DefaultNamespace, Labels: recordLabels(),
		}, Data: map[string]string{recordKey: encodeRecord(storedRecord{State: stateReported, UpdatedAt: f.rig.clock.Now()})}}
		if _, err := f.rig.client.CoreV1().ConfigMaps(DefaultNamespace).Create(t.Context(), cm, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestStreamDoesNotReportLocalOutcomes(t *testing.T) {
	for _, name := range []string{"lease_lost", "store_full"} {
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := newFixture(t)
				defer f.stop()
				if name == "lease_lost" {
					failingClaims(f)
				} else {
					fillStore(t, f)
				}
				for i := range 3 {
					l, _ := f.lease("s1."+string(rune('1'+i)), fence(1, uint64(i+1)))
					f.g.offer(l)
				}
				f.start()
				waitFor(t, 30*time.Second, "the leases to be taken", func() bool {
					f.g.mu.Lock()
					defer f.g.mu.Unlock()
					return len(f.g.queue) == 0
				})
				time.Sleep(35 * time.Second)
				if n := len(f.g.frames(gwapi.TypeResult)); n != 0 {
					t.Fatalf("%d result frames for local outcomes, want none", n)
				}
				if len(f.g.frames(gwapi.TypeClaim)) < 4 {
					t.Fatal("the stream stopped claiming")
				}
			})
		})
	}
}

// A new SVID ends the stream while an effect runs. The effect finishes, and the next stream sends the
// result.
func TestStreamExecutionSurvivesSVIDUpdate(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newFixture(t)
		defer f.stop()
		started, release := make(chan struct{}), make(chan struct{})
		kinds := f.rig.kinds()
		kinds["test.slow"] = func(ctx context.Context, _ *Executor, _ op.Operation) error {
			close(started)
			select {
			case <-release:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		f.cfg.Exec = f.rig.executor("uid-1", func(c *Config) { c.Kinds = kinds })
		o := f.rig.operation("test.slow", "{}")
		f.g.offer(gwapi.Frame{Type: gwapi.TypeLease, LeaseID: "s1.1", Envelope: f.rig.sign(o), Fence: fence(1, 1)})
		f.start()
		<-started
		f.updates <- struct{}{}
		time.Sleep(2 * time.Second)
		close(release)
		waitFor(t, 20*time.Second, "the result on a second stream", func() bool {
			for _, r := range f.g.frames(gwapi.TypeResult) {
				if r.stream == 2 && resultOf(t, r.f).Outcome == op.OutcomeApplied {
					return true
				}
			}
			return false
		})
	})
}

func TestStreamResendsUntilFinal(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newFixture(t, func(c *StreamConfig) { c.ResendEvery = 31 * time.Second })
		defer f.stop()
		l, id := f.lease("s1.1", fence(1, 5))
		f.g.offer(l)
		f.start()
		waitFor(t, 5*time.Second, "the result", func() bool { return len(f.g.frames(gwapi.TypeResult)) > 0 })

		first := f.g.frames(gwapi.TypeResult)[0].f
		res := resultOf(t, first)
		if first.LeaseID != "s1.1" || res.OpID != id || res.Outcome != op.OutcomeApplied || first.Fence != fence(1, 5) {
			t.Fatalf("first result frame %+v, result %+v", first, res)
		}
		if first.Item.Kind != gwapi.KindResult || first.Item.Cell != "cell-1" || first.Item.OpID != id {
			t.Fatalf("item %+v", first.Item)
		}
		if want := proof.ReportAudience("cell-1", "result", first.Item.Body); tokenAudience(first.Item.Token) != want {
			t.Fatalf("token audience %q, want %q", tokenAudience(first.Item.Token), want)
		}
		body, _ := json.Marshal(res)
		if !bytes.Equal(body, first.Item.Body) {
			t.Fatalf("body %s is not the compact Marshal %s", first.Item.Body, body)
		}

		// The ack came at once. Two resend periods later the record is still applied.
		time.Sleep(70 * time.Second)
		pending, err := f.exec.Pending(t.Context())
		if err != nil || len(pending) != 1 {
			t.Fatalf("pending %v, %v after an ack, want the one result", pending, err)
		}
		results := f.g.frames(gwapi.TypeResult)
		if len(results) < 3 {
			t.Fatalf("%d result frames after 70 s, want the first and two resends", len(results))
		}
		for _, r := range results[1:] {
			if r.f.LeaseID != "" {
				t.Fatalf("a resend carries lease ID %q", r.f.LeaseID)
			}
			if r.f.Item.Token == first.Item.Token {
				t.Fatal("a resend reused the token")
			}
		}

		_ = f.g.current().send(gwapi.Frame{Type: gwapi.TypeFinal, OpID: id, Outcome: mgmtapi.OutcomeAccepted})
		waitFor(t, 5*time.Second, "the record to be marked reported", func() bool {
			p, _ := f.exec.Pending(t.Context())
			return len(p) == 0
		})
		n := len(f.g.frames(gwapi.TypeResult))
		time.Sleep(95 * time.Second)
		if got := len(f.g.frames(gwapi.TypeResult)); got != n {
			t.Fatalf("%d result frames after final, want no more than %d", got, n)
		}
	})
}

func TestStreamResendsAfterRetry(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newFixture(t, func(c *StreamConfig) { c.ResendEvery = 24 * time.Hour })
		defer f.stop()
		l, id := f.lease("s1.1", fence(1, 5))
		f.g.offer(l)
		f.start()
		waitFor(t, 5*time.Second, "the result", func() bool { return len(f.g.frames(gwapi.TypeResult)) > 0 })
		time.Sleep(3 * time.Second)
		if n := len(f.g.frames(gwapi.TypeResult)); n != 1 {
			t.Fatalf("%d result frames before the retry, want 1", n)
		}
		// A retry sends the result again, whatever its reason is. The gateway may add reasons later.
		reasons := []string{"issuer_unavailable", "store", "internal", "proof_invalid", "", "a_reason_nobody_listed"}
		var lastIAT int64
		if _, err := fmtSscan(f.g.frames(gwapi.TypeResult)[0].f.Item.Token, &lastIAT); err != nil {
			t.Fatal(err)
		}
		for i, reason := range reasons {
			time.Sleep(31 * time.Second)
			_ = f.g.current().send(gwapi.Frame{Type: gwapi.TypeRetry, OpID: id, Reason: reason})
			waitFor(t, 5*time.Second, "a result after a retry with reason "+reason, func() bool {
				return len(f.g.frames(gwapi.TypeResult)) >= i+2
			})
			b := f.g.frames(gwapi.TypeResult)[i+1].f
			if b.LeaseID != "" || resultOf(t, b).OpID != id {
				t.Fatalf("frame after retry %q: %+v", reason, b)
			}
			var iat int64
			if _, err := fmtSscan(b.Item.Token, &iat); err != nil {
				t.Fatal(err)
			}
			if iat <= lastIAT {
				t.Fatalf("retry %q: the token has iat %d, want newer than %d", reason, iat, lastIAT)
			}
			lastIAT = iat
		}
		if pending, _ := f.exec.Pending(t.Context()); len(pending) != 1 {
			t.Fatalf("%d pending after a retry, want the result kept", len(pending))
		}
	})
}

func TestStreamForgedRefusalsLimited(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newFixture(t)
		defer f.stop()
		_, other, _ := ed25519.GenerateKey(rand.Reader)
		forged := func(n uint64) gwapi.Frame {
			env, err := op.Sign(f.rig.operation(testKind, "{}"), other)
			if err != nil {
				t.Fatal(err)
			}
			return gwapi.Frame{Type: gwapi.TypeLease, LeaseID: "s1.f", Envelope: env, Fence: fence(1, n)}
		}
		for i := range 5 {
			f.g.offer(forged(uint64(i + 1)))
		}
		f.start()
		waitFor(t, 20*time.Second, "five forged results to be counted", func() bool { return f.exec.Counts().ForgedSeen >= 5 })
		time.Sleep(2 * time.Second)
		results := f.g.frames(gwapi.TypeResult)
		if len(results) != 1 {
			t.Fatalf("%d result frames for 5 forged envelopes in 10 s, want 1", len(results))
		}
		if res := resultOf(t, results[0].f); res.OpID != "" || res.Reason != op.ReasonSignatureInvalid {
			t.Fatalf("result %+v", res)
		}
		time.Sleep(10 * time.Second)
		f.g.offer(forged(9))
		waitFor(t, 15*time.Second, "the next forged result after 10 s", func() bool { return len(f.g.frames(gwapi.TypeResult)) == 2 })
		if got := f.exec.Counts().ForgedSeen; got != 6 {
			t.Fatalf("ForgedSeen %d, want 6", got)
		}
	})
}

func TestStreamStatusEvery30s(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newFixture(t)
		defer f.stop()
		f.start()
		time.Sleep(5*time.Minute + time.Second)
		st := f.g.frames(gwapi.TypeStatus)
		if len(st) < 8 || len(st) > 14 {
			t.Fatalf("%d status frames in 5 minutes, want about 10", len(st))
		}
		var lastSeq uint64
		for i, s := range st {
			var body op.Status
			if err := json.Unmarshal(s.f.Item.Body, &body); err != nil {
				t.Fatal(err)
			}
			if body.Seq <= lastSeq || body.Cell != "cell-1" || body.PodUID != "uid-1" {
				t.Fatalf("status %d body %+v after seq %d", i, body, lastSeq)
			}
			lastSeq = body.Seq
			if s.f.Item.Kind != gwapi.KindStatus || tokenAudience(s.f.Item.Token) != proof.ReportAudience("cell-1", "status", s.f.Item.Body) {
				t.Fatalf("status item %+v", s.f.Item)
			}
			if i > 0 {
				if gap := s.at.Sub(st[i-1].at); gap < 24*time.Second || gap > 36*time.Second {
					t.Fatalf("status gap %v, want 30 s plus or minus 20%%", gap)
				}
			}
		}
	})
}

// With a 1 m SVID the stream ends after about 27 s. A status deadline that starts again with each stream never fires, so the
// deadline must outlive the stream: the status gap stays within StatusEvery plus the spread across streams of 20 s.
func TestStreamStatusDeadlineSurvivesNewStreams(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newFixture(t)
		defer f.stop()
		f.start()
		for range 9 {
			time.Sleep(20 * time.Second)
			f.updates <- struct{}{}
		}
		time.Sleep(5 * time.Second)
		if n := streamsStarted(f); n < 8 {
			t.Fatalf("%d streams started, want one for each SVID update", n)
		}
		st := f.g.frames(gwapi.TypeStatus)
		if len(st) < 5 {
			t.Fatalf("%d status frames in 3 minutes over streams of 20 s, want at least 5", len(st))
		}
		for i := 1; i < len(st); i++ {
			if gap := st[i].at.Sub(st[i-1].at); gap > 37*time.Second {
				t.Fatalf("status gap %v between status %d and %d, want at most 30 s plus 20%% spread plus a reconnect", gap, i-1, i)
			}
		}
	})
}

func TestStreamLogCarriesTraceID(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var out syncBuf
		f := newFixture(t)
		tp := sdktrace.NewTracerProvider(sdktrace.WithSampler(sdktrace.AlwaysSample()))
		f.cfg.Tracer = tp.Tracer("test")
		f.cfg.Log = telemetry.NewLogger(&out, slogDiscard{})
		defer f.stop()
		f.start()
		waitFor(t, 5*time.Second, "a claim", func() bool { return len(f.g.frames(gwapi.TypeClaim)) > 0 })
		var line map[string]any
		for _, l := range bytes.Split(out.bytes(), []byte("\n")) {
			var m map[string]any
			if json.Unmarshal(l, &m) == nil && m["msg"] == "stream open" {
				line = m
			}
		}
		if line == nil || line["trace_id"] == nil || line["trace_id"] == "" {
			t.Fatalf("no stream log line with trace_id in %s", out.bytes())
		}
	})
}

func streamsStarted(f *streamFixture) int { return len(f.g.frames(gwapi.TypeHello)) }

// A status that the gateway refuses as overloaded answers that item only. The stream stays, and
// its next status and claim go on it.
func TestStreamOverloadedStatusKeepsTheStream(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newFixture(t, func(c *StreamConfig) { c.StatusEvery = 5 * time.Second })
		defer f.stop()
		refused := false
		f.g.handler = func(s *gwStream) {
			s.loop(func(fr gwapi.Frame) bool {
				if fr.Type == gwapi.TypeStatus && !refused {
					refused = true
					_ = s.send(gwapi.Frame{Type: gwapi.TypeRefused, Reason: gwapi.ReasonOverloaded})
					return true
				}
				return false
			})
		}
		f.start()
		time.Sleep(75 * time.Second) // past the ack timeout of the refused item
		if n := streamsStarted(f); n != 1 {
			t.Fatalf("%d streams, want the first to stay open", n)
		}
		if n := len(f.g.frames(gwapi.TypeStatus)); n < 5 {
			t.Fatalf("%d status frames, want the stream to go on", n)
		}
	})
}

func TestStreamLevelRefusalEndsTheStream(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newFixture(t)
		defer f.stop()
		sent := false
		f.g.handler = func(s *gwStream) {
			s.loop(func(fr gwapi.Frame) bool {
				if fr.Type == gwapi.TypeClaim && !sent {
					sent = true
					_ = s.send(gwapi.Frame{Type: gwapi.TypeRefused, Reason: gwapi.ReasonReauth})
					return true
				}
				return false
			})
		}
		f.start()
		waitFor(t, 10*time.Second, "a second stream", func() bool { return streamsStarted(f) >= 2 })
	})
}

// final marks the record of its own op and no other.
func TestStreamFinalMarksOnlyItsOp(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newFixture(t, func(c *StreamConfig) { c.ResendEvery = 31 * time.Second })
		defer f.stop()
		a, idA := f.lease("s1.1", fence(1, 1))
		b, idB := f.lease("s1.2", fence(1, 2))
		f.g.offer(a, b)
		f.start()
		waitFor(t, 10*time.Second, "two results", func() bool { return len(f.g.frames(gwapi.TypeResult)) >= 2 })
		_ = f.g.current().send(gwapi.Frame{Type: gwapi.TypeFinal, OpID: idA, Outcome: mgmtapi.OutcomeAccepted})
		waitFor(t, 5*time.Second, "A to be reported", func() bool {
			p, _ := f.exec.Pending(t.Context())
			return len(p) == 1
		})
		p, _ := f.exec.Pending(t.Context())
		if len(p) != 1 || p[0].OpID != idB {
			t.Fatalf("pending %+v, want only the result of B", p)
		}
		before := len(f.g.frames(gwapi.TypeResult))
		time.Sleep(70 * time.Second)
		var again, forA int
		for _, r := range f.g.frames(gwapi.TypeResult)[before:] {
			switch resultOf(t, r.f).OpID {
			case idB:
				again++
			case idA:
				forA++
			}
		}
		if again == 0 || forA != 0 {
			t.Fatalf("after final for A: %d resends of B, %d of A, want some and none", again, forA)
		}
	})
}

// Each check that ends a dead stream has its own test. The others are set far away.
func TestStreamAppPongTimeoutAlone(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newFixture(t)
		defer f.stop()
		f.g.handler = func(s *gwStream) { s.loop(func(fr gwapi.Frame) bool { return fr.Type == gwapi.TypePing }) }
		f.start()
		time.Sleep(35 * time.Second)
		if n := streamsStarted(f); n != 1 {
			t.Fatalf("%d streams after 35 s, want the pong wait of 30 s from the first ping at 10 s to run on", n)
		}
		waitFor(t, 15*time.Second, "a new stream after the pong timeout", func() bool { return streamsStarted(f) >= 2 })
	})
}

func TestStreamH2PingTimeoutAlone(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newFixture(t, func(c *StreamConfig) { c.PongTimeout, c.AckTimeout = time.Hour, time.Hour })
		defer f.stop()
		f.start()
		waitFor(t, 5*time.Second, "the first stream", func() bool { return len(f.g.frames(gwapi.TypeClaim)) > 0 })
		f.g.mu.Lock()
		f.g.conns[0].freeze()
		f.g.mu.Unlock()
		waitFor(t, 45*time.Second, "a second stream from the transport ping alone", func() bool { return streamsStarted(f) >= 2 })
	})
}

func TestStreamAckTimeout(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newFixture(t, func(c *StreamConfig) { c.StatusEvery, c.AckTimeout = 5*time.Second, 12*time.Second })
		defer f.stop()
		f.g.handler = func(s *gwStream) { s.loop(func(fr gwapi.Frame) bool { return fr.Type == gwapi.TypeStatus }) }
		f.start()
		waitFor(t, 40*time.Second, "a new stream after an unacked status", func() bool { return streamsStarted(f) >= 2 })
	})
}

func TestStreamLeaseWithoutClaimIsIgnored(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newFixture(t)
		defer f.stop()
		l, _ := f.lease("s1.1", fence(1, 1))
		f.g.handler = func(s *gwStream) {
			sent := false
			s.loop(func(fr gwapi.Frame) bool {
				if fr.Type == gwapi.TypeClaim && !sent {
					sent = true
					_ = s.send(gwapi.Frame{Type: gwapi.TypeNone})
					_ = s.send(l)
					return true
				}
				return false
			})
		}
		f.start()
		time.Sleep(6 * time.Second)
		if n := f.rig.cnt.count(); n != 0 {
			t.Fatalf("%d effects ran for a lease that no claim asked for", n)
		}
		if n := len(f.g.frames(gwapi.TypeResult)); n != 0 {
			t.Fatalf("%d result frames", n)
		}
	})
}

// A claim that gets no answer ends the stream.
func TestStreamClaimWithoutAnswerEnds(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newFixture(t)
		defer f.stop()
		f.g.handler = func(s *gwStream) { s.loop(func(fr gwapi.Frame) bool { return fr.Type == gwapi.TypeClaim }) }
		f.start()
		time.Sleep(25 * time.Second)
		if n := streamsStarted(f); n != 1 {
			t.Fatalf("%d streams after 25 s, want the claim wait of 30 s to run on", n)
		}
		waitFor(t, 15*time.Second, "a new stream after the claim wait", func() bool { return streamsStarted(f) >= 2 })
	})
}

// Whatever sends a result again, the same op goes at most once in 30 s, also across streams.
func TestStreamResendLimitedPerOp(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newFixture(t, func(c *StreamConfig) { c.ResendEvery = 24 * time.Hour })
		defer f.stop()
		l, id := f.lease("s1.1", fence(1, 5))
		f.g.offer(l)
		f.start()
		waitFor(t, 5*time.Second, "the result", func() bool { return len(f.g.frames(gwapi.TypeResult)) > 0 })
		results := func() int { return len(f.g.frames(gwapi.TypeResult)) }
		time.Sleep(3 * time.Second)
		retry := func() { _ = f.g.current().send(gwapi.Frame{Type: gwapi.TypeRetry, OpID: id, Reason: "internal"}) }
		retry()
		waitFor(t, 5*time.Second, "the first resend", func() bool { return results() == 2 })
		time.Sleep(2 * time.Second)
		retry()
		time.Sleep(3 * time.Second)
		if n := results(); n != 2 {
			t.Fatalf("%d result frames after a second retry within 30 s, want 2", n)
		}
		f.updates <- struct{}{}
		waitFor(t, 5*time.Second, "a second stream", func() bool { return streamsStarted(f) >= 2 })
		time.Sleep(3 * time.Second)
		if n := results(); n != 2 {
			t.Fatalf("%d result frames after a new stream within 30 s, want 2", n)
		}
		time.Sleep(30 * time.Second)
		retry()
		waitFor(t, 5*time.Second, "a resend after 30 s", func() bool { return results() == 3 })
	})
}

func TestStreamRetryWithoutRecordIsLogged(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var out syncBuf
		f := newFixture(t)
		f.cfg.Log = slog.New(slog.NewJSONHandler(&out, nil))
		defer f.stop()
		f.start()
		waitFor(t, 5*time.Second, "a claim", func() bool { return len(f.g.frames(gwapi.TypeClaim)) > 0 })
		_ = f.g.current().send(gwapi.Frame{Type: gwapi.TypeRetry, OpID: "0123456789abcdef0123456789abcdef", Reason: "unknown_kid"})
		waitFor(t, 5*time.Second, "the log line", func() bool {
			for _, l := range bytes.Split(out.bytes(), []byte("\n")) {
				var m map[string]any
				if json.Unmarshal(l, &m) == nil && m["level"] == "INFO" && m["op_id"] == "0123456789abcdef0123456789abcdef" &&
					strings.Contains(m["msg"].(string), "retry") {
					return true
				}
			}
			return false
		})
	})
}

// A final that is not accepted, duplicate or unknown_op leaves the record applied. The periodic
// resend skips the operation for the rest of the stream, and the next stream sends it again.
func TestStreamFinalRefusedKeepsRecordApplied(t *testing.T) {
	for _, outcome := range []string{mgmtapi.OutcomeRefused, mgmtapi.OutcomeForgedSeen, ""} {
		t.Run("outcome="+outcome, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := newFixture(t, func(c *StreamConfig) { c.ResendEvery = 40 * time.Second })
				defer f.stop()
				l, id := f.lease("s1.1", fence(1, 5))
				f.g.offer(l)
				f.start()
				waitFor(t, 5*time.Second, "the result", func() bool { return len(f.g.frames(gwapi.TypeResult)) > 0 })

				_ = f.g.current().send(gwapi.Frame{Type: gwapi.TypeFinal, OpID: id, Outcome: outcome})
				_ = f.g.current().send(gwapi.Frame{Type: gwapi.TypeFinal, OpID: id, Outcome: outcome})
				time.Sleep(time.Second)
				if p, _ := f.exec.Pending(t.Context()); len(p) != 1 {
					t.Fatalf("%d pending after a %q final, want the result kept", len(p), outcome)
				}
				n := len(f.g.frames(gwapi.TypeResult))
				time.Sleep(125 * time.Second)
				if got := len(f.g.frames(gwapi.TypeResult)); got != n {
					t.Fatalf("%d result frames in the same stream after the final, want %d", got, n)
				}

				f.updates <- struct{}{}
				waitFor(t, 20*time.Second, "the resend on the next stream", func() bool {
					return len(f.g.frames(gwapi.TypeResult)) > n
				})
				if last := f.g.frames(gwapi.TypeResult)[n]; last.stream < 2 || resultOf(t, last.f).OpID != id {
					t.Fatalf("resend %+v", last)
				}
			})
		})
	}
}

func TestStreamFinalEndsRecord(t *testing.T) {
	for _, outcome := range []string{mgmtapi.OutcomeAccepted, mgmtapi.OutcomeDuplicate, mgmtapi.OutcomeUnknownOp} {
		t.Run(outcome, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := newFixture(t)
				defer f.stop()
				l, id := f.lease("s1.1", fence(1, 5))
				f.g.offer(l)
				f.start()
				waitFor(t, 5*time.Second, "the result", func() bool { return len(f.g.frames(gwapi.TypeResult)) > 0 })
				_ = f.g.current().send(gwapi.Frame{Type: gwapi.TypeFinal, OpID: id, Outcome: outcome})
				waitFor(t, 5*time.Second, "the record to be marked reported", func() bool {
					p, _ := f.exec.Pending(t.Context())
					return len(p) == 0
				})
			})
		})
	}
}

// A new stream sends at most maxResendBurst results at once and sends the rest after their acks.
func TestStreamResendBurstIsCapped(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newFixture(t)
		defer f.stop()
		ids := map[string]bool{}
		for i := 0; i < maxResendBurst+5; i++ {
			o := f.rig.operation(testKind, "{}")
			ids[o.ID] = true
			if res := f.exec.Execute(t.Context(), f.rig.sign(o), fence(1, uint64(i+1))); res.Outcome != op.OutcomeApplied {
				t.Fatalf("%+v", res)
			}
		}
		hold := true
		var mu sync.Mutex
		f.g.handler = func(s *gwStream) {
			s.loop(func(fr gwapi.Frame) bool {
				mu.Lock()
				defer mu.Unlock()
				return hold && fr.Type == gwapi.TypeResult
			})
		}
		f.start()
		waitFor(t, 5*time.Second, "the first burst", func() bool { return len(f.g.frames(gwapi.TypeResult)) >= maxResendBurst })
		time.Sleep(5 * time.Second)
		if n := len(f.g.frames(gwapi.TypeResult)); n != maxResendBurst {
			t.Fatalf("%d result frames before any ack, want %d", n, maxResendBurst)
		}
		mu.Lock()
		hold = false
		mu.Unlock()
		for i := 0; i < maxResendBurst; i++ {
			_ = f.g.current().send(gwapi.Frame{Type: gwapi.TypeAck})
		}
		waitFor(t, 5*time.Second, "the rest", func() bool { return len(f.g.frames(gwapi.TypeResult)) >= maxResendBurst+5 })
		seen := map[string]int{}
		for _, fr := range f.g.frames(gwapi.TypeResult) {
			seen[resultOf(t, fr.f).OpID]++
		}
		for id := range ids {
			if seen[id] != 1 {
				t.Fatalf("op %s was sent %d times, want 1", id, seen[id])
			}
		}
	})
}

// An effect runs on EffectCtx, so the end of the stream context does not cancel it, and its record is
// written.
func TestStreamEffectRunsOnItsOwnContext(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		effectCtx, endEffect := context.WithCancel(context.Background())
		defer endEffect()
		f := newFixture(t, func(c *StreamConfig) { c.EffectCtx = effectCtx })
		started, release := make(chan struct{}), make(chan struct{})
		var ctxErr error
		f.exec.cfg.Kinds[testKind] = func(c context.Context, _ *Executor, _ op.Operation) error {
			close(started)
			<-release
			ctxErr = c.Err()
			return nil
		}
		l, id := f.lease("s1.1", fence(1, 5))
		f.g.offer(l)
		f.start()
		<-started
		f.cancel()
		time.Sleep(time.Second)
		close(release)
		<-f.done
		f.g.close()
		if ctxErr != nil {
			t.Fatalf("the effect context ended with the stream: %v", ctxErr)
		}
		if rec := f.rig.record(id); rec.State != stateApplied {
			t.Fatalf("record state %q, want applied", rec.State)
		}
	})
}

// streamEndedReasons runs a stream against a gateway that the client refuses, and returns the
// reason field of each "stream ended" line.
func streamEndedReasons(t *testing.T, mkGateway func(f *streamFixture) *gateway) []string {
	var reasons []string
	synctest.Test(t, func(t *testing.T) {
		var out syncBuf
		f := newFixture(t)
		f.cfg.Log = slog.New(slog.NewJSONHandler(&out, nil))
		bad := mkGateway(f)
		f.cfg.dial = bad.dial
		f.start()
		waitFor(t, time.Minute, "a stream ended line", func() bool { return bytes.Contains(out.bytes(), []byte(`"stream ended"`)) })
		f.cancel()
		<-f.done
		bad.close()
		f.g.close()
		for _, l := range bytes.Split(out.bytes(), []byte("\n")) {
			var m map[string]any
			if json.Unmarshal(l, &m) == nil && m["msg"] == "stream ended" {
				r, _ := m["reason"].(string)
				reasons = append(reasons, r)
				for _, k := range []string{"cell", "error", "retry_in"} {
					if _, ok := m[k]; !ok {
						t.Errorf("line lost the field %s: %v", k, m)
					}
				}
			}
		}
	})
	return reasons
}

func TestStreamRefusalReason(t *testing.T) {
	for name, tc := range map[string]struct {
		want string
		mk   func(f *streamFixture) *gateway
	}{
		"wrong ID": {"peer_not_allowed", func(f *streamFixture) *gateway {
			return newGatewayWithCA(t, f.g.ca, "spiffe://dev.env.poc.internal/cp/other")
		}},
		"untrusted": {"peer_untrusted", func(f *streamFixture) *gateway {
			return newGateway(t, gwID)
		}},
	} {
		t.Run(name, func(t *testing.T) {
			reasons := streamEndedReasons(t, tc.mk)
			if len(reasons) == 0 || reasons[0] != tc.want {
				t.Fatalf("reasons = %v, want %s", reasons, tc.want)
			}
		})
	}
}
