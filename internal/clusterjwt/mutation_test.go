package clusterjwt

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/hashicorp/go-hclog"
	nodeattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/nodeattestor/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"

	"github.com/joshwrightcodes/cell-identity-poc/internal/record"
	"github.com/joshwrightcodes/cell-identity-poc/internal/satoken"
	envspec "github.com/joshwrightcodes/cell-identity-poc/internal/spec"
)

// The server builds the agent ID from the pod UID, so a UID with a path separator must not reach it,
// even when the token signature is good.
func TestPodUIDMustBeSafeForTheAgentID(t *testing.T) {
	f := newFixture(t, fixtureOptions{})
	for _, uid := range []string{"a/b", "..", strings.Repeat("a", 65)} {
		_, err := f.attest("dev-cell-1", func(nonce string) string {
			s := f.keys.good()
			s.Audience = []string{Audience(testEnv, nonce)}
			s.K8s.Pod.UID = uid
			return s.token(t)
		})
		wantDenied(t, err, Malformed)
	}
}

func TestRecordOfAnotherEnvironmentIsSkipped(t *testing.T) {
	f := newFixture(t, fixtureOptions{cells: []string{"dev-cell-1"}, mutate: func(rec *record.Cell) { rec.Env = "prod" }})
	_, err := f.attest("dev-cell-1", f.goodToken)
	wantDenied(t, err, UnknownCell)
	if logs := f.logs.String(); !strings.Contains(logs, "other environment") {
		t.Fatalf("log does not say why the record was skipped:\n%s", logs)
	}
}

func TestRecordWithACellNameThatIsNoDNSLabelIsSkipped(t *testing.T) {
	f := newFixture(t, fixtureOptions{cells: []string{"dev-cell-1"}, mutate: func(rec *record.Cell) { rec.Name = "Dev_Cell" }})
	_, err := f.attest("Dev_Cell", f.goodToken)
	wantDenied(t, err, UnknownCell)
	if logs := f.logs.String(); !strings.Contains(logs, "cell name is not a DNS label") {
		t.Fatalf("log does not say why the record was skipped:\n%s", logs)
	}
}

// A FIFO would block the read at Configure, and a large file would cost memory. Both are skipped.
// The record ConfigMap volume uses symbolic links to regular files, so those still load.
func TestRecordFileMustBeRegularAndSmall(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	base := newKeys(t).record(t)
	base.Epoch, base.Counter = 1, 1
	var entries []envspec.Entry
	sign := func(name string) []byte {
		rec := base
		rec.Name = name
		env, err := record.Sign(rec, priv)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := json.Marshal(rec)
		entries = append(entries, envspec.Entry{Name: name, Revision: envspec.RecordRevision(rec), RecordSHA256: envspec.RecordDigest(body)})
		return env
	}
	dir := t.TempDir()
	if err := syscall.Mkfifo(filepath.Join(dir, "fifo.dsse.json"), 0o600); err != nil {
		t.Fatal(err)
	}
	padded := append(sign("dev-cell-2"), bytes.Repeat([]byte(" "), maxRecordFileLen)...)
	if err := os.WriteFile(filepath.Join(dir, "dev-cell-2.dsse.json"), padded, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "data"), sign("dev-cell-3"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("data", filepath.Join(dir, "dev-cell-3.dsse.json")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, specFile), signSpec(t, priv, testEnv, 1, 1, entries, nil), 0o600); err != nil {
		t.Fatal(err)
	}

	logs := &syncBuffer{}
	p := New()
	p.log = hclog.New(&hclog.LoggerOptions{Output: logs, JSONFormat: true})
	type loaded struct {
		records map[string]record.Cell
		err     error
	}
	done := make(chan loaded, 1)
	go func() {
		snap, err := p.load(&state{dir: dir, env: testEnv, keys: []ed25519.PublicKey{pub}}, nil, false)
		if snap == nil {
			snap = emptySnapshot()
		}
		done <- loaded{snap.records, err}
	}()
	var got loaded
	select {
	case got = <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("load blocked on a record file that is not a regular file")
	}
	if got.err != nil {
		t.Fatal(got.err)
	}
	if _, ok := got.records["dev-cell-2"]; ok {
		t.Fatal("a record file over the size limit loaded")
	}
	if _, ok := got.records["dev-cell-3"]; !ok {
		t.Fatalf("a record behind a symbolic link did not load: %v", got.records)
	}
	for _, file := range []string{"fifo.dsse.json", "dev-cell-2.dsse.json"} {
		if !strings.Contains(logs.String(), `"file":"`+file+`","reason":"not a regular file of acceptable size"`) {
			t.Fatalf("log does not report the skip of %s:\n%s", file, logs)
		}
	}
}

// blockedStream is a server stream whose Recv never returns and whose context ends at once.
type blockedStream struct {
	nodeattestorv1.NodeAttestor_AttestServer
	ctx context.Context
}

func (b blockedStream) Context() context.Context                     { return b.ctx }
func (b blockedStream) Recv() (*nodeattestorv1.AttestRequest, error) { select {} }

func TestRecvWithinReturnsWhenTheStreamEnds(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	_, reason := recvWithin(blockedStream{ctx: ctx}, time.Minute)
	if reason != Abandoned {
		t.Fatalf("reason = %q, want %q", reason, Abandoned)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("recvWithin returned after %s, not when the stream ended", d)
	}
}

func TestDecodeStrictBoundsTheMessage(t *testing.T) {
	msg := func(n int) []byte {
		// {"token":"<n - 12 bytes>"} is n bytes long.
		return []byte(`{"token":"` + strings.Repeat("a", n-12) + `"}`)
	}
	var r Response
	if err := decodeStrict(msg(maxMessage), &r); err != nil {
		t.Fatalf("a message of %d bytes: %v", maxMessage, err)
	}
	if err := decodeStrict(msg(maxMessage+1), &r); err == nil {
		t.Fatalf("a message of %d bytes decoded", maxMessage+1)
	}
}

// deadlineClient records the deadline of the context that CreateToken receives.
type deadlineClient struct {
	corev1client.ServiceAccountInterface
	deadline time.Time
	ok       bool
}

func (d *deadlineClient) CreateToken(ctx context.Context, _ string, req *authenticationv1.TokenRequest, _ metav1.CreateOptions) (*authenticationv1.TokenRequest, error) {
	d.deadline, d.ok = ctx.Deadline()
	out := req.DeepCopy()
	out.Status.Token = "token"
	return out, nil
}

type deadlineClients struct{ c *deadlineClient }

func (d deadlineClients) ServiceAccounts(string) corev1client.ServiceAccountInterface { return d.c }

func TestTokenRequestHasItsOwnTimeout(t *testing.T) {
	c := &deadlineClient{}
	st := &agentState{env: testEnv, ttl: MinTokenTTL, podName: "p", podUID: "u", namespace: "n", serviceAccount: "s", client: deadlineClients{c}}
	start := time.Now()
	if _, err := NewAgent().requestToken(context.Background(), st, testAgentNonce); err != nil {
		t.Fatal(err)
	}
	if !c.ok {
		t.Fatal("the TokenRequest call has no deadline")
	}
	if d := c.deadline.Sub(start); d > satoken.RequestTimeout+time.Second || d < satoken.RequestTimeout-time.Second {
		t.Fatalf("the TokenRequest deadline is %s away, want %s", d, satoken.RequestTimeout)
	}
}

func TestExpiryMustFollowIssue(t *testing.T) {
	k := newKeys(t)
	rec := k.record(t)
	for name, exp := range map[string]time.Time{"equal": testNow, "before": testNow.Add(-10 * time.Second)} {
		t.Run(name, func(t *testing.T) {
			s := k.good()
			s.IAT, s.EXP = testNow.Unix(), exp.Unix()
			check(t, rec, s.token(t), Malformed)
		})
	}
}

// The server logs the time from the challenge to the reply on each attestation that got a reply,
// so challenge_timeout can follow the measured attestation time.
func TestReplyTimeIsLogged(t *testing.T) {
	f := newFixture(t, fixtureOptions{})
	if _, err := f.attest("dev-cell-1", func(nonce string) string {
		time.Sleep(50 * time.Millisecond)
		return f.goodToken(nonce)
	}); err != nil {
		t.Fatal(err)
	}
	_, err := f.attest("dev-cell-1", func(string) string { return f.goodToken("another-nonce") })
	wantDenied(t, err, WrongAudience)
	var attested, refused int
	for line := range strings.SplitSeq(f.logs.String(), "\n") {
		var l map[string]any
		if json.Unmarshal([]byte(line), &l) != nil {
			continue
		}
		ms, ok := l["challenge_reply_ms"].(float64)
		switch l["@message"] {
		case "attested":
			if !ok || ms < 50 {
				t.Fatalf("attested line %v: want challenge_reply_ms of 50 or more", l)
			}
			attested++
		case "attestation refused":
			if !ok || ms < 0 {
				t.Fatalf("refusal after a reply %v: want challenge_reply_ms", l)
			}
			refused++
		}
	}
	if attested != 1 || refused != 1 {
		t.Fatalf("got %d attested and %d refused lines with a reply time, want 1 and 1:\n%s", attested, refused, f.logs.String())
	}
}

// The agent must give up on its TokenRequest before the server gives up on the challenge, so a
// slow API server ends in a clear agent error and not in a challenge_timeout on the server.
func TestTokenRequestTimeoutIsBelowTheChallengeTimeout(t *testing.T) {
	conf, err := os.ReadFile("../../components/spire-server/server.conf")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^\s*challenge_timeout = "([^"]+)"`).FindSubmatch(conf)
	if m == nil {
		t.Fatal("server.conf sets no challenge_timeout")
	}
	challenge, err := time.ParseDuration(string(m[1]))
	if err != nil {
		t.Fatal(err)
	}
	if satoken.RequestTimeout >= challenge {
		t.Fatalf("satoken.RequestTimeout %s is not below challenge_timeout %s of server.conf", satoken.RequestTimeout, challenge)
	}
}
