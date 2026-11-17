//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmtapi"
	"github.com/joshwrightcodes/cell-identity-poc/internal/record"
	"github.com/joshwrightcodes/cell-identity-poc/internal/spec"
)

const envdSpecKeyFile = "/run/envd/spec-key/spec.pub"

// checkResult is the line that envd check prints.
type checkResult struct {
	Result   string         `json:"result"`
	Revision *spec.Revision `json:"revision,omitempty"`
	Reason   string         `json:"reason,omitempty"`
}

// envdCheck runs `envd check` in the envd pod of dev-cp with the bundle on standard input. The command changes no state. A
// refusal exits with status 1 and still prints its line.
func envdCheck(t *testing.T, bundle []byte) checkResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "kubectl", "--context", "kind-"+spireCluster, "-n", envdNamespace, "exec", "-i", "deploy/"+envdDeployment, "-c", envdDeployment,
		"--", "/ko-app/envd", "check", "--spec-key-file", envdSpecKeyFile, "--env", pocEnv, "--current-configmap", spireNamespace+"/"+recordsMap)
	cmd.Stdin = bytes.NewReader(bundle)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	_ = cmd.Run()
	var res checkResult
	if err := json.Unmarshal(bytes.TrimSpace(stdout.Bytes()), &res); err != nil {
		t.Fatalf("envd check printed %q (stderr %q), want one JSON line: %v", stdout.String(), stderr.String(), err)
	}
	return res
}

// waitApplied waits until ConfigMap cell-records holds the spec at counter, mgmtd shows that counter as applied, and the
// status of mgmtd holds no refusal.
func waitApplied(t *testing.T, counter uint64, timeout time.Duration) {
	t.Helper()
	waitFor(t, "cell-records at the counter "+strconv.FormatUint(counter, 10)+" with no refusal", timeout, func() (bool, string) {
		sp, _, err := readLiveRecords(t)
		if err != nil {
			return false, err.Error()
		}
		st := mgmtStatus(t)
		return sp.Revision.Counter == counter && st.Applied.Counter == counter && st.LastRefusal == nil,
			"cell-records at " + strconv.FormatUint(sp.Revision.Counter, 10) + ", applied " + strconv.FormatUint(st.Applied.Counter, 10) + ", refusal " + refusalText(st.LastRefusal)
	})
}

func refusalText(r *mgmtapi.Refusal) string {
	if r == nil {
		return "none"
	}
	return r.Reason
}

// liveBundle returns the spec bundle that envd holds in cell-records, with the step envelopes that it holds in ConfigMap
// cell-controller-system/cell-steps, one for each key <cell>.step.json. While a step is open, the spec indexes it, and a bundle
// with no envelope for it is not the live bundle: envd check refuses it.
func liveBundle(t *testing.T) mgmtapi.SpecBundle {
	t.Helper()
	data, _, _, err := recordsConfigMap(t)
	if err != nil {
		t.Fatal(err)
	}
	sp, _ := liveRecords(t)
	b := mgmtapi.SpecBundle{Spec: json.RawMessage(data["spec-envelope.json"]), Records: map[string]json.RawMessage{}}
	for _, e := range sp.Cells {
		b.Records[e.Name] = json.RawMessage(data[e.Name+".dsse.json"])
	}
	stepData, _, _, err := cellStepsConfigMap(t)
	if err != nil {
		t.Fatalf("read ConfigMap cell-steps: %v", err)
	}
	for key, envelope := range stepData {
		if cell, ok := strings.CutSuffix(key, ".step.json"); ok {
			if b.Steps == nil {
				b.Steps = map[string]json.RawMessage{}
			}
			b.Steps[cell] = json.RawMessage(envelope)
		}
	}
	return b
}

// TestM4EnvdCheckRefuses builds bundles from the live one and runs envd check on each. The live bundle gives unchanged. A bundle
// with no signature, with a changed payload, and with a signature of another key each give signature_invalid, and a record in
// place of the spec gives payload_invalid. The check writes nothing, so cell-records keeps its resourceVersion.
func TestM4EnvdCheckRefuses(t *testing.T) {
	_, _, rv, err := recordsConfigMap(t)
	if err != nil {
		t.Fatal(err)
	}
	live := liveBundle(t)
	var env struct {
		PayloadType string `json:"payloadType"`
		Payload     string `json:"payload"`
	}
	if err := json.Unmarshal(live.Spec, &env); err != nil {
		t.Fatal(err)
	}
	body, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		t.Fatal(err)
	}
	with := func(specEnvelope []byte) []byte {
		b := live
		b.Spec = specEnvelope
		out, err := json.Marshal(b)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}

	t.Run("live", func(t *testing.T) {
		out, err := json.Marshal(live)
		if err != nil {
			t.Fatal(err)
		}
		if res := envdCheck(t, out); res.Result != "unchanged" {
			t.Errorf("the live bundle gives %+v, want unchanged", res)
		}
	})
	t.Run("unsigned", func(t *testing.T) {
		unsigned, _ := json.Marshal(map[string]any{"payloadType": env.PayloadType, "payload": env.Payload, "signatures": []any{}})
		if res := envdCheck(t, with(unsigned)); res.Result != "refused" || res.Reason != mgmtapi.ReasonSignatureInvalid {
			t.Errorf("a spec with no signature gives %+v, want refused with %s", res, mgmtapi.ReasonSignatureInvalid)
		}
	})
	t.Run("tampered", func(t *testing.T) {
		var raw map[string]json.RawMessage
		if err := json.Unmarshal(live.Spec, &raw); err != nil {
			t.Fatal(err)
		}
		raw["payload"], _ = json.Marshal(base64.StdEncoding.EncodeToString(append(bytes.Clone(body), ' ')))
		tampered, _ := json.Marshal(raw)
		if res := envdCheck(t, with(tampered)); res.Result != "refused" || res.Reason != mgmtapi.ReasonSignatureInvalid {
			t.Errorf("a spec with a changed payload gives %+v, want refused with %s", res, mgmtapi.ReasonSignatureInvalid)
		}
	})
	t.Run("foreign_key", func(t *testing.T) {
		_, foreign, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		signed, err := record.SignEnvelope(spec.PayloadType, body, foreign)
		if err != nil {
			t.Fatal(err)
		}
		if res := envdCheck(t, with(signed)); res.Result != "refused" || res.Reason != mgmtapi.ReasonSignatureInvalid {
			t.Errorf("a spec signed with another key gives %+v, want refused with %s", res, mgmtapi.ReasonSignatureInvalid)
		}
	})
	t.Run("record_as_spec", func(t *testing.T) {
		var cell string
		for name := range live.Records {
			cell = name
			break
		}
		if res := envdCheck(t, with(live.Records[cell])); res.Result != "refused" || res.Reason != mgmtapi.ReasonPayloadInvalid {
			t.Errorf("a record in place of the spec gives %+v, want refused with %s", res, mgmtapi.ReasonPayloadInvalid)
		}
	})

	if _, _, after, err := recordsConfigMap(t); err != nil || after != rv {
		t.Errorf("cell-records has resourceVersion %q after the checks (%v), want %q", after, err, rv)
	}
}

// envdLog returns the envd log since a time.
func envdLog(t *testing.T, since time.Time) string {
	t.Helper()
	out, err := kubectl(t, spireCluster, "", "-n", envdNamespace, "logs", "deploy/"+envdDeployment, "-c", envdDeployment, "--since-time="+since.UTC().Format(time.RFC3339))
	if err != nil {
		t.Logf("read the envd log: %v", err)
	}
	return out
}

// TestM4EnvdRefusesOlderRevisionLive makes mgmtd serve the revision before its latest one. envd must refuse it, log the reason
// revision_old, keep the records at the latest counter C, and report the refusal to mgmtd. A new celld pod must still attest.
// The cleanup serves the latest revision again and waits until envd reports C with no refusal.
func TestM4EnvdRefusesOlderRevisionLive(t *testing.T) {
	st := mgmtStatus(t)
	if st.RestoreActive {
		t.Fatalf("mgmtd serves an older revision already. Run: mise run gate:m4:repair")
	}
	if st.Signed.Counter < 2 {
		// A rotation of the signing key sets the counter to 1, and a bind of a bound cell signs nothing. A key change that a key
		// check takes into the record signs a revision, so the test makes one. Its cleanup repairs the API server, which signs another.
		makeRevision(t, rejectCell)
		st = mgmtStatus(t)
	}
	c := st.Signed.Counter
	if c < 2 {
		t.Fatalf("mgmtd signed counter %d after a key change, want at least 2", c)
	}
	waitApplied(t, c, envdApplyWait)
	t.Cleanup(func() {
		if out, err := mgmtCtlErr("restore", "--revision", "latest"); err != nil {
			t.Errorf("restore --revision latest: %v: %s. Run: mise run gate:m4:repair", err, out)
			return
		}
		waitApplied(t, c, 2*time.Minute)
	})
	since := time.Now().Add(-logMargin)
	mgmtCtl(t, "restore", "--revision", strconv.FormatUint(c-1, 10))

	waitFor(t, "the envd log line 'spec refused' with the reason revision_old, and the same refusal in the status of mgmtd", envdApplyWait, func() (bool, string) {
		logged := len(matching(envdLog(t, since), func(l logLine) bool {
			return l.str("msg") == "spec refused" && l.str("reason") == mgmtapi.ReasonRevisionOld
		})) > 0
		got := mgmtStatus(t).LastRefusal
		return logged && got != nil && got.Reason == mgmtapi.ReasonRevisionOld, "logged " + strconv.FormatBool(logged) + ", status refusal " + refusalText(got)
	})
	if sp, _, err := readLiveRecords(t); err != nil || sp.Revision.Counter != c {
		t.Errorf("cell-records holds counter %d (%v), want it to stay at %d", sp.Revision.Counter, err, c)
	}
	pod := replaceCelldPod(t, rejectCell)
	waitCelldSVID(t, rejectCell, pod)
}
