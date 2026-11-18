//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/joshwrightcodes/cell-identity-poc/internal/bundle"
	"github.com/joshwrightcodes/cell-identity-poc/internal/bundleapply"
	"github.com/joshwrightcodes/cell-identity-poc/internal/hostsvc"
	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmtapi"
	"github.com/joshwrightcodes/cell-identity-poc/internal/ocistore"
	"github.com/joshwrightcodes/cell-identity-poc/internal/op"
	"github.com/joshwrightcodes/cell-identity-poc/internal/record"
)

const (
	// m8BundlesFile lists the targets whose signed set a test changed, one name on each line. gate:m8:repair publishes the
	// hydrated set of each of them again after an aborted run.
	m8BundlesFile = "../../build/gate/m8-bundles"
	// m8Label marks every probe object that an M8 test makes.
	m8Label = "cell.poc.internal/e2e=true"
	// m8PublishBound bounds one mise run bundle -- publish --wait. The script waits 15 minutes itself.
	m8PublishBound = 20 * time.Minute
)

// m8Command runs mise with the arguments, with stdin on its standard input, and returns standard output. A call that
// takes longer than limit is stopped.
func m8Command(t *testing.T, limit time.Duration, stdin string, args ...string) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), limit)
	defer cancel()
	cmd := exec.CommandContext(ctx, "mise", args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	if err != nil {
		err = fmt.Errorf("mise %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return strings.TrimSpace(stdout.String()), err
}

// m8Mirror opens the mirror (registry-mirror) on this Mac. A test pushes its own bundles only here, as a compromised mirror
// pusher could.
func m8Mirror(t *testing.T) *ocistore.Store {
	t.Helper()
	s, err := ocistore.New(ocistore.Client{Base: hostsvc.RegistryHost})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// m8PushBundle packs the manifests (a render, in any YAML form that bundle.DecodeManifests reads) as bundle <component> of the
// target, pushes it to the mirror under bundles/<target>/<component>, and returns the digest of its manifest. The same bytes
// always give the same digest.
func m8PushBundle(t *testing.T, target, component string, manifests []byte) string {
	t.Helper()
	return m8PushTo(t, m8Mirror(t), "bundles/"+target+"/"+component, manifests)
}

// m8PushTo packs the manifests as a bundle, pushes it to the repository of the store, and returns the digest of its manifest.
func m8PushTo(t *testing.T, s *ocistore.Store, repo string, manifests []byte) string {
	t.Helper()
	objs, err := bundle.DecodeManifests(manifests, bundle.MaxObjects)
	if err != nil {
		t.Fatalf("decode the manifests of %s: %v", repo, err)
	}
	canon, err := bundle.Canonical(objs)
	if err != nil {
		t.Fatalf("canonical form of %s: %v", repo, err)
	}
	art, err := bundle.Pack(map[string][]byte{bundle.ManifestsFile: canon})
	if err != nil {
		t.Fatalf("pack %s: %v", repo, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := s.PushBlob(ctx, repo, art.ConfigDigest, art.Config); err != nil {
		t.Fatalf("push the config of %s: %v", repo, err)
	}
	if err := s.PushBlob(ctx, repo, art.LayerDigest, art.Layer); err != nil {
		t.Fatalf("push the layer of %s: %v", repo, err)
	}
	d, err := s.PushManifest(ctx, repo, "", bundle.MediaTypeManifest, art.Manifest)
	if err != nil {
		t.Fatalf("push the manifest of %s: %v", repo, err)
	}
	if d != art.Digest {
		t.Fatalf("push of %s gave the digest %s, want %s", repo, d, art.Digest)
	}
	return art.Digest
}

// m8Get returns the last signed set of a target as mgmtd holds it, with the final result of its operation when there is one.
func m8Get(t *testing.T, target string) mgmtapi.TargetBundle {
	t.Helper()
	out, err := m8Command(t, 2*time.Minute, "", "run", "mgmt", "--", "bundle", "get", "--target", target)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	var tb mgmtapi.TargetBundle
	if err := json.Unmarshal([]byte(m8LastLine(out)), &tb); err != nil {
		t.Fatalf("mgmt -- bundle get printed %q: %v", out, err)
	}
	return tb
}

func m8LastLine(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	return lines[len(lines)-1]
}

// m8LastSet returns the last signed set of a target: its version and its components.
func m8LastSet(t *testing.T, target string) bundle.Set {
	t.Helper()
	tb := m8Get(t, target)
	return bundle.Set{Version: tb.Version, Components: tb.Components}
}

// m8Sign asks mgmtd to sign the components as the next set of the target. With serve false, the operation is signed and never
// offered (--no-serve), so a test can enqueue the envelope itself.
func m8Sign(t *testing.T, target string, comps []bundle.Component, serve bool) mgmtapi.BundleSignResult {
	t.Helper()
	slices.SortFunc(comps, func(a, b bundle.Component) int { return strings.Compare(a.Name, b.Name) })
	body, err := json.Marshal(comps)
	if err != nil {
		t.Fatal(err)
	}
	args := []string{"run", "mgmt", "--", "bundle", "sign", "--target", target}
	if !serve {
		args = append(args, "--no-serve")
	}
	out, err := m8Command(t, 2*time.Minute, string(body), args...)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	var res mgmtapi.BundleSignResult
	if err := json.Unmarshal([]byte(m8LastLine(out)), &res); err != nil || res.OpID == "" {
		t.Fatalf("mgmt -- bundle sign printed %q: %v", out, err)
	}
	return res
}

// m8Wait polls mgmtd until the operation has a final result, and returns the set with it. It fails the test when the operation is
// not the last one of the target, or when d passes.
func m8Wait(t *testing.T, target, opID string, d time.Duration) mgmtapi.TargetBundle {
	t.Helper()
	end := time.Now().Add(d)
	for {
		tb := m8Get(t, target)
		if tb.OpID != opID {
			t.Fatalf("the last set of %s is operation %s, want %s", target, tb.OpID, opID)
		}
		if tb.Result != nil {
			return tb
		}
		if time.Now().After(end) {
			t.Fatalf("operation %s of %s has no result after %s", opID, target, d)
		}
		time.Sleep(5 * time.Second)
	}
}

// m8StateNamespace names the namespace of the bundle state of a target: cell-ops-system in a cell, envd-system in dev-cp.
func m8StateNamespace(target string) string {
	if target == cpClusterName {
		return "envd-system"
	}
	return "cell-ops-system"
}

// m8State reads the bundle state of a target from its ConfigMap.
func m8State(t *testing.T, target string) bundleapply.State {
	t.Helper()
	out, err := kubectl(t, target, "", "-n", m8StateNamespace(target), "get", "configmap", "bundle-state", "-o", `jsonpath={.data.state\.json}`)
	if err != nil {
		t.Fatal(err)
	}
	var st bundleapply.State
	if err := record.DecodeStrict([]byte(out), &st); err != nil {
		t.Fatalf("the bundle state of %s does not decode: %v\n%s", target, err, out)
	}
	return st
}

// m8RestoreTarget records the target in build/gate/m8-bundles, and registers the restore of the hydrated set in t.Cleanup: a signed
// publish of the set that cell:hydrate left in build/<target>, which takes a version above every probe set. The cleanup fails the
// test when the restore does not end applied or already_applied.
func m8RestoreTarget(t *testing.T, target string) {
	t.Helper()
	m8RecordTarget(t, target)
	t.Cleanup(func() {
		res, err := m8PublishHydrated(t, target)
		if err != nil {
			t.Errorf("restore the hydrated set of %s: %v", target, err)
			return
		}
		if res["outcome"] != op.OutcomeApplied && res["outcome"] != op.OutcomeAlreadyApplied {
			t.Errorf("restore of %s ended %v", target, res)
		}
	})
}

// m8RecordTarget adds the target to build/gate/m8-bundles, so that gate:m8:repair publishes its hydrated set again after an
// aborted run.
func m8RecordTarget(t *testing.T, target string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(m8BundlesFile), 0o755); err != nil {
		t.Fatal(err)
	}
	known, _ := os.ReadFile(m8BundlesFile)
	if !slices.Contains(strings.Fields(string(known)), target) {
		f, err := os.OpenFile(m8BundlesFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fmt.Fprintln(f, target); err != nil {
			f.Close()
			t.Fatal(err)
		}
		f.Close()
	}
}

// m8PublishHydrated runs mise run bundle -- publish --target <target> --wait, and returns the last JSON line that it printed (the
// outcome of the set). The script exits 1 for any outcome other than applied and already_applied, and then the error holds the output.
func m8PublishHydrated(t *testing.T, target string) (map[string]any, error) {
	t.Helper()
	out, err := m8Command(t, m8PublishBound, "", "run", "bundle", "--", "publish", "--target", target, "--wait")
	if err != nil {
		return nil, fmt.Errorf("%w\n%s", err, out)
	}
	var res map[string]any
	if err := json.Unmarshal([]byte(m8LastLine(out)), &res); err != nil {
		return nil, fmt.Errorf("publish printed %q: %w", out, err)
	}
	return res, nil
}

// m8Application returns the Application of a cluster as a generic object.
func m8Application(t *testing.T, cluster, name string) map[string]any {
	t.Helper()
	out, err := kubectl(t, cluster, "", "-n", "argocd", "get", "application", name, "-o", "json")
	if err != nil {
		t.Fatal(err)
	}
	var app map[string]any
	if err := json.Unmarshal([]byte(out), &app); err != nil {
		t.Fatal(err)
	}
	return app
}

// m8Field reads a string at a path of a generic object, or "" when it is absent.
func m8Field(obj map[string]any, path ...string) string {
	var cur any = obj
	for _, p := range path {
		m, ok := cur.(map[string]any)
		if !ok {
			return ""
		}
		cur = m[p]
	}
	s, _ := cur.(string)
	return s
}

// m8StartedAt returns status.operationState.startedAt of every Application of a cluster except root, by name.
func m8StartedAt(t *testing.T, cluster string) map[string]string {
	t.Helper()
	out, err := kubectl(t, cluster, "", "-n", "argocd", "get", "applications", "-o", "json")
	if err != nil {
		t.Fatal(err)
	}
	var list struct {
		Items []map[string]any `json:"items"`
	}
	if err := json.Unmarshal([]byte(out), &list); err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, app := range list.Items {
		if name := m8Field(app, "metadata", "name"); name != "root" {
			got[name] = m8Field(app, "status", "operationState", "startedAt")
		}
	}
	return got
}

// m8Subject returns the digest of the subject with this name in the in-toto statement of a signed envelope, as sha256:<hex>. It fails the
// test when the envelope holds no such subject. The statement is what mgmtd signed, and the cell checks the root against it.
func m8Subject(t *testing.T, envelope json.RawMessage, name string) string {
	t.Helper()
	var env struct {
		Payload string `json:"payload"`
	}
	if err := json.Unmarshal(envelope, &env); err != nil {
		t.Fatalf("the envelope does not decode: %v", err)
	}
	raw, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		t.Fatalf("the payload of the envelope is no base64: %v", err)
	}
	var st struct {
		Subject []struct {
			Name   string            `json:"name"`
			Digest map[string]string `json:"digest"`
		} `json:"subject"`
	}
	if err := json.Unmarshal(raw, &st); err != nil {
		t.Fatalf("the statement does not decode: %v", err)
	}
	for _, sub := range st.Subject {
		if sub.Name == name && sub.Digest["sha256"] != "" {
			return "sha256:" + sub.Digest["sha256"]
		}
	}
	t.Fatalf("the signed statement names no subject %s", name)
	return ""
}

// m8PubKeyPEM writes the current public key of mgmtd as a PEM file in a temporary directory and returns its path. The key is public data.
func m8PubKeyPEM(t *testing.T) string {
	t.Helper()
	line, err := m8Command(t, time.Minute, "", "run", "mgmt", "--", "pubkey")
	if err != nil {
		t.Fatalf("%v\n%s", err, line)
	}
	pem, err := m8Command(t, time.Minute, m8LastLine(line), "run", "bundlectl", "--", "pubkey-pem")
	if err != nil {
		t.Fatalf("%v\n%s", err, pem)
	}
	path := filepath.Join(t.TempDir(), "mgmt.pub")
	if err := os.WriteFile(path, []byte(pem+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// m8Cosign runs cosign through mise with an empty Docker configuration and no network option, and returns its combined output.
func m8Cosign(t *testing.T, args ...string) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "mise", append([]string{"x", "--", "cosign"}, args...)...)
	cmd.Env = append(os.Environ(), "DOCKER_CONFIG="+t.TempDir())
	out, err := cmd.CombinedOutput()
	return string(out), err
}
