//go:build e2e

package e2e

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/joshwrightcodes/cell-identity-poc/internal/bundle"
	"github.com/joshwrightcodes/cell-identity-poc/internal/op"
)

// m8AppWave is the sync wave of the apps-sample component: after apps-demo, which has wave 5. It lives in the namespace apps-sample.
const m8AppWave = 10

// TestM8SignedBundleReachesArgoCD, in each live cell: a bundle apps-sample that holds the ConfigMap apps-sample/m8-marker with a random
// marker is pushed to the mirror, and mgmtd signs the last set of the cell with this entry. The cell applies it: the outcome is
// applied, the Application apps-sample is Synced at the digest and Healthy, the ConfigMap holds the marker, the state holds the
// signed version, and root is at the root digest of the state, which is the root subject of the signature.
func TestM8SignedBundleReachesArgoCD(t *testing.T) {
	for _, cell := range clustersWith(t, agentCellSet) {
		t.Run(cell, func(t *testing.T) {
			m8RestoreTarget(t, cell)
			marker := randomHex(t, 8)
			manifests := fmt.Sprintf(`apiVersion: v1
kind: ConfigMap
metadata:
  name: m8-marker
  namespace: apps-sample
  labels:
    cell.poc.internal/e2e: "true"
data:
  marker: %q
`, marker)
			digest := m8PushBundle(t, cell, "apps-sample", []byte(manifests))

			last := m8LastSet(t, cell)
			var comps []bundle.Component
			for _, c := range last.Components {
				if c.Name != "apps-sample" {
					comps = append(comps, c)
				}
			}
			if len(comps) == 0 {
				t.Fatalf("%s has no signed set yet. Run: mise run bundle -- publish --target %s --wait", cell, cell)
			}
			comps = append(comps, bundle.Component{Name: "apps-sample", Wave: m8AppWave, Namespace: "apps-sample", Digest: digest})
			signed := m8Sign(t, cell, comps, true)
			res := m8Wait(t, cell, signed.OpID, 10*time.Minute)
			if res.Result.Outcome != op.OutcomeApplied {
				t.Fatalf("the outcome is %+v, want applied", *res.Result)
			}

			app := m8Application(t, cell, "apps-sample")
			if got := m8Field(app, "status", "sync", "status"); got != "Synced" {
				t.Errorf("apps-sample is %s, want Synced", got)
			}
			if got := m8Field(app, "status", "sync", "revision"); got != digest {
				t.Errorf("apps-sample is at %s, want the digest %s", got, digest)
			}
			if got := m8Field(app, "status", "health", "status"); got != "Healthy" {
				t.Errorf("apps-sample is %s, want Healthy", got)
			}
			out, err := kubectl(t, cell, "", "-n", "apps-sample", "get", "configmap", "m8-marker", "-o", "jsonpath={.data.marker}")
			if err != nil || out != marker {
				t.Errorf("ConfigMap m8-marker holds %q (%v), want %q", out, err, marker)
			}

			st := m8State(t, cell)
			if st.Source != "signed" || st.State != "healthy" || st.Version != signed.Version {
				t.Errorf("the state is %s/%s at %+v, want signed/healthy at %+v", st.Source, st.State, st.Version, signed.Version)
			}
			// The root subject is the digest that the signed statement names, and not the digest that mgmtd reports next to it.
			subject := m8Subject(t, signed.Envelope, "bundles/"+cell+"/root")
			if st.Root.Digest != subject || signed.RootDigest != subject {
				t.Errorf("the state holds the root %s and mgmtd reports %s, want the signed root subject %s", st.Root.Digest, signed.RootDigest, subject)
			}
			if got := m8Field(m8Application(t, cell, "root"), "status", "sync", "revision"); got != st.Root.Digest {
				t.Errorf("root is at %s, want the root of the state %s", got, st.Root.Digest)
			}
		})
	}
}

// TestM8SameContentIsNoOp, in dev-cell-1: the hydrated set is published twice. Each publish ends applied (the second set has the
// next version and the same content), the root digest stays the same, and no child Application starts a new operation, because
// the bundles and the root are the same bytes.
func TestM8SameContentIsNoOp(t *testing.T) {
	const cell = "dev-cell-1"
	m8RestoreTarget(t, cell)
	first, err := m8PublishHydrated(t, cell)
	if err != nil {
		t.Fatal(err)
	}
	if first["outcome"] != op.OutcomeApplied {
		t.Fatalf("the first publish ended %v, want applied", first)
	}
	// Every child of the hydrated set must have run a sync, so an empty read cannot pass as "no new operation".
	children := m8LastSet(t, cell).Components
	if len(children) == 0 {
		t.Fatal("the last set of the cell holds no component")
	}
	stBefore, startedBefore := m8State(t, cell), m8StartedAt(t, cell)
	for _, c := range children {
		if startedBefore[c.Name] == "" {
			t.Fatalf("the Application %s has no operationState.startedAt (read %v)", c.Name, startedBefore)
		}
	}
	second, err := m8PublishHydrated(t, cell)
	if err != nil {
		t.Fatal(err)
	}
	if second["outcome"] != op.OutcomeApplied {
		t.Fatalf("the second publish ended %v, want applied", second)
	}
	if first["rootDigest"] == "" || first["rootDigest"] != second["rootDigest"] {
		t.Errorf("the two publishes name the roots %v and %v, want one root", first["rootDigest"], second["rootDigest"])
	}
	stAfter, startedAfter := m8State(t, cell), m8StartedAt(t, cell)
	if stAfter.Root.Digest != stBefore.Root.Digest {
		t.Errorf("the root digest changed from %s to %s", stBefore.Root.Digest, stAfter.Root.Digest)
	}
	if stAfter.Version.Compare(stBefore.Version) <= 0 {
		t.Errorf("the second set has the version %+v, want one above %+v", stAfter.Version, stBefore.Version)
	}
	if !maps.Equal(startedBefore, startedAfter) {
		keys := slices.Sorted(maps.Keys(startedAfter))
		before, _ := json.Marshal(startedBefore)
		after, _ := json.Marshal(startedAfter)
		t.Errorf("a child started a new operation (children %v)\nbefore %s\nafter  %s", keys, before, after)
	}
}

// TestM8CosignVerifiesSet, in dev-cell-1 and dev-cp: cosign on this Mac verifies the signed set offline against the public key of mgmtd.
// Subtest verifies: mise run bundle -- verify prints the subjects of the statement, which are the root of the state and each component of the
// last signed set. Subtest one_byte_changed: cosign verifies a copy of the attached Sigstore bundle, and fails on a copy in which one byte of
// the signature changed.
func TestM8CosignVerifiesSet(t *testing.T) {
	for _, target := range []string{"dev-cell-1", cpClusterName} {
		t.Run(target, func(t *testing.T) {
			t.Run("verifies", func(t *testing.T) {
				out, err := m8Command(t, 5*time.Minute, "", "run", "bundle", "--", "verify", "--target", target)
				if err != nil {
					t.Fatalf("%v\n%s", err, out)
				}
				var res struct {
					Root     string `json:"root"`
					Subjects []struct {
						Name   string `json:"name"`
						Digest string `json:"digest"`
					} `json:"subjects"`
				}
				if err := json.Unmarshal([]byte(m8LastLine(out)), &res); err != nil {
					t.Fatalf("verify printed %q: %v", out, err)
				}
				got := map[string]string{}
				for _, s := range res.Subjects {
					got[s.Name] = s.Digest
				}
				st := m8State(t, target)
				want := map[string]string{"bundles/" + target + "/root": st.Root.Digest}
				for _, c := range m8LastSet(t, target).Components {
					want["bundles/"+target+"/"+c.Name] = c.Digest
				}
				if res.Root != st.Root.Digest || !maps.Equal(got, want) {
					t.Errorf("the verified subjects are %v, want the root of the state and the last set: %v", got, want)
				}
			})
			t.Run("one_byte_changed", func(t *testing.T) {
				st := m8State(t, target)
				// The copy is made from the bundle that is attached to the root on the mirror, which is what cosign reads, and not from the local file.
				ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
				defer cancel()
				mirror, repo := m8Mirror(t), "bundles/"+target+"/root"
				refs, err := mirror.Referrers(ctx, repo, st.Root.Digest)
				if err != nil || len(refs) == 0 {
					t.Fatalf("the root has no attached bundle on the mirror (%v). Run: mise run bundle -- cosign --target %s", err, target)
				}
				manifest, err := mirror.Manifest(ctx, repo, refs[len(refs)-1].Digest.String())
				if err != nil {
					t.Fatal(err)
				}
				var layers struct {
					Layers []struct {
						Digest string `json:"digest"`
					} `json:"layers"`
				}
				if err := json.Unmarshal(manifest, &layers); err != nil || len(layers.Layers) == 0 {
					t.Fatalf("the attached referrer has no layer: %v", err)
				}
				raw, err := mirror.Blob(ctx, repo, layers.Layers[0].Digest)
				if err != nil {
					t.Fatal(err)
				}
				var bundleDoc map[string]any
				if err := json.Unmarshal(raw, &bundleDoc); err != nil {
					t.Fatal(err)
				}
				sigs, _ := bundleDoc["dsseEnvelope"].(map[string]any)["signatures"].([]any)
				if len(sigs) == 0 {
					t.Fatal("the bundle holds no signature")
				}
				sig, _ := sigs[0].(map[string]any)["sig"].(string)
				decoded, err := base64.StdEncoding.DecodeString(sig)
				if err != nil || len(decoded) == 0 {
					t.Fatalf("the signature is no base64: %v", err)
				}
				decoded[0] ^= 0x01
				key, rootHex := m8PubKeyPEM(t), strings.TrimPrefix(st.Root.Digest, "sha256:")
				dir := t.TempDir()
				verify := func(doc map[string]any) (string, error) {
					b, _ := json.Marshal(doc)
					path := filepath.Join(dir, "bundle.json")
					if err := os.WriteFile(path, b, 0o644); err != nil {
						t.Fatal(err)
					}
					return m8Cosign(t, "verify-blob-attestation", "--bundle", path, "--key", key, "--digest", rootHex, "--digestAlg", "sha256", "--type", "https://cell.poc.internal/bundle-set/v1", "--insecure-ignore-tlog=true")
				}
				if out, err := verify(bundleDoc); err != nil {
					t.Fatalf("cosign does not verify an unchanged copy: %v\n%s", err, out)
				}
				sigs[0].(map[string]any)["sig"] = base64.StdEncoding.EncodeToString(decoded)
				out, err := verify(bundleDoc)
				if err == nil {
					t.Fatalf("cosign verifies a copy with one byte changed:\n%s", out)
				}
				// The unchanged copy passed with the same arguments, so the failure must come from the signature and not from the predicate type.
				if strings.Contains(out, "invalid predicate type") {
					t.Fatalf("the changed copy fails on the predicate type:\n%s", out)
				}
			})
		})
	}
}
