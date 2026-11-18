package bundleapply

import (
	"encoding/json"
	"errors"
	"strconv"
	"testing"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	clienttesting "k8s.io/client-go/testing"

	"github.com/joshwrightcodes/cell-identity-poc/internal/bundle"
	"github.com/joshwrightcodes/cell-identity-poc/internal/op"
)

// versioned makes the fake clientset behave like an API server for resource versions: every
// write bumps the version, and an update with another version is a conflict.
func versioned(cs *fake.Clientset) {
	cs.PrependReactor("update", "configmaps", func(a clienttesting.Action) (bool, runtime.Object, error) {
		ua := a.(clienttesting.UpdateAction)
		obj := ua.GetObject().(metav1.Object)
		cur, err := cs.Tracker().Get(ua.GetResource(), ua.GetNamespace(), obj.GetName())
		if err != nil {
			return false, nil, nil
		}
		curRV := cur.(metav1.Object).GetResourceVersion()
		if obj.GetResourceVersion() != curRV {
			return true, nil, apierrors.NewConflict(ua.GetResource().GroupResource(), obj.GetName(), errors.New("stale"))
		}
		n, _ := strconv.Atoi(curRV)
		obj.SetResourceVersion(strconv.Itoa(n + 1))
		return false, nil, nil
	})
	cs.PrependReactor("create", "configmaps", func(a clienttesting.Action) (bool, runtime.Object, error) {
		a.(clienttesting.CreateAction).GetObject().(metav1.Object).SetResourceVersion("1")
		return false, nil, nil
	})
}

func newCMStore(t *testing.T) (*ConfigMapStore, *fake.Clientset) {
	t.Helper()
	cs := fake.NewSimpleClientset()
	versioned(cs)
	return &ConfigMapStore{Client: cs, Namespace: "cell-ops-system", Name: "bundle-state", MadeBy: "celld"}, cs
}

func TestConfigMapStoreAbsentIsEmpty(t *testing.T) {
	s, _ := newCMStore(t)
	st, rv, err := s.Read(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if rv != "" || st.Source != "" || st.State != "" {
		t.Fatalf("absent state = %+v, rv %q", st, rv)
	}
}

func TestConfigMapStoreRoundTrip(t *testing.T) {
	s, cs := newCMStore(t)
	want := State{
		Source: "signed", Version: bundle.Version{Epoch: 2, Counter: 7}, ContentSHA256: "c", KeySHA256: "k", OpID: "op1",
		State: "applying", Holder: "pod-a", Until: time.Date(2026, 11, 18, 10, 0, 0, 0, time.UTC),
		Root:       Root{Digest: "sha256:aa", Manifest: []byte(`{"a":1}`)},
		Components: map[string]string{"x": "sha256:bb"},
		Checked:    []string{"sha256:bb"},
		Good: []Good{{Version: bundle.Version{Epoch: 2, Counter: 6}, ContentSHA256: "c0", Root: Root{Digest: "sha256:cc", Manifest: []byte("m")},
			Components: map[string]string{"x": "sha256:dd"}, At: time.Date(2026, 11, 18, 9, 0, 0, 0, time.UTC)}},
		Result: &op.Result{OpID: "op0", Cell: "dev-cell-1", Outcome: op.OutcomeApplied},
	}
	if err := s.Write(t.Context(), want, ""); err != nil {
		t.Fatal(err)
	}
	got, rv, err := s.Read(t.Context())
	if err != nil || rv == "" {
		t.Fatalf("read: %v rv %q", err, rv)
	}
	a, _ := json.Marshal(want)
	b, _ := json.Marshal(got)
	if string(a) != string(b) {
		t.Fatalf("round trip\nwant %s\ngot  %s", a, b)
	}
	cm, err := cs.CoreV1().ConfigMaps("cell-ops-system").Get(t.Context(), "bundle-state", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if cm.Labels["poc.internal/made-by"] != "celld" {
		t.Fatalf("labels = %v", cm.Labels)
	}
	var raw map[string]any
	if err := json.Unmarshal([]byte(cm.Data["state.json"]), &raw); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"source", "version", "contentSHA256", "keySHA256", "opId", "state", "holder", "until", "root", "components", "checked", "good", "result"} {
		if _, ok := raw[k]; !ok {
			t.Errorf("state.json has no key %q", k)
		}
	}
	if m := raw["root"].(map[string]any)["manifest"]; m != "eyJhIjoxfQ==" {
		t.Errorf("manifest is not base64: %v", m)
	}
}

func TestConfigMapStoreConflict(t *testing.T) {
	s, _ := newCMStore(t)
	ctx := t.Context()
	if err := s.Write(ctx, State{Source: "signed"}, ""); err != nil {
		t.Fatal(err)
	}
	if err := s.Write(ctx, State{Source: "signed"}, ""); !errors.Is(err, ErrConflict) {
		t.Fatalf("second create = %v, want ErrConflict", err)
	}
	_, rv, _ := s.Read(ctx)
	if err := s.Write(ctx, State{Source: "signed", OpID: "a"}, rv); err != nil {
		t.Fatal(err)
	}
	if err := s.Write(ctx, State{Source: "signed", OpID: "b"}, rv); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale write = %v, want ErrConflict", err)
	}
	st, _, _ := s.Read(ctx)
	if st.OpID != "a" {
		t.Fatalf("state = %+v", st)
	}
}

func TestConfigMapStoreRefusesBadData(t *testing.T) {
	s, cs := newCMStore(t)
	_ = s.Write(t.Context(), State{Source: "signed"}, "")
	cm, _ := cs.CoreV1().ConfigMaps("cell-ops-system").Get(t.Context(), "bundle-state", metav1.GetOptions{})
	cm.Data["state.json"] = `{"source":"signed","bogus":1}`
	if _, err := cs.CoreV1().ConfigMaps("cell-ops-system").Update(t.Context(), cm, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Read(t.Context()); err == nil {
		t.Fatal("unknown field accepted")
	}
}
