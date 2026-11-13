package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"

	"github.com/joshwrightcodes/cell-identity-poc/internal/cellproxy"
	"github.com/joshwrightcodes/cell-identity-poc/internal/record"
	"github.com/joshwrightcodes/cell-identity-poc/internal/testtool/kubetoken"
)

func newKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func TestPublishPublicKey(t *testing.T) {
	client := fake.NewClientset()
	var managers []string
	client.PrependReactor("create", "configmaps", func(a ktesting.Action) (bool, runtime.Object, error) {
		managers = append(managers, "create:"+a.(ktesting.CreateActionImpl).CreateOptions.FieldManager)
		return false, nil, nil
	})
	client.PrependReactor("update", "configmaps", func(a ktesting.Action) (bool, runtime.Object, error) {
		managers = append(managers, "update:"+a.(ktesting.UpdateActionImpl).UpdateOptions.FieldManager)
		return false, nil, nil
	})
	pub, priv := newKey(t)
	ctx := t.Context()

	if err := PublishPublicKey(ctx, client, "mgmt-system", "mgmt-signing-pub", pub, nil); err != nil {
		t.Fatal(err)
	}
	cm, err := client.CoreV1().ConfigMaps("mgmt-system").Get(ctx, "mgmt-signing-pub", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	want := base64.StdEncoding.EncodeToString(pub)
	if cm.Data["spec.pub"] != want || cm.Labels["cell.poc.internal/harness"] != "mgmt-api" || cm.Labels["poc.internal/made-by"] != "mgmtd" {
		t.Fatalf("created ConfigMap: data %v labels %v", cm.Data, cm.Labels)
	}
	if len(managers) != 1 || managers[0] != "create:mgmtd" {
		t.Fatalf("create field manager: %v", managers)
	}

	// A second publish of the same key changes nothing.
	if err := PublishPublicKey(ctx, client, "mgmt-system", "mgmt-signing-pub", pub, nil); err != nil {
		t.Fatal(err)
	}
	if len(managers) != 1 {
		t.Fatalf("an unchanged publish wrote again: %v", managers)
	}

	// A wrong value and a lost label are repaired, and a key that is not in the data map goes.
	cm.Data["spec.pub"] = "AAAA"
	cm.Data["other"] = "keep"
	cm.Labels = map[string]string{"x": "y"}
	if _, err := client.CoreV1().ConfigMaps("mgmt-system").Update(ctx, cm, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	managers = nil
	if err := PublishPublicKey(ctx, client, "mgmt-system", "mgmt-signing-pub", pub, nil); err != nil {
		t.Fatal(err)
	}
	cm, _ = client.CoreV1().ConfigMaps("mgmt-system").Get(ctx, "mgmt-signing-pub", metav1.GetOptions{})
	if cm.Data["spec.pub"] != want || len(cm.Data) != 1 || cm.Labels["poc.internal/made-by"] != "mgmtd" || cm.Labels["x"] != "y" {
		t.Fatalf("repaired ConfigMap: data %v labels %v", cm.Data, cm.Labels)
	}
	if len(managers) != 1 || managers[0] != "update:mgmtd" {
		t.Fatalf("update field manager: %v", managers)
	}

	// The ConfigMap holds the public key only.
	var all bytes.Buffer
	for _, v := range cm.Data {
		all.WriteString(v)
	}
	if strings.Contains(all.String(), base64.StdEncoding.EncodeToString(priv)) || strings.Contains(all.String(), base64.StdEncoding.EncodeToString(priv.Seed())) {
		t.Fatal("the ConfigMap holds private key bytes")
	}

	if err := PublishPublicKey(ctx, client, "mgmt-system", "x", ed25519.PublicKey("short"), nil); err == nil {
		t.Fatal("a key of the wrong size was published")
	}
	if err := PublishPublicKey(ctx, client, "mgmt-system", "x", pub, ed25519.PublicKey("short")); err == nil {
		t.Fatal("a next key of the wrong size was published")
	}
}

func TestPublishPublicKeyErrors(t *testing.T) {
	client := fake.NewClientset()
	client.PrependReactor("get", "configmaps", func(ktesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("api server down")
	})
	pub, _ := newKey(t)
	if err := PublishPublicKey(t.Context(), client, "mgmt-system", "mgmt-signing-pub", pub, nil); err == nil {
		t.Fatal("no error from a failing API server")
	}
	_ = corev1.ConfigMap{}
}

func TestPublisherRetriesUntilItSucceeds(t *testing.T) {
	pub, _ := newKey(t)
	var calls atomic.Int32
	done := make(chan struct{})
	var once sync.Once
	publish := func(_ context.Context, got ed25519.PublicKey) error {
		if !got.Equal(pub) {
			t.Error("wrong key")
		}
		if calls.Add(1) < 3 {
			return errors.New("not yet")
		}
		once.Do(func() { close(done) })
		return nil
	}
	var logs lockedBuffer
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	nudge := make(chan struct{}, 1)
	go runPublisher(ctx, func() ed25519.PublicKey { return pub }, publish, nudge, jsonLogger(&logs), time.Millisecond, time.Hour)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("no success after %d calls", calls.Load())
	}
	// A nudge publishes again, for example after a rotation.
	n := calls.Load()
	nudge <- struct{}{}
	deadline := time.Now().Add(3 * time.Second)
	for calls.Load() == n && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if calls.Load() == n {
		t.Fatal("a nudge did not publish")
	}
	if !strings.Contains(logs.String(), "public_key_publish_failed") || !strings.Contains(logs.String(), "public_key_published") {
		t.Fatalf("log: %s", logs.String())
	}
}

// The background loop must back off after a failure. Probe of the backend review: the loop is wired
// as serve wires it, and every write fails.
func TestPublisherBacksOffAfterFailure(t *testing.T) {
	pub, _ := newKey(t)
	var calls atomic.Int32
	p := newKeyPublisher(func() ed25519.PublicKey { return pub }, func(context.Context, ed25519.PublicKey) error {
		calls.Add(1)
		return errors.New("forbidden")
	})
	var logs lockedBuffer
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	p.run(ctx, jsonLogger(&logs), 500*time.Millisecond, time.Hour)
	// Backoff 0.5 s, 1 s, then the end: about 3 calls in 2 s.
	if n := calls.Load(); n > 5 {
		t.Fatalf("%d publishes in 2 s with a 500 ms backoff", n)
	}
	if n := strings.Count(logs.String(), "public_key_publish_failed"); n > 2 {
		t.Fatalf("%d warning lines in 2 s", n)
	}
}

// A rotation between the read of the key and the write never puts the old key back.
func TestPublisherWritesTheCurrentKey(t *testing.T) {
	oldKey, _ := newKey(t)
	newer, _ := newKey(t)
	var cur atomic.Pointer[ed25519.PublicKey]
	cur.Store(&oldKey)
	var written []ed25519.PublicKey
	var mu sync.Mutex
	p := newKeyPublisher(func() ed25519.PublicKey { return *cur.Load() }, func(_ context.Context, k ed25519.PublicKey) error {
		mu.Lock()
		defer mu.Unlock()
		written = append(written, k)
		return nil
	})
	cur.Store(&newer)
	// The caller passes the key that it read before the rotation.
	if err := p.publish(t.Context(), oldKey); err != nil {
		t.Fatal(err)
	}
	if len(written) != 1 || !written[0].Equal(newer) {
		t.Fatalf("wrote %d keys, the first is not the current one", len(written))
	}
}

func TestPublisherResyncs(t *testing.T) {
	pub, _ := newKey(t)
	var calls atomic.Int32
	p := newKeyPublisher(func() ed25519.PublicKey { return pub }, func(context.Context, ed25519.PublicKey) error { calls.Add(1); return nil })
	ctx, cancel := context.WithTimeout(t.Context(), 400*time.Millisecond)
	defer cancel()
	p.run(ctx, jsonLogger(&lockedBuffer{}), time.Millisecond, 50*time.Millisecond)
	if calls.Load() < 3 {
		t.Fatalf("%d publishes in 400 ms with a 50 ms resync", calls.Load())
	}
}

func TestPublishRepairsLabelDrift(t *testing.T) {
	client := fake.NewClientset()
	pub, _ := newKey(t)
	must(t, PublishPublicKey(t.Context(), client, "mgmt-system", "c", pub, nil))
	cm, _ := client.CoreV1().ConfigMaps("mgmt-system").Get(t.Context(), "c", metav1.GetOptions{})
	cm.Labels = map[string]string{}
	_, err := client.CoreV1().ConfigMaps("mgmt-system").Update(t.Context(), cm, metav1.UpdateOptions{})
	must(t, err)
	must(t, PublishPublicKey(t.Context(), client, "mgmt-system", "c", pub, nil))
	cm, _ = client.CoreV1().ConfigMaps("mgmt-system").Get(t.Context(), "c", metav1.GetOptions{})
	if cm.Labels["poc.internal/made-by"] != "mgmtd" {
		t.Fatalf("labels %v", cm.Labels)
	}
}

// Writes never overlap, and the last write holds the current key. A background write that started
// before a rotation finishes first, and the admin write after the rotation follows it.
func TestPublishWritesAreSerialized(t *testing.T) {
	oldKey, _ := newKey(t)
	newer, _ := newKey(t)
	var cur atomic.Pointer[ed25519.PublicKey]
	cur.Store(&oldKey)
	var active, maxActive atomic.Int32
	var mu sync.Mutex
	var written []ed25519.PublicKey
	entered := make(chan struct{}, 4)
	gate := make(chan struct{})
	p := newKeyPublisher(func() ed25519.PublicKey { return *cur.Load() }, func(_ context.Context, k ed25519.PublicKey) error {
		n := active.Add(1)
		for {
			m := maxActive.Load()
			if n <= m || maxActive.CompareAndSwap(m, n) {
				break
			}
		}
		entered <- struct{}{}
		<-gate
		mu.Lock()
		written = append(written, k)
		mu.Unlock()
		active.Add(-1)
		return nil
	})
	var wg sync.WaitGroup
	wg.Go(func() { _ = p.publish(t.Context(), oldKey) })
	<-entered
	cur.Store(&newer)
	wg.Go(func() { _ = p.adminPublish(t.Context(), newer) })
	select {
	case <-entered:
		t.Fatal("a second write started while the first one was running")
	case <-time.After(300 * time.Millisecond):
	}
	gate <- struct{}{}
	<-entered
	gate <- struct{}{}
	wg.Wait()
	if maxActive.Load() != 1 {
		t.Fatalf("%d writes at once", maxActive.Load())
	}
	if len(written) != 2 || !written[1].Equal(newer) {
		t.Fatalf("the last write does not hold the current key")
	}
}

// A publish that waits behind a stuck write gives up with its context.
func TestPublishWaitRespectsContext(t *testing.T) {
	pub, _ := newKey(t)
	gate := make(chan struct{})
	entered := make(chan struct{}, 1)
	p := newKeyPublisher(func() ed25519.PublicKey { return pub }, func(context.Context, ed25519.PublicKey) error {
		entered <- struct{}{}
		<-gate
		return nil
	})
	go func() { _ = p.publish(context.Background(), pub) }()
	<-entered
	defer close(gate)
	ctx, cancel := context.WithTimeout(t.Context(), 150*time.Millisecond)
	defer cancel()
	start := time.Now()
	if err := p.adminPublish(ctx, pub); err == nil {
		t.Fatal("the publish returned no error behind a stuck write")
	}
	if time.Since(start) > 2*time.Second {
		t.Fatalf("the publish waited %s", time.Since(start))
	}
}

// next.pub is in the data map only while a key is staged, and any other key set is drift.
func TestPublishNextKey(t *testing.T) {
	client := fake.NewClientset()
	var writes int
	for _, verb := range []string{"create", "update"} {
		client.PrependReactor(verb, "configmaps", func(ktesting.Action) (bool, runtime.Object, error) {
			writes++
			return false, nil, nil
		})
	}
	pub, _ := newKey(t)
	next, _ := newKey(t)
	ctx := t.Context()
	data := func() map[string]string {
		t.Helper()
		cm, err := client.CoreV1().ConfigMaps("mgmt-system").Get(ctx, "mgmt-signing-pub", metav1.GetOptions{})
		must(t, err)
		return cm.Data
	}
	pubB64, nextB64 := base64.StdEncoding.EncodeToString(pub), base64.StdEncoding.EncodeToString(next)

	// A key is staged: both keys are published.
	must(t, PublishPublicKey(ctx, client, "mgmt-system", "mgmt-signing-pub", pub, next))
	if d := data(); len(d) != 2 || d["spec.pub"] != pubB64 || d["next.pub"] != nextB64 {
		t.Fatalf("staged data %v", d)
	}
	// The same input writes nothing.
	writes = 0
	must(t, PublishPublicKey(ctx, client, "mgmt-system", "mgmt-signing-pub", pub, next))
	if writes != 0 {
		t.Fatalf("an unchanged staged publish wrote %d times", writes)
	}
	// A commit: the next key is the signing key, and next.pub goes (B-05).
	must(t, PublishPublicKey(ctx, client, "mgmt-system", "mgmt-signing-pub", next, nil))
	if d := data(); len(d) != 1 || d["spec.pub"] != nextB64 {
		t.Fatalf("committed data %v", d)
	}
	// A next.pub that stays after the commit is drift, and so is any other key.
	cm, _ := client.CoreV1().ConfigMaps("mgmt-system").Get(ctx, "mgmt-signing-pub", metav1.GetOptions{})
	cm.Data["next.pub"] = pubB64
	cm.Data["extra"] = "x"
	_, err := client.CoreV1().ConfigMaps("mgmt-system").Update(ctx, cm, metav1.UpdateOptions{})
	must(t, err)
	writes = 0
	must(t, PublishPublicKey(ctx, client, "mgmt-system", "mgmt-signing-pub", next, nil))
	if d := data(); len(d) != 1 || d["spec.pub"] != nextB64 || writes != 1 {
		t.Fatalf("data after the drift %v, %d writes", d, writes)
	}
	// Staging again adds next.pub in one write.
	writes = 0
	must(t, PublishPublicKey(ctx, client, "mgmt-system", "mgmt-signing-pub", next, pub))
	if d := data(); len(d) != 2 || d["next.pub"] != pubB64 || writes != 1 {
		t.Fatalf("data after staging again %v, %d writes", d, writes)
	}
}

// ---- Registry

func registryRecords(t *testing.T, priv ed25519.PrivateKey, cells ...string) map[string]json.RawMessage {
	t.Helper()
	out := map[string]json.RawMessage{}
	for _, c := range cells {
		env, err := record.Sign(record.Cell{
			Name: c, Env: "dev", Issuer: "https://" + c + ".test", JWKS: kubetoken.NewSigner(t, "kid-1", jose.ES256).JWKS(),
			Subjects: []record.Subject{{Namespace: "cell-identity-system", ServiceAccount: "celld"}}, Epoch: 1, Counter: 1,
		}, priv)
		must(t, err)
		out[c] = env
	}
	return out
}

var registryNamespaces = []string{"central-view-system", "observability-system", "mesh-view-system"}

func getRegistry(t *testing.T, c kubernetes.Interface, ns string) *corev1.ConfigMap {
	t.Helper()
	cm, err := c.CoreV1().ConfigMaps(ns).Get(t.Context(), "cell-registry", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("ConfigMap cell-registry in %s: %v", ns, err)
	}
	return cm
}

// cellFiles returns the record files of the data of a registry ConfigMap.
func cellFiles(cm *corev1.ConfigMap) map[string]string {
	out := map[string]string{}
	for k, v := range cm.Data {
		if strings.HasSuffix(k, ".dsse.json") {
			out[k] = v
		}
	}
	return out
}

func TestPublishRegistry(t *testing.T) {
	client := fake.NewClientset()
	pub, priv := newKey(t)
	records := registryRecords(t, priv, "dev-cell-1", "dev-cell-2")
	// An object with a harness label, a content annotation and a stray key is rewritten, and the
	// namespaces without an object get one.
	_, err := client.CoreV1().ConfigMaps("central-view-system").Create(t.Context(), &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name: "cell-registry", Namespace: "central-view-system",
			Labels:      map[string]string{"cell.poc.internal/harness": "central-view", "poc.internal/made-by": "mgmtd", "other": "label"},
			Annotations: map[string]string{"poc.internal/registry-content-sha256": "abc"},
		},
		Data: map[string]string{"stale.dsse.json": "x", "signers.pub": "old\n"},
	}, metav1.CreateOptions{})
	must(t, err)

	must(t, PublishRegistry(t.Context(), client, registryNamespaces, records, pub))
	for _, ns := range registryNamespaces {
		cm := getRegistry(t, client, ns)
		if len(cm.Labels) != 1 || cm.Labels["poc.internal/made-by"] != "mgmtd" || len(cm.Annotations) != 0 {
			t.Errorf("%s: labels %v annotations %v, want only the mgmtd label", ns, cm.Labels, cm.Annotations)
		}
		if len(cm.Data) != 3 || cm.Data["dev-cell-1.dsse.json"] != string(records["dev-cell-1"]) || cm.Data["dev-cell-2.dsse.json"] != string(records["dev-cell-2"]) {
			t.Errorf("%s: data keys %v", ns, keysOf(cm.Data))
		}
		if cm.Data["signers.pub"] != base64.StdEncoding.EncodeToString(pub)+"\n" {
			t.Errorf("%s: signers.pub %q", ns, cm.Data["signers.pub"])
		}
		// cell-proxy reads this directory.
		dir := t.TempDir()
		for k, v := range cm.Data {
			must(t, os.WriteFile(filepath.Join(dir, k), []byte(v), 0o600))
		}
		reg, err := cellproxy.LoadRegistry(dir)
		if err != nil {
			t.Fatalf("%s: LoadRegistry: %v", ns, err)
		}
		if _, ok := reg.Record("dev-cell-2"); !ok {
			t.Errorf("%s: the registry holds no record of dev-cell-2", ns)
		}
	}
	if err := PublishRegistry(t.Context(), client, registryNamespaces, records, ed25519.PublicKey("short")); err == nil {
		t.Fatal("a key of the wrong size was published")
	}
}

func keysOf(m map[string]string) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// An unchanged registry is not written again, and one namespace that fails does not stop the others.
func TestPublishRegistryWritesOnlyOnChange(t *testing.T) {
	client := fake.NewClientset()
	var writes atomic.Int32
	for _, verb := range []string{"create", "update"} {
		client.PrependReactor(verb, "configmaps", func(a ktesting.Action) (bool, runtime.Object, error) {
			if a.GetNamespace() == "observability-system" {
				return true, nil, apierrors.NewForbidden(schema.GroupResource{Resource: "configmaps"}, "cell-registry", errors.New("no"))
			}
			writes.Add(1)
			return false, nil, nil
		})
	}
	pub, priv := newKey(t)
	records := registryRecords(t, priv, "dev-cell-1")
	err := PublishRegistry(t.Context(), client, registryNamespaces, records, pub)
	if err == nil || !strings.Contains(err.Error(), "observability-system") || strings.Contains(err.Error(), "central-view-system") {
		t.Fatalf("error %v", err)
	}
	getRegistry(t, client, "central-view-system")
	getRegistry(t, client, "mesh-view-system")
	if writes.Load() != 2 {
		t.Fatalf("%d writes, want 2", writes.Load())
	}
	_ = PublishRegistry(t.Context(), client, registryNamespaces, records, pub)
	if writes.Load() != 2 {
		t.Fatalf("an unchanged registry was written again: %d writes", writes.Load())
	}
}

func TestPublishRegistryRetriesForbidden(t *testing.T) {
	client := fake.NewClientset()
	var allowed atomic.Bool
	var attempts atomic.Int32
	client.PrependReactor("*", "configmaps", func(a ktesting.Action) (bool, runtime.Object, error) {
		if a.GetNamespace() == "observability-system" && !allowed.Load() {
			if a.GetVerb() == "get" {
				attempts.Add(1)
			}
			return true, nil, apierrors.NewForbidden(schema.GroupResource{Resource: "configmaps"}, "cell-registry", errors.New("no role"))
		}
		return false, nil, nil
	})
	pub, priv := newKey(t)
	p := newRegistryPublisher()
	p.set(registryRecords(t, priv, "dev-cell-1"), pub)
	var logs lockedBuffer
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		p.run(ctx, client, registryNamespaces, jsonLogger(&logs), 20*time.Millisecond, time.Hour)
		close(done)
	}()
	defer func() { cancel(); <-done }()

	// The other namespaces are served while one is forbidden.
	waitFor(t, "the allowed namespaces", func() bool {
		_, e1 := client.CoreV1().ConfigMaps("central-view-system").Get(t.Context(), "cell-registry", metav1.GetOptions{})
		_, e2 := client.CoreV1().ConfigMaps("mesh-view-system").Get(t.Context(), "cell-registry", metav1.GetOptions{})
		return e1 == nil && e2 == nil
	})
	// The forbidden one backs off: 20 ms, 40, 80, 160 ... gives a handful of tries in 600 ms.
	waitFor(t, "four tries", func() bool { return attempts.Load() >= 4 })
	time.Sleep(600 * time.Millisecond)
	if n := attempts.Load(); n > 12 {
		t.Fatalf("%d tries in about 1 s with a backoff that starts at 20 ms", n)
	}
	// One line for a namespace whose error stays the same.
	if n := strings.Count(logs.String(), `"msg":"registry_publish_failed"`); n != 1 {
		t.Fatalf("%d failure lines, want 1: %s", n, logs.String())
	}
	if !strings.Contains(logs.String(), `"namespace":"observability-system"`) || strings.Contains(logs.String(), `"error":"`+"namespace central") {
		t.Fatalf("log %s", logs.String())
	}
	allowed.Store(true)
	waitFor(t, "the forbidden namespace after the Role appears", func() bool {
		_, err := client.CoreV1().ConfigMaps("observability-system").Get(t.Context(), "cell-registry", metav1.GetOptions{})
		return err == nil
	})
	waitFor(t, "the recovery line", func() bool { return strings.Contains(logs.String(), `"msg":"registry_published"`) })
}

func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// A deleted or edited ConfigMap is back within one check, and the check is 60 s in production.
func TestPublishRegistryRepairsDrift(t *testing.T) {
	if registryResync != time.Minute || registryBackoff != time.Second || maxPublishBackoff != 30*time.Second {
		t.Fatalf("resync %s, backoff %s to %s", registryResync, registryBackoff, maxPublishBackoff)
	}
	client := fake.NewClientset()
	pub, priv := newKey(t)
	records := registryRecords(t, priv, "dev-cell-1")
	p := newRegistryPublisher()
	p.set(records, pub)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		p.run(ctx, client, registryNamespaces[:2], jsonLogger(&lockedBuffer{}), time.Millisecond, 50*time.Millisecond)
		close(done)
	}()
	defer func() { cancel(); <-done }()
	want := string(records["dev-cell-1"])
	waitFor(t, "both ConfigMaps", func() bool {
		for _, ns := range registryNamespaces[:2] {
			if _, err := client.CoreV1().ConfigMaps(ns).Get(t.Context(), "cell-registry", metav1.GetOptions{}); err != nil {
				return false
			}
		}
		return true
	})
	cms := client.CoreV1().ConfigMaps("central-view-system")
	must(t, cms.Delete(t.Context(), "cell-registry", metav1.DeleteOptions{}))
	waitFor(t, "the deleted ConfigMap", func() bool {
		cm, err := cms.Get(t.Context(), "cell-registry", metav1.GetOptions{})
		return err == nil && cellFiles(cm)["dev-cell-1.dsse.json"] == want
	})
	cm := getRegistry(t, client, "observability-system")
	cm.Data["dev-cell-1.dsse.json"] = "tampered"
	cm.Data["dev-cell-9.dsse.json"] = "stray"
	cm.Labels["cell.poc.internal/harness"] = "x"
	_, err := client.CoreV1().ConfigMaps("observability-system").Update(t.Context(), cm, metav1.UpdateOptions{})
	must(t, err)
	waitFor(t, "the edited ConfigMap", func() bool {
		cm := getRegistry(t, client, "observability-system")
		files := cellFiles(cm)
		return len(files) == 1 && files["dev-cell-1.dsse.json"] == want && len(cm.Labels) == 1
	})
}

// set never blocks, even while a publish is stuck, and the publisher writes the latest records.
func TestRegistryPublisherKeepsTheLatest(t *testing.T) {
	client := fake.NewClientset()
	gate := make(chan struct{})
	entered := make(chan struct{}, 8)
	var once sync.Once
	client.PrependReactor("get", "configmaps", func(ktesting.Action) (bool, runtime.Object, error) {
		entered <- struct{}{}
		once.Do(func() { <-gate })
		return false, nil, nil
	})
	pub, priv := newKey(t)
	p := newRegistryPublisher()
	p.set(registryRecords(t, priv, "dev-cell-1"), pub)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		p.run(ctx, client, registryNamespaces[:1], jsonLogger(&lockedBuffer{}), time.Millisecond, time.Hour)
		close(done)
	}()
	defer func() { cancel(); <-done }()
	<-entered
	start := time.Now()
	var last map[string]json.RawMessage
	for i := 0; i < 50; i++ {
		last = registryRecords(t, priv, "dev-cell-1", "dev-cell-2")
		p.set(last, pub)
	}
	if d := time.Since(start); d > 500*time.Millisecond {
		t.Fatalf("50 calls of set took %s while a publish was stuck", d)
	}
	close(gate)
	waitFor(t, "the latest records", func() bool {
		cm, err := client.CoreV1().ConfigMaps("central-view-system").Get(t.Context(), "cell-registry", metav1.GetOptions{})
		return err == nil && len(cellFiles(cm)) == 2 && cellFiles(cm)["dev-cell-2.dsse.json"] == string(last["dev-cell-2"])
	})
}

// An object with the right data but a harness label, another label or an annotation is rewritten.
func TestPublishRegistryRepairsLabelsAndAnnotations(t *testing.T) {
	client := fake.NewClientset()
	pub, priv := newKey(t)
	records := registryRecords(t, priv, "dev-cell-1")
	ns := []string{"central-view-system"}
	must(t, PublishRegistry(t.Context(), client, ns, records, pub))
	for name, mod := range map[string]func(*corev1.ConfigMap){
		"harness_label": func(cm *corev1.ConfigMap) { cm.Labels["cell.poc.internal/harness"] = "central-view" },
		"missing_label": func(cm *corev1.ConfigMap) { cm.Labels = map[string]string{} },
		"annotation": func(cm *corev1.ConfigMap) {
			cm.Annotations = map[string]string{"poc.internal/registry-content-sha256": "x"}
		},
		"binary_data":    func(cm *corev1.ConfigMap) { cm.BinaryData = map[string][]byte{"x": []byte("y")} },
		"wrong_made_by":  func(cm *corev1.ConfigMap) { cm.Labels["poc.internal/made-by"] = "harness" },
		"extra_key_only": func(cm *corev1.ConfigMap) { cm.Data["dev-cell-9.dsse.json"] = "x" },
	} {
		cm := getRegistry(t, client, ns[0]).DeepCopy()
		mod(cm)
		_, err := client.CoreV1().ConfigMaps(ns[0]).Update(t.Context(), cm, metav1.UpdateOptions{})
		must(t, err)
		must(t, PublishRegistry(t.Context(), client, ns, records, pub))
		got := getRegistry(t, client, ns[0])
		if len(got.Labels) != 1 || got.Labels["poc.internal/made-by"] != "mgmtd" || len(got.Annotations) != 0 || len(got.BinaryData) != 0 || len(cellFiles(got)) != 1 {
			t.Errorf("%s: labels %v annotations %v binary %d files %v", name, got.Labels, got.Annotations, len(got.BinaryData), keysOf(got.Data))
		}
	}
}

// No record, no registry: PublishRegistry refuses an empty set, and the publisher writes nothing
// and leaves an existing object alone until records arrive.
func TestRegistryPublisherPublishesNothingWhileEmpty(t *testing.T) {
	client := fake.NewClientset()
	pub, priv := newKey(t)
	if err := PublishRegistry(t.Context(), client, registryNamespaces, map[string]json.RawMessage{}, pub); err == nil {
		t.Fatal("an empty record set was published")
	}
	_, err := client.CoreV1().ConfigMaps("central-view-system").Create(t.Context(), &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "cell-registry", Namespace: "central-view-system"},
		Data:       map[string]string{"dev-cell-1.dsse.json": "old", "signers.pub": "old\n"},
	}, metav1.CreateOptions{})
	must(t, err)
	var writes atomic.Int32
	for _, verb := range []string{"create", "update"} {
		client.PrependReactor(verb, "configmaps", func(ktesting.Action) (bool, runtime.Object, error) {
			writes.Add(1)
			return false, nil, nil
		})
	}
	p := newRegistryPublisher()
	p.set(map[string]json.RawMessage{}, pub)
	var logs lockedBuffer
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		p.run(ctx, client, registryNamespaces, jsonLogger(&logs), time.Millisecond, 20*time.Millisecond)
		close(done)
	}()
	defer func() { cancel(); <-done }()
	waitFor(t, "the registry_empty line", func() bool { return strings.Contains(logs.String(), `"msg":"registry_empty"`) })
	time.Sleep(200 * time.Millisecond)
	if writes.Load() != 0 || getRegistry(t, client, "central-view-system").Data["dev-cell-1.dsse.json"] != "old" {
		t.Fatalf("%d writes while no record exists", writes.Load())
	}
	if n := strings.Count(logs.String(), `"msg":"registry_empty"`); n != 1 {
		t.Fatalf("%d registry_empty lines, want 1", n)
	}
	records := registryRecords(t, priv, "dev-cell-1")
	p.set(records, pub)
	waitFor(t, "the first record", func() bool {
		return cellFiles(getRegistry(t, client, "central-view-system"))["dev-cell-1.dsse.json"] == string(records["dev-cell-1"])
	})
}

// The B-05 drift rule on its own: one unrelated key, or binary data, in an otherwise right ConfigMap.
func TestPublishPublicKeyUnrelatedKeyIsDrift(t *testing.T) {
	pub, _ := newKey(t)
	for name, mod := range map[string]func(*corev1.ConfigMap){
		"unrelated_key": func(cm *corev1.ConfigMap) { cm.Data["extra"] = "x" },
		"binary_data":   func(cm *corev1.ConfigMap) { cm.BinaryData = map[string][]byte{"x": []byte("y")} },
	} {
		client := fake.NewClientset()
		must(t, PublishPublicKey(t.Context(), client, "mgmt-system", "c", pub, nil))
		cm, _ := client.CoreV1().ConfigMaps("mgmt-system").Get(t.Context(), "c", metav1.GetOptions{})
		mod(cm)
		_, err := client.CoreV1().ConfigMaps("mgmt-system").Update(t.Context(), cm, metav1.UpdateOptions{})
		must(t, err)
		var writes int
		client.PrependReactor("update", "configmaps", func(ktesting.Action) (bool, runtime.Object, error) { writes++; return false, nil, nil })
		must(t, PublishPublicKey(t.Context(), client, "mgmt-system", "c", pub, nil))
		got, _ := client.CoreV1().ConfigMaps("mgmt-system").Get(t.Context(), "c", metav1.GetOptions{})
		if writes != 1 || len(got.Data) != 1 || len(got.BinaryData) != 0 {
			t.Errorf("%s: %d writes, data %v binary %d", name, writes, got.Data, len(got.BinaryData))
		}
	}
}
