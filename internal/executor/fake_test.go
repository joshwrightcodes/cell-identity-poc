package executor

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"log/slog"
	"strconv"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	clienttesting "k8s.io/client-go/testing"

	"github.com/joshwrightcodes/cell-identity-poc/internal/op"
)

var configMaps = schema.GroupVersionResource{Version: "v1", Resource: "configmaps"}

// newClient returns a fake client whose ConfigMap writes are atomic: a second create gives
// AlreadyExists, and update compares resourceVersion and raises it.
func newClient() *fake.Clientset {
	cs := fake.NewSimpleClientset()
	var mu sync.Mutex
	cs.PrependReactor("create", "configmaps", func(a clienttesting.Action) (bool, runtime.Object, error) {
		mu.Lock()
		defer mu.Unlock()
		ca := a.(clienttesting.CreateAction)
		cm := ca.GetObject().(*corev1.ConfigMap).DeepCopy()
		cm.ResourceVersion = "1"
		if err := cs.Tracker().Create(configMaps, cm, ca.GetNamespace()); err != nil {
			return true, nil, err
		}
		return true, cm.DeepCopy(), nil
	})
	cs.PrependReactor("update", "configmaps", func(a clienttesting.Action) (bool, runtime.Object, error) {
		mu.Lock()
		defer mu.Unlock()
		ua := a.(clienttesting.UpdateAction)
		cm := ua.GetObject().(*corev1.ConfigMap).DeepCopy()
		cur, err := cs.Tracker().Get(configMaps, ua.GetNamespace(), cm.Name)
		if err != nil {
			return true, nil, err
		}
		have := cur.(*corev1.ConfigMap).ResourceVersion
		if cm.ResourceVersion != have {
			return true, nil, apierrors.NewConflict(configMaps.GroupResource(), cm.Name, nil)
		}
		n, _ := strconv.Atoi(have)
		cm.ResourceVersion = strconv.Itoa(n + 1)
		if err := cs.Tracker().Update(configMaps, cm, ua.GetNamespace()); err != nil {
			return true, nil, err
		}
		return true, cm.DeepCopy(), nil
	})
	return cs
}

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *clock { return &clock{t: time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)} }

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// counter is the test.count effect: it counts calls and does not deduplicate.
type counter struct {
	mu sync.Mutex
	n  int
}

func (c *counter) effect(context.Context, *Executor, op.Operation) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.n++
	return nil
}

func (c *counter) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.n
}

const testKind = "test.count"

type rig struct {
	t      *testing.T
	client *fake.Clientset
	clock  *clock
	cnt    *counter
	pub    ed25519.PublicKey
	priv   ed25519.PrivateKey
}

func newRig(t *testing.T) *rig {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &rig{t: t, client: newClient(), clock: newClock(), cnt: &counter{}, pub: pub, priv: priv}
}

func (r *rig) kinds() map[string]Effect {
	k := DefaultKinds()
	k[testKind] = r.cnt.effect
	return k
}

func (r *rig) executor(podUID string, mod ...func(*Config)) *Executor {
	cfg := Config{
		Cell: "cell-1", Env: "dev", Pod: "celld-" + podUID, PodUID: podUID, Namespace: DefaultNamespace,
		Keys: []ed25519.PublicKey{r.pub}, Kinds: r.kinds(), Client: r.client,
		Now: r.clock.Now, Log: slog.New(slog.NewJSONHandler(io.Discard, nil)),
	}
	for _, m := range mod {
		m(&cfg)
	}
	return New(cfg)
}

// operation returns a valid operation for the rig clock.
func (r *rig) operation(kind, args string) op.Operation {
	now := r.clock.Now()
	return op.Operation{
		ID: op.NewID(), Env: "dev", Cell: "cell-1", Kind: kind, Version: 1, KeyEpoch: 1,
		IssuedAt: now, ExpiresAt: now.Add(10 * time.Minute), Args: []byte(args),
	}
}

func (r *rig) sign(o op.Operation) []byte {
	r.t.Helper()
	env, err := op.Sign(o, r.priv)
	if err != nil {
		r.t.Fatal(err)
	}
	return env
}

func (r *rig) list() []corev1.ConfigMap {
	r.t.Helper()
	l, err := r.client.CoreV1().ConfigMaps(DefaultNamespace).List(context.Background(), metav1.ListOptions{})
	if err != nil {
		r.t.Fatal(err)
	}
	return l.Items
}

func (r *rig) records() []corev1.ConfigMap {
	var out []corev1.ConfigMap
	for _, cm := range r.list() {
		if _, ok := cm.Data[recordKey]; ok {
			out = append(out, cm)
		}
	}
	return out
}

func (r *rig) record(id string) storedRecord {
	r.t.Helper()
	cm, err := r.client.CoreV1().ConfigMaps(DefaultNamespace).Get(context.Background(), recordPrefix+id, metav1.GetOptions{})
	if err != nil {
		r.t.Fatal(err)
	}
	rec, err := decodeRecord(cm)
	if err != nil {
		r.t.Fatal(err)
	}
	return rec
}
