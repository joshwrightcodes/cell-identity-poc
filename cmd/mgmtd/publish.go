package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"math/rand/v2"
	"slices"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/joshwrightcodes/cell-identity-poc/internal/lograte"
)

const (
	fieldManager = "mgmtd"
	pubKey       = "spec.pub"
	nextPubKey   = "next.pub"
)

// publishLabels are the two labels of the shared table.
var publishLabels = map[string]string{
	"cell.poc.internal/harness": "mgmt-api",
	"poc.internal/made-by":      "mgmtd",
}

// PublishPublicKey creates or repairs ConfigMap name in namespace so that its data holds key
// spec.pub with the standard base64 of the 32 bytes of pub, key next.pub with the same form of next
// while a key is staged (next is not empty), and no other key. The ConfigMap carries the two
// labels. Each write sets the field manager mgmtd. A ConfigMap that is already right is not written.
func PublishPublicKey(ctx context.Context, c kubernetes.Interface, namespace, name string, pub, next ed25519.PublicKey) error {
	if len(pub) != ed25519.PublicKeySize {
		return errors.New("public key has the wrong size")
	}
	if len(next) != 0 && len(next) != ed25519.PublicKeySize {
		return errors.New("next public key has the wrong size")
	}
	want := map[string]string{pubKey: base64.StdEncoding.EncodeToString(pub)}
	if len(next) != 0 {
		want[nextPubKey] = base64.StdEncoding.EncodeToString(next)
	}
	cms := c.CoreV1().ConfigMaps(namespace)
	cm, err := cms.Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		_, err = cms.Create(ctx, &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace, Labels: copyMap(publishLabels)},
			Data:       want,
		}, metav1.CreateOptions{FieldManager: fieldManager})
		if err != nil {
			return fmt.Errorf("create ConfigMap %s/%s: %w", namespace, name, err)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("get ConfigMap %s/%s: %w", namespace, name, err)
	}
	if maps.Equal(cm.Data, want) && len(cm.BinaryData) == 0 && hasLabels(cm.Labels) {
		return nil
	}
	cm = cm.DeepCopy()
	cm.Data, cm.BinaryData = want, nil
	if cm.Labels == nil {
		cm.Labels = map[string]string{}
	}
	for k, v := range publishLabels {
		cm.Labels[k] = v
	}
	if _, err := cms.Update(ctx, cm, metav1.UpdateOptions{FieldManager: fieldManager}); err != nil {
		return fmt.Errorf("update ConfigMap %s/%s: %w", namespace, name, err)
	}
	return nil
}

func copyMap(m map[string]string) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func hasLabels(have map[string]string) bool {
	for k, v := range publishLabels {
		if have[k] != v {
			return false
		}
	}
	return true
}

// maxPublishBackoff is the longest wait between two failed publishes.
const maxPublishBackoff = 30 * time.Second

// runPublisher publishes the current public key until it succeeds, and then again after each nudge
// and after each resync interval, so that a ConfigMap changed by someone else is repaired. A failed
// publish waits backoff, doubling up to 30 s, with jitter. It never blocks the caller and returns
// when ctx ends.
func runPublisher(ctx context.Context, current func() ed25519.PublicKey, publish func(context.Context, ed25519.PublicKey) error,
	nudge <-chan struct{}, log *slog.Logger, backoff, resync time.Duration) {
	wait := backoff
	announce := true
	limit := lograte.New(time.Minute, 4, time.Now)
	for {
		err := publish(ctx, current())
		var next <-chan time.Time
		switch {
		case err != nil:
			if _, ok, suppressed, _ := limit.Allow("publish_failed"); ok {
				log.Warn("public_key_publish_failed", "error", err.Error(), "retry_in", wait.String(), "suppressed", suppressed)
			}
			announce = true
			next = time.After(wait + time.Duration(rand.Int64N(int64(wait)/4+1)))
			if wait *= 2; wait > maxPublishBackoff {
				wait = maxPublishBackoff
			}
		default:
			if announce {
				log.Info("public_key_published")
			}
			announce, wait = false, backoff
			next = time.After(resync)
		}
		select {
		case <-ctx.Done():
			return
		case <-nudge:
			announce = true
		case <-next:
		}
	}
}

// publishWriteTimeout bounds one write of the ConfigMap, so that a stuck write frees the lock.
const publishWriteTimeout = 15 * time.Second

// keyPublisher writes the current public key of the plane. One lock (a channel, so that a waiting caller can give up with its context) serializes the writes, and
// each write reads the current key inside the lock, so a rotation that lands during a write is
// never undone by a write of the older key.
type keyPublisher struct {
	sem     chan struct{}
	current func() ed25519.PublicKey
	write   func(context.Context, ed25519.PublicKey) error
	nudge   chan struct{}
}

func newKeyPublisher(current func() ed25519.PublicKey, write func(context.Context, ed25519.PublicKey) error) *keyPublisher {
	return &keyPublisher{sem: make(chan struct{}, 1), current: current, write: write, nudge: make(chan struct{}, 1)}
}

// publish writes the current key. The argument is ignored.
func (p *keyPublisher) publish(ctx context.Context, _ ed25519.PublicKey) error {
	select {
	case p.sem <- struct{}{}:
	case <-ctx.Done():
		return fmt.Errorf("wait for the publish in progress: %w", ctx.Err())
	}
	defer func() { <-p.sem }()
	ctx, cancel := context.WithTimeout(ctx, publishWriteTimeout)
	defer cancel()
	return p.write(ctx, p.current())
}

// adminPublish is publish for the admin handler. A failure wakes the background loop.
func (p *keyPublisher) adminPublish(ctx context.Context, pub ed25519.PublicKey) error {
	err := p.publish(ctx, pub)
	if err != nil {
		select {
		case p.nudge <- struct{}{}:
		default:
		}
	}
	return err
}

// run is the background loop.
func (p *keyPublisher) run(ctx context.Context, log *slog.Logger, backoff, resync time.Duration) {
	runPublisher(ctx, p.current, p.publish, p.nudge, log, backoff, resync)
}

// The ConfigMap of the cell registry, and the timing of its publisher.
const (
	registryName     = "cell-registry"
	registrySigners  = "signers.pub"
	registrySuffix   = ".dsse.json"
	registryMadeBy   = "poc.internal/made-by"
	registryBackoff  = time.Second
	registryResync   = time.Minute
	registryAttempt  = 15 * time.Second
	registryMaxError = 512
)

// registryData returns the data of ConfigMap cell-registry: <cell>.dsse.json with the record
// envelope of each cell, and signers.pub with the base64 of pub and a newline.
func registryData(records map[string]json.RawMessage, pub ed25519.PublicKey) map[string]string {
	data := make(map[string]string, len(records)+1)
	for cell, rec := range records {
		data[cell+registrySuffix] = string(rec)
	}
	data[registrySigners] = base64.StdEncoding.EncodeToString(pub) + "\n"
	return data
}

// publishRegistryNamespace creates or repairs ConfigMap cell-registry in one namespace. The object
// then holds exactly the data of registryData, the one label poc.internal/made-by=mgmtd, and no
// annotation. An object that is already right is not written.
func publishRegistryNamespace(ctx context.Context, c kubernetes.Interface, namespace string, want map[string]string) error {
	cms := c.CoreV1().ConfigMaps(namespace)
	cm, err := cms.Get(ctx, registryName, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		_, err = cms.Create(ctx, &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Name: registryName, Namespace: namespace, Labels: map[string]string{registryMadeBy: fieldManager}},
			Data:       want,
		}, metav1.CreateOptions{FieldManager: fieldManager})
		if err != nil {
			return fmt.Errorf("create ConfigMap %s/%s: %w", namespace, registryName, err)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("get ConfigMap %s/%s: %w", namespace, registryName, err)
	}
	if maps.Equal(cm.Data, want) && len(cm.BinaryData) == 0 && len(cm.Annotations) == 0 &&
		len(cm.Labels) == 1 && cm.Labels[registryMadeBy] == fieldManager {
		return nil
	}
	cm = cm.DeepCopy()
	cm.Data, cm.BinaryData, cm.Annotations = want, nil, nil
	cm.Labels = map[string]string{registryMadeBy: fieldManager}
	if _, err := cms.Update(ctx, cm, metav1.UpdateOptions{FieldManager: fieldManager}); err != nil {
		return fmt.Errorf("update ConfigMap %s/%s: %w", namespace, registryName, err)
	}
	return nil
}

// PublishRegistry creates or repairs ConfigMap cell-registry in each namespace, with
// <cell>.dsse.json for each record and signers.pub for pub. The only label is
// poc.internal/made-by=mgmtd, so that a harness label or another annotation on an existing object
// is removed. An empty record set gives a registry with signers.pub only, which admits no cell.
// It tries every namespace and returns the errors of those that failed.
func PublishRegistry(ctx context.Context, c kubernetes.Interface, namespaces []string, records map[string]json.RawMessage, pub ed25519.PublicKey) error {
	if len(pub) != ed25519.PublicKeySize {
		return errors.New("public key has the wrong size")
	}
	want := registryData(records, pub)
	var errs []error
	for _, ns := range namespaces {
		if err := publishRegistryNamespace(ctx, c, ns, want); err != nil {
			errs = append(errs, fmt.Errorf("namespace %s: %w", ns, err))
		}
	}
	return errors.Join(errs...)
}

// registryPublisher keeps the latest records that the plane signed. set never blocks, so it can run
// inside the commit path of the plane, and a newer set replaces an older one that no publish has
// read.
type registryPublisher struct {
	mu      sync.Mutex
	records map[string]json.RawMessage
	pub     ed25519.PublicKey
	have    bool
	wake    chan struct{}
}

func newRegistryPublisher() *registryPublisher {
	return &registryPublisher{wake: make(chan struct{}, 1)}
}

// set stores copies of the records and the key, and wakes the publisher.
func (p *registryPublisher) set(records map[string]json.RawMessage, pub ed25519.PublicKey) {
	cp := make(map[string]json.RawMessage, len(records))
	for k, v := range records {
		cp[k] = slices.Clone(v)
	}
	p.mu.Lock()
	p.records, p.pub, p.have = cp, slices.Clone(pub), true
	p.mu.Unlock()
	select {
	case p.wake <- struct{}{}:
	default:
	}
}

func (p *registryPublisher) latest() (map[string]json.RawMessage, ed25519.PublicKey, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.records, p.pub, p.have
}

// registryState is the publish state of one namespace.
type registryState struct {
	namespace string
	due       time.Time
	wait      time.Duration
	lastErr   string
	published bool
}

// run publishes the latest records to each namespace until ctx ends. It writes nothing before the
// plane has set a first set, and a set with no record gives a registry that admits no cell. A
// namespace that fails waits backoff, doubling up to 30 s, with jitter, and each namespace has its own wait. A namespace that
// succeeds is read again after resync, and a ConfigMap that differs or is gone is written again. A
// new set wakes every namespace that is not backing off. The log gets one line for a namespace when
// its error changes, and one when it recovers.
func (p *registryPublisher) run(ctx context.Context, c kubernetes.Interface, namespaces []string, log *slog.Logger, backoff, resync time.Duration) {
	states := make([]*registryState, len(namespaces))
	for i, ns := range namespaces {
		states[i] = &registryState{namespace: ns, wait: backoff}
	}
	for {
		now := time.Now()
		records, pub, ok := p.latest()
		if ok {
			want := registryData(records, pub)
			for _, st := range states {
				if now.Before(st.due) {
					continue
				}
				actx, cancel := context.WithTimeout(ctx, registryAttempt)
				err := publishRegistryNamespace(actx, c, st.namespace, want)
				cancel()
				if ctx.Err() != nil {
					return
				}
				p.settle(st, err, log, backoff, resync)
			}
		}
		next := resync
		for _, st := range states {
			if d := time.Until(st.due); d < next {
				next = d
			}
		}
		timer := time.NewTimer(max(next, 0))
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-p.wake:
			for _, st := range states {
				if st.lastErr == "" {
					st.due = time.Time{}
				}
			}
		case <-timer.C:
		}
		timer.Stop()
	}
}

func (p *registryPublisher) settle(st *registryState, err error, log *slog.Logger, backoff, resync time.Duration) {
	if err == nil {
		if st.lastErr != "" || !st.published {
			log.Info("registry_published", "namespace", st.namespace)
		}
		st.lastErr, st.published, st.wait = "", true, backoff
		st.due = time.Now().Add(resync)
		return
	}
	msg := err.Error()
	if len(msg) > registryMaxError {
		msg = msg[:registryMaxError]
	}
	if msg != st.lastErr {
		log.Warn("registry_publish_failed", "namespace", st.namespace, "error", msg, "retry_in", st.wait.String())
	}
	st.lastErr = msg
	st.due = time.Now().Add(st.wait + time.Duration(rand.Int64N(int64(st.wait)/4+1)))
	if st.wait *= 2; st.wait > maxPublishBackoff {
		st.wait = maxPublishBackoff
	}
}
