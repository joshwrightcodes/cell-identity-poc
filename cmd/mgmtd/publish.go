package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
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
)

// publishLabels are the two labels of the shared table.
var publishLabels = map[string]string{
	"cell.poc.internal/harness": "mgmt-api",
	"poc.internal/made-by":      "mgmtd",
}

// PublishPublicKey creates or repairs ConfigMap name in namespace so that key spec.pub holds the
// standard base64 of the 32 bytes of pub, and the ConfigMap carries the two labels. Each write sets
// the field manager mgmtd. A ConfigMap that is already right is not written.
func PublishPublicKey(ctx context.Context, c kubernetes.Interface, namespace, name string, pub ed25519.PublicKey) error {
	if len(pub) != ed25519.PublicKeySize {
		return errors.New("public key has the wrong size")
	}
	want := base64.StdEncoding.EncodeToString(pub)
	cms := c.CoreV1().ConfigMaps(namespace)
	cm, err := cms.Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		_, err = cms.Create(ctx, &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace, Labels: copyMap(publishLabels)},
			Data:       map[string]string{pubKey: want},
		}, metav1.CreateOptions{FieldManager: fieldManager})
		if err != nil {
			return fmt.Errorf("create ConfigMap %s/%s: %w", namespace, name, err)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("get ConfigMap %s/%s: %w", namespace, name, err)
	}
	if cm.Data[pubKey] == want && hasLabels(cm.Labels) {
		return nil
	}
	cm = cm.DeepCopy()
	if cm.Data == nil {
		cm.Data = map[string]string{}
	}
	cm.Data[pubKey] = want
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
