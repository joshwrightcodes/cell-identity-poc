package envd

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmtapi"
)

// The keys and annotations of the records ConfigMap.
const (
	SpecKey           = "spec-envelope.json"
	RecordSuffix      = ".dsse.json"
	AnnotationEpoch   = "poc.internal/spec-epoch"
	AnnotationCounter = "poc.internal/spec-counter"
	AnnotationKeySHA  = "poc.internal/spec-key-sha256"
)

// ErrStateUnverifiable means the stored state carries the fingerprint of the pinned key but does
// not verify. Load never replaces such a state with an empty one, because that would drop the marks.
var ErrStateUnverifiable = errors.New(mgmtapi.ReasonStateUnverifiable)

// Store keeps the accepted state.
type Store interface {
	Load(ctx context.Context) (*State, error)
	Save(ctx context.Context, s *State) error
}

type configMapStore struct {
	c         kubernetes.Interface
	namespace string
	name      string
	env       string
	keys      []ed25519.PublicKey
	pin       string
	log       *slog.Logger
}

// KeyFingerprint returns the lowercase hex SHA-256 of the pinned keys, joined in order.
func KeyFingerprint(keys []ed25519.PublicKey) string {
	h := sha256.New()
	for _, k := range keys {
		h.Write(k)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// NewConfigMapStore returns a Store on the ConfigMap namespace/name. Load gives Empty() for an
// absent ConfigMap and for one that another key wrote, and an error that wraps ErrStateUnverifiable
// for one that the pinned key wrote and that does not verify.
func NewConfigMapStore(c kubernetes.Interface, namespace, name, env string, keys []ed25519.PublicKey, log *slog.Logger) Store {
	return &configMapStore{c: c, namespace: namespace, name: name, env: env, keys: keys, pin: KeyFingerprint(keys), log: log}
}

func (s *configMapStore) Load(ctx context.Context) (*State, error) {
	cm, err := s.c.CoreV1().ConfigMaps(s.namespace).Get(ctx, s.name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return Empty(), nil
	}
	if err != nil {
		return nil, fmt.Errorf("read configmap %s/%s: %w", s.namespace, s.name, err)
	}
	if got := cm.Annotations[AnnotationKeySHA]; got != s.pin {
		s.log.Warn("state_reset", "configmap", s.namespace+"/"+s.name, "stored_key_sha256", got, "pinned_key_sha256", s.pin)
		return Empty(), nil
	}
	b := mgmtapi.SpecBundle{Records: map[string]json.RawMessage{}}
	b.Spec = json.RawMessage(cm.Data[SpecKey])
	for k, v := range cm.Data {
		if name, ok := strings.CutSuffix(k, RecordSuffix); ok {
			b.Records[name] = json.RawMessage(v)
		}
	}
	st, _, err := Accept(Empty(), b, s.env, s.keys)
	if err != nil {
		return nil, fmt.Errorf("%w: configmap %s/%s: %v", ErrStateUnverifiable, s.namespace, s.name, err)
	}
	return st, nil
}

func (s *configMapStore) Save(ctx context.Context, st *State) error {
	data := make(map[string]string, len(st.Records)+1)
	data[SpecKey] = string(st.SpecEnvelope)
	for name, raw := range st.Records {
		data[name+RecordSuffix] = string(raw)
	}
	annotations := map[string]string{
		AnnotationEpoch:   strconv.FormatUint(st.Revision.Epoch, 10),
		AnnotationCounter: strconv.FormatUint(st.Revision.Counter, 10),
		AnnotationKeySHA:  s.pin,
	}
	cms := s.c.CoreV1().ConfigMaps(s.namespace)
	live, err := cms.Get(ctx, s.name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		_, err = cms.Create(ctx, &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Name: s.name, Namespace: s.namespace, Annotations: annotations},
			Data:       data,
		}, metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("create configmap %s/%s: %w", s.namespace, s.name, err)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("read configmap %s/%s: %w", s.namespace, s.name, err)
	}
	next := live.DeepCopy()
	next.Data = data
	next.BinaryData = nil
	if next.Annotations == nil {
		next.Annotations = map[string]string{}
	}
	for k, v := range annotations {
		next.Annotations[k] = v
	}
	if _, err := cms.Update(ctx, next, metav1.UpdateOptions{}); err != nil {
		return fmt.Errorf("update configmap %s/%s: %w", s.namespace, s.name, err)
	}
	return nil
}
