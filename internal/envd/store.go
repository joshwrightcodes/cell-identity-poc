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

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmtapi"
	"github.com/joshwrightcodes/cell-identity-poc/internal/spec"
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

// ErrStoreNewer means the stored state holds a verified revision above the one to save. Save never
// writes a lower revision over a higher one.
var ErrStoreNewer = errors.New("stored revision is above the revision to save")

// maxSaveAttempts bounds the read-and-write cycles of one Save against concurrent writers.
const maxSaveAttempts = 3

// Store keeps the accepted state.
type Store interface {
	// Load returns the stored state, Empty() when there is none, or an error that wraps
	// ErrStateUnverifiable.
	Load(ctx context.Context) (*State, error)
	// Save writes s as the whole content of the store. It writes against the version that it last
	// read and refuses to lower a verified stored revision.
	Save(ctx context.Context, s *State) error
	// Peek returns the verified stored state and whether the stored content is exactly the canonical
	// form of that state, with no extra keys. A stored state that does not verify gives an error that
	// wraps ErrStateUnverifiable.
	Peek(ctx context.Context) (live *State, clean bool, err error)
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
// absent ConfigMap, and for one whose spec does not verify under the pinned keys and whose key
// annotation differs from the pin. A stored spec that verifies is kept, whatever the annotation says.
// A state that does not verify and carries the pin gives an error that wraps ErrStateUnverifiable.
func NewConfigMapStore(c kubernetes.Interface, namespace, name, env string, keys []ed25519.PublicKey, log *slog.Logger) Store {
	return &configMapStore{c: c, namespace: namespace, name: name, env: env, keys: keys, pin: KeyFingerprint(keys), log: log}
}

func unverifiable(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrStateUnverifiable, clip(fmt.Sprintf(format, args...)))
}

// decode verifies the content of cm. The spec comes first, and only the records that it indexes are
// read. clean is false when the ConfigMap holds anything else, or annotations that do not match.
func (s *configMapStore) decode(cm *corev1.ConfigMap) (st *State, clean bool, err error) {
	raw, ok := cm.Data[SpecKey]
	if !ok {
		return nil, false, unverifiable("configmap %s/%s has no %s", s.namespace, s.name, SpecKey)
	}
	sp, _, err := spec.Verify([]byte(raw), s.keys)
	if err != nil {
		return nil, false, unverifiable("configmap %s/%s: %v", s.namespace, s.name, err)
	}
	b := mgmtapi.SpecBundle{Spec: json.RawMessage(raw), Records: map[string]json.RawMessage{}}
	want := map[string]bool{SpecKey: true}
	for _, e := range sp.Cells {
		want[e.Name+RecordSuffix] = true
		if v, ok := cm.Data[e.Name+RecordSuffix]; ok {
			b.Records[e.Name] = json.RawMessage(v)
		}
	}
	st, _, err = Accept(Empty(), b, s.env, s.keys)
	if err != nil {
		return nil, false, unverifiable("configmap %s/%s: %v", s.namespace, s.name, err)
	}
	clean = len(cm.BinaryData) == 0 && len(cm.Data) == len(want) &&
		cm.Annotations[AnnotationKeySHA] == s.pin &&
		cm.Annotations[AnnotationEpoch] == strconv.FormatUint(st.Revision.Epoch, 10) &&
		cm.Annotations[AnnotationCounter] == strconv.FormatUint(st.Revision.Counter, 10)
	return st, clean, nil
}

func (s *configMapStore) get(ctx context.Context) (*corev1.ConfigMap, error) {
	cm, err := s.c.CoreV1().ConfigMaps(s.namespace).Get(ctx, s.name, metav1.GetOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		return nil, fmt.Errorf("read configmap %s/%s: %w", s.namespace, s.name, err)
	}
	if err != nil {
		return nil, nil
	}
	return cm, nil
}

func (s *configMapStore) Load(ctx context.Context) (*State, error) {
	cm, err := s.get(ctx)
	if err != nil {
		return nil, err
	}
	if cm == nil {
		return Empty(), nil
	}
	st, _, err := s.decode(cm)
	if err == nil {
		return st, nil
	}
	if got := cm.Annotations[AnnotationKeySHA]; got != s.pin {
		s.log.Warn("state_reset", "configmap", s.namespace+"/"+s.name, "stored_key_sha256", clip(got), "pinned_key_sha256", s.pin)
		return Empty(), nil
	}
	return nil, err
}

func (s *configMapStore) Peek(ctx context.Context) (*State, bool, error) {
	cm, err := s.get(ctx)
	if err != nil {
		return nil, false, err
	}
	if cm == nil {
		return Empty(), true, nil
	}
	return s.decode(cm)
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
	var last error
	for range maxSaveAttempts {
		live, err := s.get(ctx)
		if err != nil {
			return err
		}
		if live == nil {
			_, err = cms.Create(ctx, &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Name: s.name, Namespace: s.namespace, Annotations: annotations},
				Data:       data,
			}, metav1.CreateOptions{})
			if apierrors.IsAlreadyExists(err) {
				last = err
				continue
			}
			if err != nil {
				return fmt.Errorf("create configmap %s/%s: %w", s.namespace, s.name, err)
			}
			return nil
		}
		if stored, _, derr := s.decode(live); derr == nil && stored.Revision.Compare(st.Revision) > 0 {
			return fmt.Errorf("%w: stored %v, saving %v", ErrStoreNewer, stored.Revision, st.Revision)
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
		_, err = cms.Update(ctx, next, metav1.UpdateOptions{})
		if apierrors.IsConflict(err) {
			last = err
			continue
		}
		if err != nil {
			return fmt.Errorf("update configmap %s/%s: %w", s.namespace, s.name, err)
		}
		return nil
	}
	return fmt.Errorf("save configmap %s/%s: still conflicting after %d attempts: %w", s.namespace, s.name, maxSaveAttempts, last)
}
