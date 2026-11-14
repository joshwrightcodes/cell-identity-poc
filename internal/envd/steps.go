package envd

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"slices"
	"strconv"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/joshwrightcodes/cell-identity-poc/internal/lograte"
	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmtapi"
	"github.com/joshwrightcodes/cell-identity-poc/internal/spec"
	"github.com/joshwrightcodes/cell-identity-poc/internal/step"
)

const (
	// MaxStepBytes is the largest step envelope that Accept stores. The host service takes no more.
	MaxStepBytes = 16 << 10
	// StepSuffix ends the key of each step envelope in the steps ConfigMap.
	StepSuffix = ".step.json"
	// StatusKey is the key of the step status in the status ConfigMap.
	StatusKey = "status.json"
	// MaxStepStatuses is the most step statuses that envd forwards in one report.
	MaxStepStatuses = 32
	// MaxStatusBytes is the largest status ConfigMap that envd reads.
	MaxStatusBytes = 64 << 10

	// fieldManagerEnvd is the field manager of every write of envd to a ConfigMap of this PoC.
	fieldManagerEnvd = "envd"
)

// checkSteps verifies the step envelopes of b against the step index of s and returns copies of them.
func checkSteps(s spec.Spec, b mgmtapi.SpecBundle, env string, keys []ed25519.PublicKey) (map[string][]byte, error) {
	refuse := func(reason, cell, format string, args ...any) error {
		return &Refused{Reason: reason, Cell: clip(cell), Revision: s.Revision, Detail: clip(fmt.Sprintf(format, args...))}
	}
	steps := make(map[string][]byte, len(s.Steps))
	for _, e := range s.Steps {
		raw, ok := b.Steps[e.Name]
		if !ok {
			return nil, refuse(mgmtapi.ReasonStepInvalid, e.Name, "bundle has no step envelope")
		}
		if len(raw) > MaxStepBytes {
			return nil, refuse(mgmtapi.ReasonStepInvalid, e.Name, "step envelope has %d bytes, the limit is %d", len(raw), MaxStepBytes)
		}
		st, payload, err := step.Verify(raw, keys)
		if err != nil {
			return nil, refuse(mgmtapi.ReasonStepInvalid, e.Name, "%v", err)
		}
		switch {
		case st.ID != e.StepID:
			return nil, refuse(mgmtapi.ReasonStepInvalid, e.Name, "step id %q, the spec indexes %q", st.ID, e.StepID)
		case st.Cell != e.Name:
			return nil, refuse(mgmtapi.ReasonStepInvalid, e.Name, "step is for cell %q", st.Cell)
		case st.Env != env:
			return nil, refuse(mgmtapi.ReasonStepInvalid, e.Name, "step env %q, want %q", st.Env, env)
		case step.PayloadSHA256(payload) != e.StepSHA256:
			return nil, refuse(mgmtapi.ReasonStepInvalid, e.Name, "step digest differs from the spec index")
		}
		steps[e.Name] = slices.Clone(raw)
	}
	for name := range b.Steps {
		if _, ok := steps[name]; !ok {
			return nil, refuse(mgmtapi.ReasonStepUnindexed, name, "bundle has a step envelope that the spec does not index")
		}
	}
	return steps, nil
}

// stepsDigest identifies what the steps ConfigMap holds for st: the spec, and the name and digest of
// each step envelope.
func stepsDigest(st *State) string {
	h := sha256.New()
	h.Write([]byte(st.SpecSHA256))
	names := make([]string, 0, len(st.Steps))
	for name := range st.Steps {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		sum := sha256.Sum256(st.Steps[name])
		fmt.Fprintf(h, "\n%s %x", name, sum)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// StepStore keeps the signed spec and step envelopes for the cell controller.
type StepStore interface {
	// Save writes the spec envelope of s and its step envelopes as the whole content of the store.
	Save(ctx context.Context, s *State) error
}

type configMapSteps struct {
	c         kubernetes.Interface
	namespace string
	name      string
	keySHA    string
	log       *slog.Logger
}

// NewStepStore returns a StepStore on the ConfigMap namespace/name. It creates the ConfigMap when it
// is absent, and an update replaces the whole data. The key annotation carries keySHA256.
func NewStepStore(c kubernetes.Interface, namespace, name, keySHA256 string, log *slog.Logger) StepStore {
	if log == nil {
		log = slog.Default()
	}
	return &configMapSteps{c: c, namespace: namespace, name: name, keySHA: keySHA256, log: log}
}

func (s *configMapSteps) Save(ctx context.Context, st *State) error {
	if len(st.SpecEnvelope) == 0 {
		return fmt.Errorf("refusing to write steps for a state with no spec")
	}
	data := make(map[string]string, len(st.Steps)+1)
	data[SpecKey] = string(st.SpecEnvelope)
	for cell, raw := range st.Steps {
		data[cell+StepSuffix] = string(raw)
	}
	annotations := map[string]string{
		AnnotationEpoch:   strconv.FormatUint(st.Revision.Epoch, 10),
		AnnotationCounter: strconv.FormatUint(st.Revision.Counter, 10),
		AnnotationKeySHA:  s.keySHA,
	}
	cms := s.c.CoreV1().ConfigMaps(s.namespace)
	var last error
	for range maxSaveAttempts {
		live, err := cms.Get(ctx, s.name, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			_, err = cms.Create(ctx, &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Name: s.name, Namespace: s.namespace, Annotations: annotations,
					Labels: map[string]string{labelMadeBy: madeByEnvd}},
				Data: data,
			}, metav1.CreateOptions{FieldManager: fieldManagerEnvd})
			if apierrors.IsAlreadyExists(err) {
				last = err
				continue
			}
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
		if next.Labels == nil {
			next.Labels = map[string]string{}
		}
		next.Labels[labelMadeBy] = madeByEnvd
		_, err = cms.Update(ctx, next, metav1.UpdateOptions{FieldManager: fieldManagerEnvd})
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

// StepStatusSource gives envd the step status that the cell controller wrote.
type StepStatusSource interface {
	// Read returns the valid step statuses and the time of the last write. It returns none when the
	// source is absent or does not decode.
	Read(ctx context.Context) ([]mgmtapi.StepStatus, time.Time, error)
}

type configMapStepStatus struct {
	c         kubernetes.Interface
	namespace string
	name      string
	log       *slog.Logger
	logs      *lograte.Limiter
}

// NewConfigMapStepStatus returns a StepStatusSource on the ConfigMap namespace/name. A missing
// ConfigMap, one above 64 KiB and a body that does not decode strictly give no entries. Read keeps
// only the entries that pass mgmtapi.ValidStepStatus, at most 32. It logs one line for each ignored
// ConfigMap, at most once in each window, to the first logger or to the default logger.
func NewConfigMapStepStatus(c kubernetes.Interface, namespace, name string, log ...*slog.Logger) StepStatusSource {
	l := slog.Default()
	if len(log) > 0 && log[0] != nil {
		l = log[0]
	}
	return &configMapStepStatus{c: c, namespace: namespace, name: name, log: l,
		logs: lograte.New(RefusalLogWindow, maxLogKeys, time.Now)}
}

func (s *configMapStepStatus) skip(ctx context.Context, why string) {
	if _, ok, suppressed, _ := s.logs.Allow("step-status"); ok {
		s.log.WarnContext(ctx, "step status ignored", "configmap", s.namespace+"/"+s.name, "why", why, "suppressed", suppressed)
	}
}

func (s *configMapStepStatus) Read(ctx context.Context) ([]mgmtapi.StepStatus, time.Time, error) {
	cm, err := s.c.CoreV1().ConfigMaps(s.namespace).Get(ctx, s.name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil, time.Time{}, nil
	}
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("step status configmap %s/%s: %w", s.namespace, s.name, err)
	}
	size := len(cm.BinaryData)
	for k, v := range cm.Data {
		size += len(k) + len(v)
	}
	if size > MaxStatusBytes {
		s.skip(ctx, "configmap is too large")
		return nil, time.Time{}, nil
	}
	raw, ok := cm.Data[StatusKey]
	if !ok {
		return nil, time.Time{}, nil
	}
	var body struct {
		At    time.Time            `json:"at"`
		Steps []mgmtapi.StepStatus `json:"steps"`
	}
	dec := json.NewDecoder(bytes.NewReader([]byte(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil || dec.More() {
		s.skip(ctx, "body does not decode")
		return nil, time.Time{}, nil
	}
	var out []mgmtapi.StepStatus
	for _, st := range body.Steps {
		if mgmtapi.ValidStepStatus(st) {
			out = append(out, st)
		}
	}
	if len(out) > MaxStepStatuses {
		out = out[:MaxStepStatuses]
	}
	return out, body.At, nil
}
