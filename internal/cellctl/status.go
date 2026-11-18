package cellctl

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmtapi"
)

const (
	// StatusKey is the key of the step status in the status ConfigMap.
	StatusKey = "status.json"
	// MaxStatuses is the most step statuses in one report.
	MaxStatuses = 32

	fieldManager = "cell-controller"
	labelMadeBy  = "poc.internal/made-by"
	maxAttempts  = 5
)

// statusDoc is the whole content of key status.json.
type statusDoc struct {
	At    time.Time            `json:"at"`
	Steps []mgmtapi.StepStatus `json:"steps"`
}

// encodeSteps returns the JSON of the steps list: never null.
func encodeSteps(steps []mgmtapi.StepStatus) ([]byte, error) {
	if steps == nil {
		steps = []mgmtapi.StepStatus{}
	}
	return json.Marshal(steps)
}

// statusStore writes the step status ConfigMap.
type statusStore struct {
	c         kubernetes.Interface
	namespace string
	name      string
}

// write stores {"at": at, "steps": steps} as the only key of the ConfigMap, which it creates when
// it is absent. The writes carry the field manager cell-controller and the made-by label.
func (s *statusStore) write(ctx context.Context, at time.Time, steps []mgmtapi.StepStatus) error {
	if steps == nil {
		steps = []mgmtapi.StepStatus{}
	}
	body, err := json.Marshal(statusDoc{At: at.UTC(), Steps: steps})
	if err != nil {
		return fmt.Errorf("encode status: %w", err)
	}
	data := map[string]string{StatusKey: string(body)}
	cms := s.c.CoreV1().ConfigMaps(s.namespace)
	var last error
	for range maxAttempts {
		live, err := cms.Get(ctx, s.name, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			_, err = cms.Create(ctx, &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Name: s.name, Namespace: s.namespace, Labels: map[string]string{labelMadeBy: fieldManager}},
				Data:       data,
			}, metav1.CreateOptions{FieldManager: fieldManager})
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
		next.Data, next.BinaryData = data, nil
		if next.Labels == nil {
			next.Labels = map[string]string{}
		}
		next.Labels[labelMadeBy] = fieldManager
		_, err = cms.Update(ctx, next, metav1.UpdateOptions{FieldManager: fieldManager})
		if apierrors.IsConflict(err) {
			last = err
			continue
		}
		if err != nil {
			return fmt.Errorf("update configmap %s/%s: %w", s.namespace, s.name, err)
		}
		return nil
	}
	return fmt.Errorf("write configmap %s/%s: still conflicting after %d attempts: %w", s.namespace, s.name, maxAttempts, last)
}

// sameSteps reports whether two encoded lists are equal.
func sameSteps(a, b []byte) bool { return bytes.Equal(a, b) }
