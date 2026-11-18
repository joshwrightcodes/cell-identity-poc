package bundleapply

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/joshwrightcodes/cell-identity-poc/internal/bundle"
	"github.com/joshwrightcodes/cell-identity-poc/internal/op"
	"github.com/joshwrightcodes/cell-identity-poc/internal/record"
)

const madeByLabel = "poc.internal/made-by"

// ErrConflict means that the state changed since it was read.
var ErrConflict = errors.New("bundle state changed since it was read")

// Root is a root bundle: its manifest digest and the manifest bytes.
type Root struct {
	Digest   string `json:"digest"`
	Manifest []byte `json:"manifest"`
}

// Good is a set that became healthy, with what a rollback to it needs.
type Good struct {
	Version       bundle.Version    `json:"version"`
	ContentSHA256 string            `json:"contentSHA256"`
	Root          Root              `json:"root"`
	Components    map[string]string `json:"components"`
	At            time.Time         `json:"at"`
}

// State is the durable state of an applier.
type State struct {
	Source        string            `json:"source"`
	Version       bundle.Version    `json:"version"`
	ContentSHA256 string            `json:"contentSHA256"`
	KeySHA256     string            `json:"keySHA256"`
	OpID          string            `json:"opId"`
	State         string            `json:"state"`
	Holder        string            `json:"holder"`
	Until         time.Time         `json:"until"`
	Root          Root              `json:"root"`
	Components    map[string]string `json:"components"`
	Checked       []string          `json:"checked"`
	CheckedBy     string            `json:"checkedBy"`
	Good          []Good            `json:"good"`
	Result        *op.Result        `json:"result,omitempty"`
}

// Store keeps the State.
type Store interface {
	Read(ctx context.Context) (State, string, error)
	Write(ctx context.Context, st State, resourceVersion string) error
}

// ConfigMapStore keeps the State in the key state.json of a ConfigMap.
type ConfigMapStore struct {
	Client          kubernetes.Interface
	Namespace, Name string
	MadeBy          string
}

const stateKey = "state.json"

// Read returns the state and its resource version. A ConfigMap that does not exist gives the empty
// state and an empty resource version.
func (s *ConfigMapStore) Read(ctx context.Context) (State, string, error) {
	cm, err := s.Client.CoreV1().ConfigMaps(s.Namespace).Get(ctx, s.Name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return State{}, "", nil
	}
	if err != nil {
		return State{}, "", fmt.Errorf("read bundle state: %w", err)
	}
	var st State
	if err := record.DecodeStrict([]byte(cm.Data[stateKey]), &st); err != nil {
		return State{}, "", fmt.Errorf("decode bundle state: %w", err)
	}
	return st, cm.ResourceVersion, nil
}

// Write stores the state. An empty resource version creates the ConfigMap, and any other value
// updates it only if it is still current. A lost race gives ErrConflict.
func (s *ConfigMapStore) Write(ctx context.Context, st State, rv string) error {
	body, err := json.Marshal(st)
	if err != nil {
		return fmt.Errorf("encode bundle state: %w", err)
	}
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: s.Namespace, Name: s.Name, ResourceVersion: rv,
			Labels: map[string]string{madeByLabel: s.MadeBy},
		},
		Data: map[string]string{stateKey: string(body)},
	}
	cms := s.Client.CoreV1().ConfigMaps(s.Namespace)
	if rv == "" {
		_, err = cms.Create(ctx, cm, metav1.CreateOptions{})
	} else {
		_, err = cms.Update(ctx, cm, metav1.UpdateOptions{})
	}
	switch {
	case apierrors.IsAlreadyExists(err), apierrors.IsConflict(err), apierrors.IsNotFound(err) && rv != "":
		return ErrConflict
	case err != nil:
		return fmt.Errorf("write bundle state: %w", err)
	}
	return nil
}
