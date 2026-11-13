package clusterjwt

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/hashicorp/go-hclog"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"

	"github.com/joshwrightcodes/cell-identity-poc/internal/lograte"
)

const (
	defaultHintInterval = "60s"
	minHintInterval     = 10 * time.Second
	// hintGap is the shortest time between two hint writes of any cells.
	hintGap       = time.Second
	hintQueueSize = 16
	hintWriteTime = 10 * time.Second
	hintLogWindow = time.Minute
)

var kubeNameRE = regexp.MustCompile(`^[a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?$`)

// HintWriter tells the management plane that a cell presented a key ID that its record does not hold.
type HintWriter interface {
	Hint(ctx context.Context, cell string, at time.Time) error
}

// configMapHints writes hints into the data of one existing ConfigMap.
type configMapHints struct {
	cms       corev1client.ConfigMapsGetter
	namespace string
	name      string
	log       hclog.Logger
	now       func() time.Time
	lim       *lograte.Limiter
}

func newConfigMapHints(c corev1client.ConfigMapsGetter, namespace, name string, log hclog.Logger) HintWriter {
	h := &configMapHints{cms: c, namespace: namespace, name: name, log: log, now: time.Now}
	h.lim = lograte.New(hintLogWindow, 4, func() time.Time { return h.now() })
	return h
}

// hintValue is the value that a hint stores under the cell name.
type hintValue struct {
	At string `json:"at"`
}

// Hint sends one JSON merge patch. It never creates the ConfigMap.
func (h *configMapHints) Hint(ctx context.Context, cell string, at time.Time) error {
	value, err := json.Marshal(hintValue{At: at.UTC().Format(time.RFC3339)})
	if err != nil {
		return err
	}
	patch, err := json.Marshal(map[string]map[string]string{"data": {cell: string(value)}})
	if err != nil {
		return err
	}
	_, err = h.cms.ConfigMaps(h.namespace).Patch(ctx, h.name, types.MergePatchType, patch, metav1.PatchOptions{})
	if apierrors.IsNotFound(err) {
		if _, ok, _, _ := h.lim.Allow("missing"); ok {
			h.log.Warn("hints_configmap_missing", "namespace", h.namespace, "name", h.name)
		}
	}
	return err
}

// parseHintConfigMap splits "<namespace>/<name>". An empty value means hints are off.
func parseHintConfigMap(s string) (namespace, name string, err error) {
	if s == "" {
		return "", "", nil
	}
	namespace, name, ok := strings.Cut(s, "/")
	if !ok || !kubeNameRE.MatchString(namespace) || !kubeNameRE.MatchString(name) {
		return "", "", errors.New("hint_configmap must be empty or <namespace>/<name>")
	}
	return namespace, name, nil
}

func parseHintInterval(s string) (time.Duration, error) {
	d, err := time.ParseDuration(s)
	if err != nil || d < minHintInterval {
		return 0, fmt.Errorf("hint_min_interval must be a duration of at least %s", minHintInterval)
	}
	return d, nil
}

// defaultHintWriter builds the writer for a configured ConfigMap from the in-cluster credentials.
func (p *Plugin) defaultHintWriter(cm string) (HintWriter, error) {
	namespace, name, err := parseHintConfigMap(cm)
	if err != nil {
		return nil, err
	}
	c, err := inClusterClient()
	if err != nil {
		return nil, err
	}
	getter, ok := c.(corev1client.ConfigMapsGetter)
	if !ok {
		return nil, errors.New("the Kubernetes client has no ConfigMap access")
	}
	return newConfigMapHints(getter, namespace, name, p.log), nil
}

// startHints starts the writing goroutine once, at the first Configure that turns hints on.
func (p *Plugin) startHints(st *state) {
	if st.hintCM == "" {
		return
	}
	p.hintMu.Lock()
	defer p.hintMu.Unlock()
	select {
	case <-p.done:
		return
	default:
	}
	if p.hintStarted {
		return
	}
	p.hintStarted = true
	go p.hintLoop()
}

// queueHint hands a cell to the writing goroutine without waiting.
func (p *Plugin) queueHint(st *state, cell string) {
	if st.hintCM == "" {
		return
	}
	select {
	case p.hintCh <- cell:
	default:
		p.hintLogged("hint_dropped", "hint dropped, the queue is full", "cell", cell)
	}
}

func (p *Plugin) hintLogged(key, msg string, kv ...any) {
	if _, ok, _, _ := p.hintLim.Allow(key); ok {
		p.log.Warn(msg, clip(kv)...)
	}
}

func (p *Plugin) hintLoop() {
	var (
		writer   HintWriter
		writerCM string
		last     = map[string]time.Time{}
		lastAny  time.Time
	)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		select {
		case <-p.done:
			cancel()
		case <-ctx.Done():
		}
	}()
	for {
		var cell string
		select {
		case cell = <-p.hintCh:
		case <-p.stop:
			return
		case <-p.done:
			return
		}
		st := p.st.Load()
		if st != nil && st.hintCM != "" {
			now := p.now()
			switch {
			case now.Sub(lastAny) < hintGap, now.Sub(last[cell]) < st.hintEvery:
			default:
				if writer == nil || writerCM != st.hintCM {
					w, err := p.newHints(st.hintCM)
					if err != nil {
						p.hintLogged("hint_client", "hint client unavailable", "error", err.Error())
						writer = nil
					} else {
						writer, writerCM = w, st.hintCM
					}
				}
				if writer != nil {
					last[cell], lastAny = now, now
					wctx, wcancel := context.WithTimeout(ctx, hintWriteTime)
					if err := writer.Hint(wctx, cell, now); err != nil && !apierrors.IsNotFound(err) {
						p.hintLogged("hint_write", "hint write failed", "cell", cell, "error", err.Error())
					}
					wcancel()
				}
			}
		}
		if p.afterHint != nil {
			p.afterHint()
		}
	}
}
