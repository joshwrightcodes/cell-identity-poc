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
	"k8s.io/client-go/rest"

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
	// hintBuildRetry is the shortest time between two attempts to build the hint client.
	hintBuildRetry = time.Minute
)

var (
	kubeNameRE  = regexp.MustCompile(`^[a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?$`)
	kubeLabelRE = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$`)
)

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
	if !ok || !kubeLabelRE.MatchString(namespace) || !kubeNameRE.MatchString(name) {
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
	c, err := p.newConfigMaps()
	if err != nil {
		return nil, err
	}
	return newConfigMapHints(c, namespace, name, p.log), nil
}

// inClusterConfigMaps returns a ConfigMap client that uses the in-cluster credentials.
func inClusterConfigMaps() (corev1client.ConfigMapsGetter, error) {
	cfg, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("load in-cluster configuration: %w", err)
	}
	c, err := corev1client.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("create Kubernetes client: %w", err)
	}
	return c, nil
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
	if _, ok, suppressed, _ := p.hintLim.Allow(key); ok {
		if suppressed > 0 {
			kv = append(kv, "suppressed", suppressed)
		}
		p.log.Warn(msg, clip(kv)...)
	}
}

// hintLoop writes the hints. A hint that a limit holds back is kept as pending for its cell, so one
// write follows when the limits allow it, whatever the agent does next.
func (p *Plugin) hintLoop() {
	defer close(p.hintExit)
	l := &hintWork{
		p: p, last: map[string]time.Time{}, pending: map[string]bool{},
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	l.ctx = ctx
	go func() {
		select {
		case <-p.done:
			cancel()
		case <-ctx.Done():
		}
	}()
	var ticker *time.Ticker
	defer func() {
		if ticker != nil {
			ticker.Stop()
		}
	}()
	for {
		var tickC <-chan time.Time
		if len(l.pending) > 0 {
			tickC = p.hintTick
			if tickC == nil {
				if ticker == nil {
					ticker = time.NewTicker(hintGap)
				}
				tickC = ticker.C
			}
		} else if ticker != nil {
			ticker.Stop()
			ticker = nil
		}
		select {
		case cell := <-p.hintCh:
			l.handle(cell)
		case <-tickC:
			for cell := range l.pending {
				l.handle(cell)
			}
		case <-p.stop:
			return
		case <-p.done:
			return
		}
		if p.afterHint != nil {
			p.afterHint()
		}
	}
}

// hintWork is the state of the writing goroutine.
type hintWork struct {
	p         *Plugin
	ctx       context.Context
	writer    HintWriter
	writerCM  string
	nextBuild time.Time
	last      map[string]time.Time
	lastAny   time.Time
	pending   map[string]bool
}

func (l *hintWork) handle(cell string) {
	p := l.p
	st := p.st.Load()
	if st == nil || st.hintCM == "" {
		delete(l.pending, cell)
		return
	}
	now := p.now()
	if now.Sub(l.lastAny) < hintGap || now.Sub(l.last[cell]) < st.hintEvery {
		l.pending[cell] = true
		return
	}
	if l.writer == nil || l.writerCM != st.hintCM {
		l.writer = nil
		if now.Before(l.nextBuild) {
			l.pending[cell] = true
			return
		}
		w, err := p.newHints(st.hintCM)
		if err != nil {
			l.nextBuild = now.Add(hintBuildRetry)
			p.hintLogged("hint_client", "hint client unavailable", "error", err.Error())
			l.pending[cell] = true
			return
		}
		l.writer, l.writerCM = w, st.hintCM
	}
	delete(l.pending, cell)
	l.last[cell], l.lastAny = now, now
	wctx, wcancel := context.WithTimeout(l.ctx, hintWriteTime)
	defer wcancel()
	if err := l.writer.Hint(wctx, cell, now); err != nil && !apierrors.IsNotFound(err) {
		p.hintLogged("hint_write", "hint write failed", "cell", cell, "error", err.Error())
	}
}
