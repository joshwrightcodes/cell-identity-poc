package envd

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/joshwrightcodes/cell-identity-poc/internal/lograte"
	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmtapi"
	"github.com/joshwrightcodes/cell-identity-poc/internal/spec"
)

const (
	// LabelMadeBy marks an object that a process of this PoC wrote at runtime.
	LabelMadeBy = "poc.internal/made-by"
	// MadeByEnvd is the value of LabelMadeBy on the hints ConfigMap.
	MadeByEnvd = "envd"

	maxHintValue = 256
	maxHints     = 64
)

// HintSource gives envd the key hints that the plugin of the SPIRE server wrote.
type HintSource interface {
	// New returns the hints that are newer than the last forwarded hint of their cell.
	New(ctx context.Context) ([]mgmtapi.KeyHint, error)
	// Forwarded raises the mark of each cell to the time of its hint. envd calls it only after a
	// status report that carried the hints succeeded.
	Forwarded(h []mgmtapi.KeyHint)
}

type configMapHints struct {
	c         kubernetes.Interface
	namespace string
	name      string
	log       *slog.Logger
	logs      *lograte.Limiter

	mu    sync.Mutex
	marks map[string]time.Time
}

// NewConfigMapHints returns a HintSource on the ConfigMap namespace/name. New creates the ConfigMap
// empty, with label poc.internal/made-by=envd, when it is absent. Keys that are not DNS labels and
// values that do not decode are ignored.
func NewConfigMapHints(c kubernetes.Interface, namespace, name string, log *slog.Logger) HintSource {
	if log == nil {
		log = slog.Default()
	}
	return &configMapHints{c: c, namespace: namespace, name: name, log: log,
		logs: lograte.New(RefusalLogWindow, maxLogKeys, time.Now), marks: map[string]time.Time{}}
}

func (h *configMapHints) New(ctx context.Context) ([]mgmtapi.KeyHint, error) {
	cms := h.c.CoreV1().ConfigMaps(h.namespace)
	cm, err := cms.Get(ctx, h.name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		cm, err = cms.Create(ctx, &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{
			Name: h.name, Namespace: h.namespace, Labels: map[string]string{LabelMadeBy: MadeByEnvd}}}, metav1.CreateOptions{})
		if apierrors.IsAlreadyExists(err) {
			cm, err = cms.Get(ctx, h.name, metav1.GetOptions{})
		}
	}
	if err != nil {
		return nil, fmt.Errorf("hints configmap %s/%s: %w", h.namespace, h.name, err)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []mgmtapi.KeyHint
	for cell, raw := range cm.Data {
		at, ok := decodeHint(cell, raw)
		if !ok {
			h.skip(ctx, cell)
			continue
		}
		if at.After(h.marks[cell]) {
			out = append(out, mgmtapi.KeyHint{Cell: cell, At: at})
		}
	}
	slices.SortFunc(out, func(a, b mgmtapi.KeyHint) int { return strings.Compare(a.Cell, b.Cell) })
	return out, nil
}

func (h *configMapHints) skip(ctx context.Context, cell string) {
	_, ok, suppressed, _ := h.logs.Allow("hint/" + clip(cell))
	if ok {
		h.log.WarnContext(ctx, "hint ignored", "key", clip(cell), "suppressed", suppressed)
	}
}

func (h *configMapHints) Forwarded(hints []mgmtapi.KeyHint) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, k := range hints {
		if k.At.After(h.marks[k.Cell]) {
			h.marks[k.Cell] = k.At
		}
	}
}

// decodeHint reads the value of one key. The key must be a DNS label and the value must hold a
// non-zero "at".
func decodeHint(cell, raw string) (time.Time, bool) {
	if !spec.ValidName(cell) || len(raw) > maxHintValue {
		return time.Time{}, false
	}
	var v struct {
		At time.Time `json:"at"`
	}
	if err := json.Unmarshal([]byte(raw), &v); err != nil || v.At.IsZero() {
		return time.Time{}, false
	}
	return v.At, true
}

// pendingHints merges the hints of the source with those of the gateway status. It keeps the newest
// hint of each cell and drops every hint that a successful report has already carried.
func (p *Puller) pendingHints(ctx context.Context, gw *mgmtapi.GatewayStatus) []mgmtapi.KeyHint {
	var all []mgmtapi.KeyHint
	if p.cfg.Hints != nil {
		h, err := p.cfg.Hints.New(ctx)
		if err != nil {
			p.logLimited(ctx, "hints read failed", "hints", "error", clip(err.Error()))
		}
		all = append(all, h...)
	}
	if gw != nil {
		all = append(all, gw.KeyHints...)
	}
	newest := map[string]time.Time{}
	for _, k := range all {
		if !spec.ValidName(k.Cell) || k.At.IsZero() || !k.At.After(p.hintMarks[k.Cell]) {
			continue
		}
		if k.At.After(newest[k.Cell]) {
			newest[k.Cell] = k.At
		}
	}
	var out []mgmtapi.KeyHint
	for cell, at := range newest {
		out = append(out, mgmtapi.KeyHint{Cell: cell, At: at})
	}
	slices.SortFunc(out, func(a, b mgmtapi.KeyHint) int { return strings.Compare(a.Cell, b.Cell) })
	if len(out) > maxHints {
		out = out[:maxHints]
	}
	return out
}

// forwarded raises the marks after a status report that carried hints succeeded.
func (p *Puller) forwarded(hints []mgmtapi.KeyHint) {
	for _, k := range hints {
		if k.At.After(p.hintMarks[k.Cell]) {
			p.hintMarks[k.Cell] = k.At
		}
	}
	if p.cfg.Hints != nil && len(hints) > 0 {
		p.cfg.Hints.Forwarded(hints)
	}
}
