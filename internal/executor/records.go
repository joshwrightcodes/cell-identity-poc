package executor

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/joshwrightcodes/cell-identity-poc/internal/op"
)

// The states of an operation record.
const (
	stateClaimed  = "claimed"
	stateApplied  = "applied"
	stateReported = "reported"
)

const (
	recordPrefix = "op-"
	recordKey    = "record.json"
	labelRecord  = "poc.internal/op-record"
	labelMadeBy  = "poc.internal/made-by"
	madeBy       = "celld"
	updateTries  = 3
)

type storedRecord struct {
	State          string     `json:"state"`
	Fence          op.Fence   `json:"fence"`
	Holder         string     `json:"holder"`
	LeaseUntil     time.Time  `json:"leaseUntil"`
	EnvelopeSHA256 string     `json:"envelopeSHA256"`
	Result         *op.Result `json:"result,omitempty"`
	UpdatedAt      time.Time  `json:"updatedAt"`
}

func madeByLabels() map[string]string { return map[string]string{labelMadeBy: madeBy} }

func recordLabels() map[string]string {
	return map[string]string{labelRecord: "true", labelMadeBy: madeBy}
}

func decodeRecord(cm *corev1.ConfigMap) (storedRecord, error) {
	var r storedRecord
	if err := json.Unmarshal([]byte(cm.Data[recordKey]), &r); err != nil {
		return storedRecord{}, fmt.Errorf("record %s: %w", cm.Name, err)
	}
	return r, nil
}

func encodeRecord(r storedRecord) string {
	b, _ := json.Marshal(r)
	return string(b)
}

// claim writes the record of the operation for this pod. It returns nil when this pod holds the
// claim, and otherwise the result to return.
func (e *Executor) claim(ctx context.Context, o op.Operation, f op.Fence, sha string) *op.Result {
	lost := func(reason string) *op.Result {
		r := e.result(o.ID, op.OutcomeLeaseLost, reason, f, sha)
		return &r
	}
	cms := e.cfg.Client.CoreV1().ConfigMaps(e.cfg.Namespace)
	name := recordPrefix + o.ID
	now := e.cfg.Now()
	n, err := e.Count(ctx)
	if err != nil {
		return lost(reasonStore)
	}
	var existing *corev1.ConfigMap
	if n >= maxRecords {
		existing, err = cms.Get(ctx, name, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			r := e.result(o.ID, op.OutcomeStoreFull, op.ReasonStoreFull, f, sha)
			return &r
		}
		if err != nil {
			return lost(reasonStore)
		}
	} else {
		rec := storedRecord{
			State: stateClaimed, Fence: f, Holder: e.cfg.PodUID, LeaseUntil: now.Add(leaseTerm),
			EnvelopeSHA256: sha, UpdatedAt: now,
		}
		cm := &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: e.cfg.Namespace, Labels: recordLabels()},
			Data:       map[string]string{recordKey: encodeRecord(rec)},
		}
		_, err := cms.Create(ctx, cm, metav1.CreateOptions{})
		if err == nil {
			return nil
		}
		if !apierrors.IsAlreadyExists(err) {
			return lost(reasonStore)
		}
		existing, err = cms.Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return lost(reasonStore)
		}
	}
	rec, err := decodeRecord(existing)
	if err != nil {
		return lost(reasonStore)
	}
	switch rec.State {
	case stateApplied, stateReported:
		var r op.Result
		if rec.Result != nil {
			r = *rec.Result
		}
		r.OpID = o.ID
		r.Outcome = op.OutcomeAlreadyApplied
		r.Reason = ""
		r.EnvelopeSHA256 = sha
		return &r
	case stateClaimed:
		if f.Compare(rec.Fence) > 0 && now.After(rec.LeaseUntil) {
			rec.Fence, rec.Holder, rec.LeaseUntil = f, e.cfg.PodUID, now.Add(leaseTerm)
			rec.EnvelopeSHA256, rec.UpdatedAt = sha, now
			existing.Data[recordKey] = encodeRecord(rec)
			if _, err := cms.Update(ctx, existing, metav1.UpdateOptions{}); err != nil {
				return lost(op.ReasonLeaseLost)
			}
			return nil
		}
	}
	return lost(op.ReasonLeaseLost)
}

// holds reads the record and reports whether this pod holds the claim of fence f.
func (e *Executor) holds(ctx context.Context, id string, f op.Fence) (*corev1.ConfigMap, bool) {
	cm, err := e.cfg.Client.CoreV1().ConfigMaps(e.cfg.Namespace).Get(ctx, recordPrefix+id, metav1.GetOptions{})
	if err != nil {
		return nil, false
	}
	rec, err := decodeRecord(cm)
	if err != nil {
		return nil, false
	}
	return cm, rec.State == stateClaimed && rec.Holder == e.cfg.PodUID && rec.Fence == f
}

// renewLease extends the lease every renewEvery until the returned function is called. The
// function returns after the last renewal ends.
func (e *Executor) renewLease(ctx context.Context, id string, f op.Fence) (stop func()) {
	rctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		t := time.NewTicker(e.renewEvery)
		defer t.Stop()
		for {
			select {
			case <-rctx.Done():
				return
			case <-t.C:
				cm, ok := e.holds(rctx, id, f)
				if !ok {
					continue
				}
				rec, _ := decodeRecord(cm)
				now := e.cfg.Now()
				rec.LeaseUntil, rec.UpdatedAt = now.Add(leaseTerm), now
				cm.Data[recordKey] = encodeRecord(rec)
				_, _ = e.cfg.Client.CoreV1().ConfigMaps(e.cfg.Namespace).Update(rctx, cm, metav1.UpdateOptions{})
			}
		}
	}()
	return func() { cancel(); <-done }
}

// finish stores the applied result when this pod still holds the claim.
func (e *Executor) finish(ctx context.Context, id string, f op.Fence, res op.Result) bool {
	cm, ok := e.holds(ctx, id, f)
	if !ok {
		return false
	}
	rec, _ := decodeRecord(cm)
	rec.State, rec.Result, rec.UpdatedAt = stateApplied, &res, e.cfg.Now()
	cm.Data[recordKey] = encodeRecord(rec)
	_, err := e.cfg.Client.CoreV1().ConfigMaps(e.cfg.Namespace).Update(ctx, cm, metav1.UpdateOptions{})
	return err == nil
}

func (e *Executor) list(ctx context.Context) ([]corev1.ConfigMap, error) {
	l, err := e.cfg.Client.CoreV1().ConfigMaps(e.cfg.Namespace).List(ctx,
		metav1.ListOptions{LabelSelector: labelRecord + "=true"})
	if err != nil {
		return nil, err
	}
	return l.Items, nil
}

// Count returns the number of operation records.
func (e *Executor) Count(ctx context.Context) (int, error) {
	items, err := e.list(ctx)
	return len(items), err
}

// MarkReported marks the applied record of an operation as reported. A record in another state is
// left as it is.
func (e *Executor) MarkReported(ctx context.Context, id string) error {
	cms := e.cfg.Client.CoreV1().ConfigMaps(e.cfg.Namespace)
	var last error
	for try := 0; try < updateTries; try++ {
		cm, err := cms.Get(ctx, recordPrefix+id, metav1.GetOptions{})
		if err != nil {
			return err
		}
		rec, err := decodeRecord(cm)
		if err != nil {
			return err
		}
		if rec.State != stateApplied {
			return nil
		}
		rec.State, rec.UpdatedAt = stateReported, e.cfg.Now()
		cm.Data[recordKey] = encodeRecord(rec)
		if _, last = cms.Update(ctx, cm, metav1.UpdateOptions{}); last == nil {
			return nil
		} else if !apierrors.IsConflict(last) {
			return last
		}
	}
	return last
}

// Pending returns the results of applied records that are not reported, oldest first.
func (e *Executor) Pending(ctx context.Context) ([]op.Result, error) {
	items, err := e.list(ctx)
	if err != nil {
		return nil, err
	}
	var out []op.Result
	for i := range items {
		rec, err := decodeRecord(&items[i])
		if err != nil || rec.State != stateApplied || rec.Result == nil {
			continue
		}
		out = append(out, *rec.Result)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].At.Before(out[j].At) })
	return out, nil
}

// GC deletes the reported records that are older than op.RecordRetention.
func (e *Executor) GC(ctx context.Context) error {
	items, err := e.list(ctx)
	if err != nil {
		return err
	}
	cutoff := e.cfg.Now().Add(-op.RecordRetention)
	cms := e.cfg.Client.CoreV1().ConfigMaps(e.cfg.Namespace)
	for i := range items {
		rec, err := decodeRecord(&items[i])
		if err != nil || rec.State != stateReported || !rec.UpdatedAt.Before(cutoff) {
			continue
		}
		if err := cms.Delete(ctx, items[i].Name, metav1.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
			return err
		}
	}
	return nil
}
