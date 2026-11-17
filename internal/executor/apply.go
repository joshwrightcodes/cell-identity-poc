package executor

import (
	"context"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/joshwrightcodes/cell-identity-poc/internal/op"
)

const (
	demoLogName  = "demo-log"
	demoLogKey   = "log"
	demoLogLines = 500
	applyTries   = 3
)

// applyDemoAppend appends the line "<op id> <line>" to the demo log. A log that already holds a
// line that starts with the operation ID stays unchanged.
func applyDemoAppend(ctx context.Context, e *Executor, o op.Operation) error {
	args, err := op.ParseDemoAppend(o.Args)
	if err != nil {
		return err
	}
	cms := e.cfg.Client.CoreV1().ConfigMaps(e.cfg.Namespace)
	var last error
	for try := 0; try < applyTries; try++ {
		cm, err := cms.Get(ctx, demoLogName, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			cm = &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{
				Name: demoLogName, Namespace: e.cfg.Namespace, Labels: madeByLabels(),
			}}
			cm.Data = map[string]string{demoLogKey: o.ID + " " + args.Line}
			if _, err := cms.Create(ctx, cm, metav1.CreateOptions{}); err != nil {
				last = err
				continue
			}
			return nil
		}
		if err != nil {
			return fmt.Errorf("read %s: %w", demoLogName, err)
		}
		var lines []string
		if log := cm.Data[demoLogKey]; log != "" {
			lines = strings.Split(log, "\n")
		}
		for _, l := range lines {
			if strings.HasPrefix(l, o.ID+" ") {
				return nil
			}
		}
		lines = append(lines, o.ID+" "+args.Line)
		if len(lines) > demoLogLines {
			lines = lines[len(lines)-demoLogLines:]
		}
		if cm.Data == nil {
			cm.Data = map[string]string{}
		}
		cm.Data[demoLogKey] = strings.Join(lines, "\n")
		if cm.Labels == nil {
			cm.Labels = map[string]string{}
		}
		for k, v := range madeByLabels() {
			cm.Labels[k] = v
		}
		if _, err := cms.Update(ctx, cm, metav1.UpdateOptions{}); err != nil {
			last = err
			if apierrors.IsConflict(err) {
				continue
			}
			return fmt.Errorf("update %s: %w", demoLogName, err)
		}
		return nil
	}
	return fmt.Errorf("write %s after %d tries: %w", demoLogName, applyTries, last)
}
