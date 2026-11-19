package bundleapply

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/joshwrightcodes/cell-identity-poc/internal/bundle"
	"github.com/joshwrightcodes/cell-identity-poc/internal/ocistore"
)

// The values of RefillResult.Outcome.
const (
	RefillIntact   = "intact"
	RefillRefilled = "refilled"
	RefillSkipped  = "skipped"
	RefillFailed   = "failed"
)

// refillTimeout bounds one refill, including the read of every component from the mirror.
const refillTimeout = 5 * time.Minute

// RefillResult is the result of one Refill. Pushed counts the artifacts that Refill wrote, the
// components and the root. Root is the digest of the root that Refill checked.
type RefillResult struct {
	Outcome string
	Pushed  int
	Root    string
}

// Refill restores a bundle store that lost its content. It takes the root of the state, which is
// the root of the healthy set, or good[0] while another set is in flight or rolled back, and it
// does nothing for a bootstrap state, which has no signed root.
//
// The store proxy refuses every read of the writer, so the probe is a write: the registry accepts
// the manifest of the root by digest only when every blob that it names is present. A refusal for
// a missing blob starts the refill. Refill reads the components and the root from the mirror by
// the digests of the state, never by tag, and checks each one against its digest before it writes
// anything. It writes blobs and component manifests first and the root last, and then moves the tag
// current and asks for a hard refresh of root. Refill never deletes. It takes the same lock as
// Apply and skips when Apply holds it.
func (a *Applier) Refill(ctx context.Context) (RefillResult, error) {
	res, reason, err := a.refill(ctx)
	attrs := []attribute.KeyValue{attribute.String("outcome", res.Outcome)}
	a.tel.refills.Add(context.WithoutCancel(ctx), 1, metric.WithAttributes(attrs...))
	switch {
	case err != nil:
		a.log.Warn("store_refill_failed", "root", res.Root, "error", err)
	case res.Outcome == RefillRefilled:
		a.log.Info("store_refilled", "root", res.Root, "pushed", res.Pushed)
	case res.Outcome == RefillSkipped:
		a.log.Debug("store_refill_skipped", "reason", reason)
	}
	return res, err
}

func (a *Applier) refill(ctx context.Context) (RefillResult, string, error) {
	if !a.running.TryLock() {
		return RefillResult{Outcome: RefillSkipped}, "lock_held", nil
	}
	defer a.running.Unlock()
	st, _, err := a.cfg.State.Read(ctx)
	if err != nil {
		return RefillResult{Outcome: RefillFailed}, "", err
	}
	if st.Holder != "" && st.Holder != a.cfg.Holder && a.cfg.Now().Before(st.Until) {
		return RefillResult{Outcome: RefillSkipped}, "lock_held", nil
	}
	if st.Source != sourceSigned {
		return RefillResult{Outcome: RefillSkipped}, "bootstrap", nil
	}
	root, comps := st.Root, st.Components
	if st.State != stateHealthy {
		if len(st.Good) == 0 {
			return RefillResult{Outcome: RefillSkipped}, "no_good_root", nil
		}
		root, comps = st.Good[0].Root, st.Good[0].Components
	}
	res := RefillResult{Outcome: RefillFailed, Root: root.Digest}
	if root.Digest == "" || len(root.Manifest) == 0 {
		return RefillResult{Outcome: RefillSkipped}, "no_root", nil
	}
	if got := sha256Digest(root.Manifest); got != root.Digest {
		return res, "", fmt.Errorf("the state holds a root manifest that is %s, not %s", got, root.Digest)
	}

	ctx, cancel := context.WithTimeout(ctx, refillTimeout)
	defer cancel()
	store := a.cfg.Store
	if _, err := store.PushManifest(ctx, repoRoot, "", bundle.MediaTypeManifest, root.Manifest); err == nil {
		res.Outcome = RefillIntact
		return res, "", nil
	} else if !errors.Is(err, ocistore.ErrBlobUnknown) {
		return res, "", fmt.Errorf("probe the store with the root manifest: %w", err)
	}

	arts, err := a.refillRead(ctx, root, comps)
	if err != nil {
		return res, "", err
	}
	for _, name := range slices.Sorted(maps.Keys(comps)) {
		if err := pushArtifact(ctx, store, "bundles/"+name, arts[name]); err != nil {
			return res, "", fmt.Errorf("refill component %s: %w", name, err)
		}
		res.Pushed++
	}
	if err := pushArtifact(ctx, store, repoRoot, arts[""]); err != nil {
		return res, "", fmt.Errorf("refill root: %w", err)
	}
	res.Pushed++
	if _, err := store.PushManifest(ctx, repoRoot, tagCurrent, bundle.MediaTypeManifest, root.Manifest); err != nil {
		return res, "", fmt.Errorf("move the tag %s: %w", tagCurrent, err)
	}
	a.refresh(ctx)
	res.Outcome = RefillRefilled
	return res, "", nil
}

// refillRead reads the components and the root from the mirror by digest. It returns them by
// component name, with the root under the empty name. Nothing is written before every artifact
// has been read and checked.
func (a *Applier) refillRead(ctx context.Context, root Root, comps map[string]string) (map[string]bundle.Artifact, error) {
	arts := map[string]bundle.Artifact{}
	total := 0
	read := func(name, repo, digest string) error {
		art, err := ocistore.Fetch(ctx, a.cfg.Mirror, repo, digest)
		if err != nil {
			return fmt.Errorf("read %s from the mirror: %w", repo, err)
		}
		if art.Digest != digest {
			return fmt.Errorf("%w: %s is %s, not %s", ocistore.ErrDigestMismatch, repo, art.Digest, digest)
		}
		if total += len(art.Layer); total > a.maxSetBytes {
			return fmt.Errorf("%w: the refill holds more than %d layer bytes", ocistore.ErrTooLarge, a.maxSetBytes)
		}
		arts[name] = art
		return nil
	}
	for _, name := range slices.Sorted(maps.Keys(comps)) {
		if err := read(name, "bundles/"+a.cfg.Target+"/"+name, comps[name]); err != nil {
			return nil, err
		}
	}
	if err := read("", "bundles/"+a.cfg.Target+"/root", root.Digest); err != nil {
		return nil, err
	}
	return arts, nil
}

// RunRefill calls Refill at once and then every interval, until ctx ends. A failure is logged and
// tried again at the next tick. An interval of zero or less runs nothing.
func (a *Applier) RunRefill(ctx context.Context, every time.Duration) {
	if every <= 0 {
		return
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		_, _ = a.Refill(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
