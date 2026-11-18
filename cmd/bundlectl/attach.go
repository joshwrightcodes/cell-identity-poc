package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/opencontainers/go-digest"
	specs "github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/joshwrightcodes/cell-identity-poc/internal/bundle"
	"github.com/joshwrightcodes/cell-identity-poc/internal/ocistore"
)

// The cosign bundle travels as an OCI referrer of the root manifest, in the layout that cosign reads.
const (
	sigstoreMediaType = "application/vnd.dev.sigstore.bundle.v0.3+json"
	annContent        = "dev.sigstore.bundle.content"
	annPredicate      = "dev.sigstore.bundle.predicateType"
	maxSigstoreBundle = 64 << 10
	defaultLockWait   = lockWait(2 * time.Minute)
	lockPoll          = 50 * time.Millisecond
)

var rootDigestRE = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// lockWait is a flag value: a Go duration.
type lockWait time.Duration

func (l *lockWait) String() string { return time.Duration(*l).String() }

func (l *lockWait) Set(s string) error {
	d, err := time.ParseDuration(s)
	if err != nil || d < 0 {
		return fmt.Errorf("%q is not a duration", s)
	}
	*l = lockWait(d)
	return nil
}

// acquireLock takes an exclusive lock on the file at path and returns the function that releases it.
// It fails when another process holds the lock for the whole wait.
func acquireLock(ctx context.Context, path string, wait time.Duration) (func(), error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(wait)
	for {
		err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return func() {
				_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
				_ = f.Close()
			}, nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) {
			_ = f.Close()
			return nil, fmt.Errorf("lock %s: %w", path, err)
		}
		if !time.Now().Before(deadline) {
			_ = f.Close()
			return nil, fmt.Errorf("lock %s is held by another attach", path)
		}
		select {
		case <-ctx.Done():
			_ = f.Close()
			return nil, ctx.Err()
		case <-time.After(lockPoll):
		}
	}
}

// readBundle reads the cosign bundle and checks that it is the object that mgmtd makes.
func readBundle(path string) ([]byte, error) {
	if path == "" {
		return nil, errors.New("--bundle is required")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, maxSigstoreBundle+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maxSigstoreBundle {
		return nil, fmt.Errorf("cosign bundle is larger than %d bytes", maxSigstoreBundle)
	}
	var probe struct {
		MediaType    string          `json:"mediaType"`
		DSSEEnvelope json.RawMessage `json:"dsseEnvelope"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil || probe.MediaType != sigstoreMediaType || len(probe.DSSEEnvelope) == 0 {
		return nil, fmt.Errorf("%s is not a cosign bundle of media type %s with a dsseEnvelope", path, sigstoreMediaType)
	}
	return raw, nil
}

// referrerManifest builds the manifest of the cosign bundle as a referrer of the root manifest.
// The same bundle and root always give the same bytes, so a repeat attach changes nothing.
func referrerManifest(root ocispec.Descriptor, bundleJSON []byte) ([]byte, ocispec.Descriptor, ocispec.Descriptor, error) {
	config := []byte("{}")
	cfg := ocispec.Descriptor{MediaType: bundle.MediaTypeConfig, Digest: digest.FromBytes(config), Size: int64(len(config))}
	layer := ocispec.Descriptor{MediaType: sigstoreMediaType, Digest: digest.FromBytes(bundleJSON), Size: int64(len(bundleJSON))}
	m := ocispec.Manifest{
		Versioned:    specs.Versioned{SchemaVersion: 2},
		MediaType:    ocispec.MediaTypeImageManifest,
		ArtifactType: sigstoreMediaType,
		Config:       cfg,
		Layers:       []ocispec.Descriptor{layer},
		Subject:      &root,
		Annotations:  map[string]string{annContent: "dsse-envelope", annPredicate: bundle.PredicateType},
	}
	data, err := json.Marshal(m)
	return data, cfg, layer, err
}

// cmdAttach attaches the cosign bundle to the root bundle of a target on the mirror. One attach at
// a time may change the referrers of a root, because the registry has no referrers API and the
// fallback tag is one index that each attach reads and writes. The lock file keeps the attaches of
// this Mac in turn, and the store reads the index back to find an entry that another writer lost.
func cmdAttach(ctx context.Context, f flags, out io.Writer) error {
	if err := checkTarget(f.target); err != nil {
		return err
	}
	if !rootDigestRE.MatchString(f.digest) {
		return fmt.Errorf("--digest %q is not a digest as sha256:<64 hex>", f.digest)
	}
	raw, err := readBundle(f.bundleFile)
	if err != nil {
		return err
	}
	s, err := openStore(f.registry)
	if err != nil {
		return err
	}
	unlock, err := acquireLock(ctx, f.lock, time.Duration(f.lockWait))
	if err != nil {
		return err
	}
	defer unlock()

	repo := "bundles/" + f.target + "/root"
	rootManifest, err := s.Manifest(ctx, repo, f.digest)
	if err != nil {
		return fmt.Errorf("read root %s of %s: %w", f.digest, f.target, err)
	}
	subject := ocispec.Descriptor{MediaType: bundle.MediaTypeManifest, Digest: digest.Digest(f.digest), Size: int64(len(rootManifest))}
	data, cfg, layer, err := referrerManifest(subject, raw)
	if err != nil {
		return err
	}
	if err := s.PushBlob(ctx, repo, cfg.Digest.String(), []byte("{}")); err != nil {
		return fmt.Errorf("push config: %w", err)
	}
	if err := s.PushBlob(ctx, repo, layer.Digest.String(), raw); err != nil {
		return fmt.Errorf("push cosign bundle: %w", err)
	}
	d, err := s.PushManifest(ctx, repo, "", ocispec.MediaTypeImageManifest, data)
	if err != nil {
		return fmt.Errorf("push referrer: %w", err)
	}
	ref := ocistore.Referrer{
		Digest: d, Size: int64(len(data)), MediaType: ocispec.MediaTypeImageManifest, ArtifactType: sigstoreMediaType,
		Annotations: map[string]string{annContent: "dsse-envelope", annPredicate: bundle.PredicateType},
	}
	err = s.AttachReferrer(ctx, repo, f.digest, ref)
	if err != nil && strings.Contains(err.Error(), "lost") {
		err = s.AttachReferrer(ctx, repo, f.digest, ref)
	}
	if err != nil {
		return fmt.Errorf("attach to %s: %w", f.digest, err)
	}
	return writeJSON(out, map[string]string{"root": f.digest, "referrer": d, "repository": repo})
}
