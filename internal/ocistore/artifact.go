package ocistore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	specs "github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/joshwrightcodes/cell-identity-poc/internal/bundle"
)

// urlHolder is every descriptor position of a manifest or index that can carry urls.
type urlHolder struct {
	URLs []string `json:"urls"`
}

type urlScan struct {
	Config    *urlHolder  `json:"config"`
	Subject   *urlHolder  `json:"subject"`
	Layers    []urlHolder `json:"layers"`
	Blobs     []urlHolder `json:"blobs"`
	Manifests []urlHolder `json:"manifests"`
}

// refuseURLs returns ErrLayout when the manifest or index is not a JSON object or any descriptor
// in it sets urls.
func refuseURLs(data []byte) error {
	var s urlScan
	if err := json.Unmarshal(data, &s); err != nil {
		return fmt.Errorf("%w: manifest is not a JSON object: %v", ErrLayout, err)
	}
	all := append(append(append([]urlHolder{}, s.Layers...), s.Blobs...), s.Manifests...)
	for _, h := range []*urlHolder{s.Config, s.Subject} {
		if h != nil {
			all = append(all, *h)
		}
	}
	for _, h := range all {
		if len(h.URLs) > 0 {
			return fmt.Errorf("%w: a descriptor sets urls", ErrLayout)
		}
	}
	return nil
}

type descriptor struct {
	MediaType string `json:"mediaType"`
	Digest    string `json:"digest"`
	Size      int64  `json:"size"`
}

type artifactManifest struct {
	SchemaVersion int          `json:"schemaVersion"`
	MediaType     string       `json:"mediaType"`
	Config        descriptor   `json:"config"`
	Layers        []descriptor `json:"layers"`
}

// Fetch reads the bundle at the manifest digest. The manifest has the shape that bundle.Pack makes:
// one layer of the bundle layer type and an empty config. Every blob is checked against its
// digest and its declared size.
func Fetch(ctx context.Context, s *Store, repo, dgst string) (bundle.Artifact, error) {
	raw, err := s.Manifest(ctx, repo, dgst)
	if err != nil {
		return bundle.Artifact{}, err
	}
	var m artifactManifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return bundle.Artifact{}, fmt.Errorf("%w: %v", ErrLayout, err)
	}
	switch {
	case m.SchemaVersion != 2:
		return bundle.Artifact{}, fmt.Errorf("%w: schemaVersion %d", ErrLayout, m.SchemaVersion)
	case m.MediaType != bundle.MediaTypeManifest:
		return bundle.Artifact{}, fmt.Errorf("%w: manifest media type %q", ErrLayout, m.MediaType)
	case len(m.Layers) != 1:
		return bundle.Artifact{}, fmt.Errorf("%w: %d layers, want 1", ErrLayout, len(m.Layers))
	case m.Config.MediaType != bundle.MediaTypeConfig:
		return bundle.Artifact{}, fmt.Errorf("%w: config media type %q", ErrLayout, m.Config.MediaType)
	case bundle.CheckLayerMediaType(m.Layers[0].MediaType) != nil:
		return bundle.Artifact{}, fmt.Errorf("%w: %w", ErrLayout, bundle.CheckLayerMediaType(m.Layers[0].MediaType))
	case m.Config.Size < 0 || m.Config.Size > bundle.MaxConfigBytes:
		return bundle.Artifact{}, fmt.Errorf("%w: config size %d", ErrLayout, m.Config.Size)
	case m.Layers[0].Size <= 0 || m.Layers[0].Size > s.c.MaxBlob:
		return bundle.Artifact{}, fmt.Errorf("%w: layer size %d", ErrLayout, m.Layers[0].Size)
	}
	config, err := s.fetch(ctx, repo, m.Config.Digest, mediaTypeBlob, m.Config.Size)
	if err != nil {
		return bundle.Artifact{}, fmt.Errorf("read config: %w", err)
	}
	layer, err := s.fetch(ctx, repo, m.Layers[0].Digest, mediaTypeBlob, m.Layers[0].Size)
	if err != nil {
		return bundle.Artifact{}, fmt.Errorf("read layer: %w", err)
	}
	if int64(len(config)) != m.Config.Size || int64(len(layer)) != m.Layers[0].Size {
		return bundle.Artifact{}, fmt.Errorf("%w: a blob is shorter than its declared size", ErrLayout)
	}
	return bundle.Artifact{
		Layer: layer, LayerDigest: m.Layers[0].Digest,
		Config: config, ConfigDigest: m.Config.Digest,
		Manifest: raw, Digest: dgst,
	}, nil
}

// FallbackTag returns the tag of the referrers index of a subject when the registry has no
// referrers API: sha256-<hex>.
func FallbackTag(subject string) (string, error) {
	if _, err := checkDigest(subject); err != nil {
		return "", err
	}
	return "sha256-" + subject[len("sha256:"):], nil
}

// Referrer is one entry of the referrers index of a subject.
type Referrer struct {
	Digest       string
	Size         int64
	MediaType    string
	ArtifactType string
	Annotations  map[string]string
}

func (r Referrer) descriptor() (ocispec.Descriptor, error) {
	d, err := checkDigest(r.Digest)
	if err != nil {
		return ocispec.Descriptor{}, err
	}
	if r.MediaType != ocispec.MediaTypeImageManifest || r.Size <= 0 {
		return ocispec.Descriptor{}, fmt.Errorf("referrer %s needs an OCI manifest media type and a size", r.Digest)
	}
	return ocispec.Descriptor{MediaType: r.MediaType, Digest: d, Size: r.Size, ArtifactType: r.ArtifactType, Annotations: r.Annotations}, nil
}

// referrersIndex reads the fallback index of the subject. A missing tag is an empty index.
func (s *Store) referrersIndex(ctx context.Context, repo, subject string) ([]ocispec.Descriptor, error) {
	tag, err := FallbackTag(subject)
	if err != nil {
		return nil, err
	}
	limit := max(s.c.MaxManifest, maxIndex)
	d, err := s.resolve(ctx, repo, tag, limit)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, nil
		}
		return nil, err
	}
	raw, err := s.manifest(ctx, repo, d, limit)
	if err != nil {
		return nil, err
	}
	var idx ocispec.Index
	if err := json.Unmarshal(raw, &idx); err != nil {
		return nil, fmt.Errorf("%w: referrers index: %v", ErrLayout, err)
	}
	if idx.SchemaVersion != 2 || idx.MediaType != ocispec.MediaTypeImageIndex {
		return nil, fmt.Errorf("%w: tag %s is not an OCI index", ErrLayout, tag)
	}
	for i := range idx.Manifests {
		if _, err := checkDigest(idx.Manifests[i].Digest.String()); err != nil {
			return nil, fmt.Errorf("%w: referrers index: %v", ErrLayout, err)
		}
		idx.Manifests[i].URLs = nil
	}
	return idx.Manifests, nil
}

// Referrers lists the manifests that name the subject, read from the fallback tag. The store never
// calls the referrers API, which Distribution 3.1.2 does not have. A subject with no index has no
// referrers.
func (s *Store) Referrers(ctx context.Context, repo, subject string) ([]ocispec.Descriptor, error) {
	return s.referrersIndex(ctx, repo, subject)
}

// ErrLost is wrapped by the error of AttachReferrer when the read back finds that another writer
// replaced the index and dropped the new entry.
var ErrLost = errors.New("referrer entry lost")

var attachLocks sync.Map // registry/repo:tag -> *sync.Mutex

// AttachReferrer adds a referrer to the fallback index of the subject. The caller pushes the
// referrer manifest first. Calls for the same subject run one at a time in this process, because
// the update reads the index, changes it and writes it back. A referrer that the index already
// lists leaves it unchanged. Another process that writes the same tag at the same time can still
// lose an entry, because the registry has no compare-and-swap for tags. Only one writer may
// attach to a subject. The call reads the index again after the write and fails when its entry is
// missing, which detects such a loss.
func (s *Store) AttachReferrer(ctx context.Context, repo, subject string, r Referrer) error {
	desc, err := r.descriptor()
	if err != nil {
		return err
	}
	tag, err := FallbackTag(subject)
	if err != nil {
		return err
	}
	if err := checkRepo(repo); err != nil {
		return err
	}
	l, _ := attachLocks.LoadOrStore(s.host+"/"+repo+":"+tag, &sync.Mutex{})
	mu := l.(*sync.Mutex)
	mu.Lock()
	defer mu.Unlock()

	cur, err := s.referrersIndex(ctx, repo, subject)
	if err != nil {
		return err
	}
	for _, e := range cur {
		if e.Digest == desc.Digest {
			return nil
		}
	}
	data, err := json.Marshal(ocispec.Index{
		Versioned: specs.Versioned{SchemaVersion: 2},
		MediaType: ocispec.MediaTypeImageIndex,
		Manifests: append(cur, desc),
	})
	if err != nil {
		return fmt.Errorf("encode referrers index: %w", err)
	}
	if _, err := s.PushManifest(ctx, repo, tag, ocispec.MediaTypeImageIndex, data); err != nil {
		return fmt.Errorf("write referrers index: %w", err)
	}
	after, err := s.referrersIndex(ctx, repo, subject)
	if err != nil {
		return fmt.Errorf("read referrers index back: %w", err)
	}
	for _, e := range after {
		if e.Digest == desc.Digest {
			return nil
		}
	}
	return fmt.Errorf("%w: referrers index lost %s: another writer changed tag %s", ErrLost, desc.Digest, tag)
}
