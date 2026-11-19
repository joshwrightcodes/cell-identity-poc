package bundle

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"
)

// The media types of a bundle.
const (
	MediaTypeManifest = "application/vnd.oci.image.manifest.v1+json"
	MediaTypeConfig   = "application/vnd.oci.empty.v1+json"
	MediaTypeLayer    = "application/vnd.oci.image.layer.v1.tar"
)

// ManifestsFile is the one file of a component layer.
const ManifestsFile = "manifests.yaml"

// MaxEntries is the most files in one layer. A root has one file for each component.
const MaxEntries = MaxComponents

// The sentinels of Unpack and its helpers. A caller tells the classes apart with errors.Is: the
// applier maps ErrTooLarge to the detail too_large and the others to layout.
var (
	// ErrTooLarge means the layer, its files or its entry count exceed a limit.
	ErrTooLarge = errors.New("bundle layer is too large")
	// ErrLayout means the layer is not a tar of plain, non-empty regular files, or a component
	// layer does not hold exactly manifests.yaml.
	ErrLayout = errors.New("bundle layer has the wrong layout")
	// ErrMediaType means a layer media type, or a layer that is compressed, is not
	// MediaTypeLayer.
	ErrMediaType = errors.New("bundle layer has an unsupported media type")
)

// CheckLayerMediaType returns an error that wraps ErrMediaType unless mediaType is MediaTypeLayer.
func CheckLayerMediaType(mediaType string) error {
	if mediaType != MediaTypeLayer {
		return fmt.Errorf("%w %q", ErrMediaType, mediaType)
	}
	return nil
}

// Artifact is one bundle as it sits in a registry: the layer, the empty config and the manifest
// that names both. Digest is the manifest digest, as sha256:<hex>.
type Artifact struct {
	Layer        []byte
	LayerDigest  string
	Config       []byte
	ConfigDigest string
	Manifest     []byte
	Digest       string
}

type descriptor struct {
	MediaType string `json:"mediaType"`
	Digest    string `json:"digest"`
	Size      int    `json:"size"`
}

type manifest struct {
	SchemaVersion int          `json:"schemaVersion"`
	MediaType     string       `json:"mediaType"`
	Config        descriptor   `json:"config"`
	Layers        []descriptor `json:"layers"`
}

func sha256Digest(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func validFileName(name string) bool {
	return name != "" && name != "." && name != ".." && !strings.ContainsAny(name, "/\\\x00")
}

// Pack returns the bundle of files. The file ManifestsFile must hold the canonical form, and Pack
// returns an error that wraps ErrNotCanonical for any other bytes. Callers canonicalise first. The
// layer is one uncompressed tar in USTAR form with each file at the root, mode 0644, user and group 0, modification time 0, and the entries sorted by name.
// The same files always give the same bytes, with no dependency on a compression library. A file
// name holds no slash, and a file is not empty. A bundle holds 1 to MaxEntries files.
func Pack(files map[string][]byte) (Artifact, error) {
	if len(files) == 0 || len(files) > MaxEntries {
		return Artifact{}, fmt.Errorf("%w: %d files are outside 1 to %d", ErrLayout, len(files), MaxEntries)
	}
	names := make([]string, 0, len(files))
	total := 0
	for name, body := range files {
		if !validFileName(name) {
			return Artifact{}, fmt.Errorf("%w: file name %q is not a plain name", ErrLayout, name)
		}
		if len(body) == 0 {
			return Artifact{}, fmt.Errorf("%w: file %q is empty", ErrLayout, name)
		}
		if name == ManifestsFile {
			if err := CheckCanonical(body); err != nil {
				return Artifact{}, fmt.Errorf("file %q: %w", name, err)
			}
		}
		names = append(names, name)
		total += len(body)
	}
	if total > MaxUnpackedBytes {
		return Artifact{}, fmt.Errorf("%w: files hold %d bytes, above %d", ErrTooLarge, total, MaxUnpackedBytes)
	}
	slices.Sort(names)

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, name := range names {
		body := files[name]
		hdr := &tar.Header{
			Typeflag: tar.TypeReg,
			Name:     name,
			Mode:     0o644,
			Size:     int64(len(body)),
			ModTime:  time.Unix(0, 0),
			Format:   tar.FormatUSTAR,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return Artifact{}, fmt.Errorf("write tar header of %q: %w", name, err)
		}
		if _, err := tw.Write(body); err != nil {
			return Artifact{}, fmt.Errorf("write tar body of %q: %w", name, err)
		}
	}
	if err := tw.Close(); err != nil {
		return Artifact{}, fmt.Errorf("close tar: %w", err)
	}
	layer := buf.Bytes()
	if len(layer) > MaxLayerBytes {
		return Artifact{}, fmt.Errorf("%w: layer of %d bytes is above %d", ErrTooLarge, len(layer), MaxLayerBytes)
	}

	config := []byte("{}")
	a := Artifact{Layer: layer, LayerDigest: sha256Digest(layer), Config: config, ConfigDigest: sha256Digest(config)}
	m, err := json.Marshal(manifest{
		SchemaVersion: 2,
		MediaType:     MediaTypeManifest,
		Config:        descriptor{MediaType: MediaTypeConfig, Digest: a.ConfigDigest, Size: len(config)},
		Layers:        []descriptor{{MediaType: MediaTypeLayer, Digest: a.LayerDigest, Size: len(layer)}},
	})
	if err != nil {
		return Artifact{}, fmt.Errorf("encode manifest: %w", err)
	}
	if len(m) > MaxManifestBytes {
		return Artifact{}, fmt.Errorf("manifest of %d bytes is above %d", len(m), MaxManifestBytes)
	}
	a.Manifest = m
	a.Digest = sha256Digest(m)
	return a, nil
}

// Unpack returns the files of a layer that Pack made, or a layer of the same shape. The layer is an
// uncompressed tar, and a gzip layer gives ErrMediaType. It gives ErrTooLarge for a layer above
// MaxLayerBytes, files that hold more than maxBytes together, or more than MaxEntries entries. It
// gives ErrLayout for zero entries, an empty file, a duplicate name, a name with a slash or a dot
// name, an entry that is not a regular file, and a layer that is not a tar.
func Unpack(layer []byte, maxBytes int64) (map[string][]byte, error) {
	if len(layer) > MaxLayerBytes {
		return nil, fmt.Errorf("%w: layer of %d bytes is above %d", ErrTooLarge, len(layer), MaxLayerBytes)
	}
	if len(layer) >= 2 && layer[0] == 0x1f && layer[1] == 0x8b {
		return nil, fmt.Errorf("%w: the layer is gzip", ErrMediaType)
	}
	tr := tar.NewReader(bytes.NewReader(layer))
	files := map[string][]byte{}
	left := maxBytes
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("%w: not a tar: %v", ErrLayout, err)
		}
		switch {
		case hdr.Typeflag != tar.TypeReg:
			return nil, fmt.Errorf("%w: entry %q is not a regular file", ErrLayout, hdr.Name)
		case !validFileName(hdr.Name):
			return nil, fmt.Errorf("%w: entry name %q is not a plain name", ErrLayout, hdr.Name)
		case len(files) >= MaxEntries:
			return nil, fmt.Errorf("%w: more than %d entries", ErrTooLarge, MaxEntries)
		case hdr.Size == 0:
			return nil, fmt.Errorf("%w: entry %q is empty", ErrLayout, hdr.Name)
		case hdr.Size > left:
			return nil, fmt.Errorf("%w: files hold more than %d bytes", ErrTooLarge, maxBytes)
		}
		if _, dup := files[hdr.Name]; dup {
			return nil, fmt.Errorf("%w: entry %q appears twice", ErrLayout, hdr.Name)
		}
		body, err := io.ReadAll(tr)
		if err != nil {
			return nil, fmt.Errorf("%w: read entry %q: %v", ErrLayout, hdr.Name, err)
		}
		left -= int64(len(body))
		files[hdr.Name] = body
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("%w: no entries", ErrLayout)
	}
	return files, nil
}

// UnpackComponent returns the manifests of a component layer. The layer must hold exactly one file,
// ManifestsFile, because Argo CD reads every YAML and JSON file of the path.
func UnpackComponent(layer []byte, maxBytes int64) ([]byte, error) {
	files, err := Unpack(layer, maxBytes)
	if err != nil {
		return nil, err
	}
	body, ok := files[ManifestsFile]
	if !ok || len(files) != 1 {
		return nil, fmt.Errorf("%w: a component layer holds exactly %s", ErrLayout, ManifestsFile)
	}
	return body, nil
}
