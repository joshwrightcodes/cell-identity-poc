package bundle

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
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
	MediaTypeLayer    = "application/vnd.oci.image.layer.v1.tar+gzip"
)

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

// Pack returns the bundle of files. The layer is one gzip tar with each file at the root, mode
// 0644, user and group 0, modification time 0, the entries sorted by name, and a gzip header with
// no name and no time. The same files always give the same bytes. A file name holds no slash.
func Pack(files map[string][]byte) (Artifact, error) {
	if len(files) == 0 {
		return Artifact{}, errors.New("bundle has no files")
	}
	names := make([]string, 0, len(files))
	total := 0
	for name, body := range files {
		if !validFileName(name) {
			return Artifact{}, fmt.Errorf("file name %q is not a plain name", name)
		}
		names = append(names, name)
		total += len(body)
	}
	if total > MaxUnpackedBytes {
		return Artifact{}, fmt.Errorf("files hold %d bytes, above %d", total, MaxUnpackedBytes)
	}
	slices.Sort(names)

	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	zw.Header = gzip.Header{}
	tw := tar.NewWriter(zw)
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
	if err := zw.Close(); err != nil {
		return Artifact{}, fmt.Errorf("close gzip: %w", err)
	}
	layer := buf.Bytes()
	if len(layer) > MaxLayerBytes {
		return Artifact{}, fmt.Errorf("layer of %d bytes is above %d", len(layer), MaxLayerBytes)
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

// Unpack returns the files of a layer that Pack made, or a layer of the same shape. It refuses a
// layer above MaxLayerBytes, files that hold more than maxBytes together, more than MaxObjects
// entries, a duplicate name, a name with a slash or a dot name, and any entry that is not a
// regular file. It reads at most maxBytes plus the tar overhead of MaxObjects entries from the
// unpacked stream.
func Unpack(layer []byte, maxBytes int64) (map[string][]byte, error) {
	if len(layer) > MaxLayerBytes {
		return nil, fmt.Errorf("layer of %d bytes is above %d", len(layer), MaxLayerBytes)
	}
	zr, err := gzip.NewReader(bytes.NewReader(layer))
	if err != nil {
		return nil, fmt.Errorf("layer is not gzip: %w", err)
	}
	defer zr.Close()
	const tarOverhead = int64(MaxObjects+2) * 1024
	lr := &io.LimitedReader{R: zr, N: maxBytes + tarOverhead}
	tr := tar.NewReader(lr)
	files := map[string][]byte{}
	left := maxBytes
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("layer is not a tar: %w", err)
		}
		switch {
		case hdr.Typeflag != tar.TypeReg:
			return nil, fmt.Errorf("entry %q is not a regular file", hdr.Name)
		case !validFileName(hdr.Name):
			return nil, fmt.Errorf("entry name %q is not a plain name", hdr.Name)
		case len(files) >= MaxObjects:
			return nil, fmt.Errorf("layer has more than %d entries", MaxObjects)
		case hdr.Size > left:
			return nil, fmt.Errorf("layer unpacks to more than %d bytes", maxBytes)
		}
		if _, dup := files[hdr.Name]; dup {
			return nil, fmt.Errorf("entry %q appears twice", hdr.Name)
		}
		body, err := io.ReadAll(tr)
		if err != nil {
			return nil, fmt.Errorf("read entry %q: %w", hdr.Name, err)
		}
		left -= int64(len(body))
		files[hdr.Name] = body
	}
	if _, err := io.Copy(io.Discard, lr); err != nil {
		return nil, fmt.Errorf("read the end of the layer: %w", err)
	}
	if lr.N <= 0 {
		return nil, fmt.Errorf("layer unpacks to more than %d bytes", maxBytes)
	}
	return files, nil
}
