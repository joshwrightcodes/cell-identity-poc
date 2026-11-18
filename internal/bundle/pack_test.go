package bundle_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/joshwrightcodes/cell-identity-poc/internal/bundle"
)

func sampleFiles() map[string][]byte {
	return map[string][]byte{
		"zeta.yaml":  []byte("kind: ConfigMap\n"),
		"alpha.yaml": []byte("kind: Secret\n"),
		"mid.yaml":   []byte(strings.Repeat("x", 3000)),
	}
}

// The mtime of a tar entry has a resolution of one second, so the runs below sit more than a second apart.
func TestPackDeterministic(t *testing.T) {
	a, err := bundle.Pack(sampleFiles())
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(1100 * time.Millisecond)
	// A map copy has a new iteration order for each range.
	b, err := bundle.Pack(maps.Clone(sampleFiles()))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a.Layer, b.Layer) || !bytes.Equal(a.Manifest, b.Manifest) || a.Digest != b.Digest {
		t.Fatalf("two runs differ: %s %s", a.Digest, b.Digest)
	}

	zr, err := gzip.NewReader(bytes.NewReader(a.Layer))
	if err != nil {
		t.Fatal(err)
	}
	if h := zr.Header; h.Name != "" || h.Comment != "" || !h.ModTime.IsZero() || len(h.Extra) != 0 {
		t.Errorf("gzip header %+v", h)
	}
	tr := tar.NewReader(zr)
	var names []string
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		names = append(names, hdr.Name)
		if hdr.Mode != 0o644 || hdr.Uid != 0 || hdr.Gid != 0 || hdr.Uname != "" || hdr.Gname != "" ||
			hdr.ModTime.Unix() != 0 || hdr.Typeflag != tar.TypeReg || len(hdr.PAXRecords) != 0 {
			t.Errorf("entry %q: %+v", hdr.Name, hdr)
		}
	}
	if want := []string{"alpha.yaml", "mid.yaml", "zeta.yaml"}; !reflect.DeepEqual(names, want) {
		t.Errorf("entries %v, want %v", names, want)
	}
}

func TestPackManifest(t *testing.T) {
	a, err := bundle.Pack(sampleFiles())
	if err != nil {
		t.Fatal(err)
	}
	sum := func(b []byte) string { s := sha256.Sum256(b); return "sha256:" + hex.EncodeToString(s[:]) }
	if string(a.Config) != "{}" || a.ConfigDigest != "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a" {
		t.Errorf("config %q %s", a.Config, a.ConfigDigest)
	}
	if a.LayerDigest != sum(a.Layer) || a.Digest != sum(a.Manifest) {
		t.Error("digests do not match the bytes")
	}
	var m struct {
		SchemaVersion int `json:"schemaVersion"`
		MediaType     string
		Config        struct {
			MediaType, Digest string
			Size              int
		}
		Layers []struct {
			MediaType, Digest string
			Size              int
		}
	}
	if err := json.Unmarshal(a.Manifest, &m); err != nil {
		t.Fatal(err)
	}
	if m.SchemaVersion != 2 || m.MediaType != "application/vnd.oci.image.manifest.v1+json" ||
		m.Config.MediaType != "application/vnd.oci.empty.v1+json" || m.Config.Digest != a.ConfigDigest || m.Config.Size != 2 ||
		len(m.Layers) != 1 || m.Layers[0].MediaType != "application/vnd.oci.image.layer.v1.tar+gzip" ||
		m.Layers[0].Digest != a.LayerDigest || m.Layers[0].Size != len(a.Layer) {
		t.Errorf("manifest %s", a.Manifest)
	}
}

func TestPackUnpackRoundTrip(t *testing.T) {
	a, err := bundle.Pack(sampleFiles())
	if err != nil {
		t.Fatal(err)
	}
	got, err := bundle.Unpack(a.Layer, bundle.MaxUnpackedBytes)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, sampleFiles()) {
		t.Errorf("got %v", got)
	}
	// An empty file survives.
	b, err := bundle.Pack(map[string][]byte{"empty.yaml": {}})
	if err != nil {
		t.Fatal(err)
	}
	if got, err := bundle.Unpack(b.Layer, 10); err != nil || len(got["empty.yaml"]) != 0 || len(got) != 1 {
		t.Errorf("empty file: %v %v", got, err)
	}
	// The unpack limit counts exactly.
	size := int64(len(sampleFiles()["zeta.yaml"]) + len(sampleFiles()["alpha.yaml"]) + 3000)
	if _, err := bundle.Unpack(a.Layer, size); err != nil {
		t.Errorf("limit equal to the size: %v", err)
	}
	if _, err := bundle.Unpack(a.Layer, size-1); err == nil {
		t.Error("limit one below the size passed")
	}
}

func TestPackRefuses(t *testing.T) {
	for name, files := range map[string]map[string][]byte{
		"nil":       nil,
		"empty_map": {},
		"slash":     {"a/b.yaml": []byte("x")},
		"dotdot":    {"..": []byte("x")},
		"dot":       {".": []byte("x")},
		"empty":     {"": []byte("x")},
		"backslash": {`a\b`: []byte("x")},
	} {
		if _, err := bundle.Pack(files); err == nil {
			t.Errorf("%s packed", name)
		}
	}
}

func rawTar(t testing.TB, entries ...*tar.Header) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	for _, h := range entries {
		body := []byte(strings.Repeat("x", int(h.Size)))
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestUnpackRefuses(t *testing.T) {
	reg := func(name string, size int64) *tar.Header {
		return &tar.Header{Typeflag: tar.TypeReg, Name: name, Mode: 0o644, Size: size}
	}
	many := make([]*tar.Header, 0, bundle.MaxObjects+1)
	for i := range bundle.MaxObjects + 1 {
		many = append(many, reg(fmt.Sprintf("f%04d", i), 0))
	}
	good, _ := bundle.Pack(sampleFiles())
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	zw.Write(bytes.Repeat([]byte{0}, 4<<20))
	zw.Close()

	for _, tc := range []struct {
		name  string
		layer []byte
		max   int64
	}{
		{"traversal", rawTar(t, reg("../evil", 1)), 1 << 20},
		{"absolute", rawTar(t, reg("/etc/passwd", 1)), 1 << 20},
		{"subdirectory", rawTar(t, reg("a/b", 1)), 1 << 20},
		{"dot_name", rawTar(t, reg(".", 1)), 1 << 20},
		{"directory", rawTar(t, &tar.Header{Typeflag: tar.TypeDir, Name: "d", Mode: 0o755}), 1 << 20},
		{"symlink", rawTar(t, &tar.Header{Typeflag: tar.TypeSymlink, Name: "l", Linkname: "/etc/passwd"}), 1 << 20},
		{"hardlink", rawTar(t, &tar.Header{Typeflag: tar.TypeLink, Name: "l", Linkname: "a"}), 1 << 20},
		{"duplicate", rawTar(t, reg("a", 1), reg("a", 2)), 1 << 20},
		{"too_many_entries", rawTar(t, many...), 1 << 20},
		{"over_limit", rawTar(t, reg("a", 100)), 99},
		{"over_limit_two_files", rawTar(t, reg("a", 60), reg("b", 60)), 100},
		{"bomb_not_tar", gz.Bytes(), 1000},
		{"not_gzip", []byte("plain text, not gzip"), 1 << 20},
		{"empty_input", nil, 1 << 20},
		{"truncated", good.Layer[:len(good.Layer)/2], 1 << 20},
		{"layer_over_8_mib", make([]byte, bundle.MaxLayerBytes+1), 1 << 20},
		{"trailing_gzip_garbage", append(append([]byte(nil), good.Layer...), []byte("garbage after the member")...), 1 << 20},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got, err := bundle.Unpack(tc.layer, tc.max); err == nil {
				t.Fatalf("unpacked %d files", len(got))
			}
		})
	}
	if _, err := bundle.Unpack(rawTar(t, reg("a", 100)), 100); err != nil {
		t.Errorf("control at the limit: %v", err)
	}
}
