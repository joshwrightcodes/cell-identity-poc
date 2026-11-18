package bundle_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"maps"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/joshwrightcodes/cell-identity-poc/internal/bundle"
)

var update = flag.Bool("update", false, "rewrite the golden files")

// checkGolden compares the digests of a with the golden file, or writes the file with -update.
func checkGolden(t testing.TB, path string, a bundle.Artifact) {
	t.Helper()
	got := fmt.Sprintf("manifest %s\nlayer %s\nconfig %s\n", a.Digest, a.LayerDigest, a.ConfigDigest)
	if *update {
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(want) != got {
		t.Errorf("digests differ from %s\n got:\n%s want:\n%s", path, got, want)
	}
}

func sampleFiles() map[string][]byte {
	return map[string][]byte{
		"zeta.yaml":  []byte("kind: ConfigMap\n"),
		"alpha.yaml": []byte("kind: Secret\n"),
		"mid.yaml":   []byte(strings.Repeat("x", 3000)),
	}
}

func TestPackGolden(t *testing.T) {
	a, err := bundle.Pack(sampleFiles())
	if err != nil {
		t.Fatal(err)
	}
	checkGolden(t, "testdata/pack.golden", a)
}

func TestPackDeterministic(t *testing.T) {
	a, err := bundle.Pack(sampleFiles())
	if err != nil {
		t.Fatal(err)
	}
	// A map copy has a new iteration order for each range.
	b, err := bundle.Pack(maps.Clone(sampleFiles()))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a.Layer, b.Layer) || !bytes.Equal(a.Manifest, b.Manifest) || a.Digest != b.Digest {
		t.Fatalf("two runs differ: %s %s", a.Digest, b.Digest)
	}

	tr := tar.NewReader(bytes.NewReader(a.Layer))
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
			hdr.ModTime.Unix() != 0 || hdr.Typeflag != tar.TypeReg || len(hdr.PAXRecords) != 0 || hdr.Format != tar.FormatUSTAR {
			t.Errorf("entry %q: %+v", hdr.Name, hdr)
		}
	}
	if want := []string{"alpha.yaml", "mid.yaml", "zeta.yaml"}; !reflect.DeepEqual(names, want) {
		t.Errorf("entries %v, want %v", names, want)
	}
	if a.Layer[0] == 0x1f && a.Layer[1] == 0x8b {
		t.Error("the layer is gzip")
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
		len(m.Layers) != 1 || m.Layers[0].MediaType != "application/vnd.oci.image.layer.v1.tar" ||
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
	// The unpack limit counts the bytes of the files exactly.
	size := int64(len("kind: ConfigMap\n") + len("kind: Secret\n") + 3000)
	if _, err := bundle.Unpack(a.Layer, size); err != nil {
		t.Errorf("limit equal to the size: %v", err)
	}
	if _, err := bundle.Unpack(a.Layer, size-1); !errors.Is(err, bundle.ErrTooLarge) {
		t.Errorf("limit one below the size: %v", err)
	}
}

func TestUnpackComponent(t *testing.T) {
	valid := "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: a\n"
	a, err := bundle.Pack(map[string][]byte{"manifests.yaml": []byte(valid)})
	if err != nil {
		t.Fatal(err)
	}
	got, err := bundle.UnpackComponent(a.Layer, 1<<20)
	if err != nil || string(got) != valid {
		t.Fatalf("got %q, %v", got, err)
	}
	for name, files := range map[string]map[string][]byte{
		"other_name":   {"other.yaml": []byte("x")},
		"extra_file":   {"manifests.yaml": []byte("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: a\n"), "extra.yaml": []byte("y")},
		"only_a_wrong": {"manifest.yaml": []byte("x")},
	} {
		b, err := bundle.Pack(files)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := bundle.UnpackComponent(b.Layer, 1<<20); !errors.Is(err, bundle.ErrLayout) {
			t.Errorf("%s: want ErrLayout, got %v", name, err)
		}
	}
	if _, err := bundle.UnpackComponent(a.Layer, 3); !errors.Is(err, bundle.ErrTooLarge) {
		t.Errorf("limit: %v", err)
	}
}

func TestPackRefuses(t *testing.T) {
	over := map[string][]byte{}
	for i := range bundle.MaxEntries + 1 {
		over[fmt.Sprintf("f%02d", i)] = []byte("x")
	}
	for name, tc := range map[string]struct {
		files map[string][]byte
		want  error
	}{
		"nil":        {nil, bundle.ErrLayout},
		"empty_map":  {map[string][]byte{}, bundle.ErrLayout},
		"slash":      {map[string][]byte{"a/b.yaml": []byte("x")}, bundle.ErrLayout},
		"dotdot":     {map[string][]byte{"..": []byte("x")}, bundle.ErrLayout},
		"dot":        {map[string][]byte{".": []byte("x")}, bundle.ErrLayout},
		"empty":      {map[string][]byte{"": []byte("x")}, bundle.ErrLayout},
		"backslash":  {map[string][]byte{`a\b`: []byte("x")}, bundle.ErrLayout},
		"empty_file": {map[string][]byte{"a": {}}, bundle.ErrLayout},
		"33_files":   {over, bundle.ErrLayout},
		"too_big":    {map[string][]byte{"a": make([]byte, bundle.MaxLayerBytes+1)}, bundle.ErrTooLarge},
	} {
		if _, err := bundle.Pack(tc.files); !errors.Is(err, tc.want) {
			t.Errorf("%s: want %v, got %v", name, tc.want, err)
		}
	}
}

func rawTar(t testing.TB, entries ...*tar.Header) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
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
	return buf.Bytes()
}

func TestUnpackRefuses(t *testing.T) {
	reg := func(name string, size int64) *tar.Header {
		return &tar.Header{Typeflag: tar.TypeReg, Name: name, Mode: 0o644, Size: size}
	}
	many := make([]*tar.Header, 0, bundle.MaxEntries+1)
	for i := range bundle.MaxEntries + 1 {
		many = append(many, reg(fmt.Sprintf("f%02d", i), 1))
	}
	good, _ := bundle.Pack(sampleFiles())
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	zw.Write(good.Layer)
	zw.Close()

	for _, tc := range []struct {
		name  string
		layer []byte
		max   int64
		want  error
	}{
		{"traversal", rawTar(t, reg("../evil", 1)), 1 << 20, bundle.ErrLayout},
		{"absolute", rawTar(t, reg("/etc/passwd", 1)), 1 << 20, bundle.ErrLayout},
		{"subdirectory", rawTar(t, reg("a/b", 1)), 1 << 20, bundle.ErrLayout},
		{"dot_name", rawTar(t, reg(".", 1)), 1 << 20, bundle.ErrLayout},
		{"directory", rawTar(t, &tar.Header{Typeflag: tar.TypeDir, Name: "d", Mode: 0o755}), 1 << 20, bundle.ErrLayout},
		{"symlink", rawTar(t, &tar.Header{Typeflag: tar.TypeSymlink, Name: "l", Linkname: "/etc/passwd"}), 1 << 20, bundle.ErrLayout},
		{"hardlink", rawTar(t, &tar.Header{Typeflag: tar.TypeLink, Name: "l", Linkname: "a"}), 1 << 20, bundle.ErrLayout},
		{"duplicate", rawTar(t, reg("a", 1), reg("a", 2)), 1 << 20, bundle.ErrLayout},
		{"empty_file", rawTar(t, reg("a", 0)), 1 << 20, bundle.ErrLayout},
		{"zero_entries", rawTar(t), 1 << 20, bundle.ErrLayout},
		{"33_entries", rawTar(t, many...), 1 << 20, bundle.ErrTooLarge},
		{"over_limit", rawTar(t, reg("a", 100)), 99, bundle.ErrTooLarge},
		{"over_limit_two_files", rawTar(t, reg("a", 60), reg("b", 60)), 100, bundle.ErrTooLarge},
		{"gzip_layer", gz.Bytes(), 1 << 20, bundle.ErrMediaType},
		{"not_a_tar", []byte(strings.Repeat("plain text, not a tar. ", 100)), 1 << 20, bundle.ErrLayout},
		{"empty_input", nil, 1 << 20, bundle.ErrLayout},
		{"truncated", good.Layer[:len(good.Layer)/2], 1 << 20, bundle.ErrLayout},
		{"layer_over_8_mib", make([]byte, bundle.MaxLayerBytes+1), 1 << 20, bundle.ErrTooLarge},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := bundle.Unpack(tc.layer, tc.max)
			if !errors.Is(err, tc.want) {
				t.Fatalf("want %v, got %v (%d files)", tc.want, err, len(got))
			}
		})
	}
	if _, err := bundle.Unpack(rawTar(t, reg("a", 100)), 100); err != nil {
		t.Errorf("control at the limit: %v", err)
	}
}

func TestCheckLayerMediaType(t *testing.T) {
	if err := bundle.CheckLayerMediaType("application/vnd.oci.image.layer.v1.tar"); err != nil {
		t.Error(err)
	}
	for _, mt := range []string{"application/vnd.oci.image.layer.v1.tar+gzip", "application/vnd.oci.image.layer.v1.tar+zstd", "", "text/plain"} {
		if err := bundle.CheckLayerMediaType(mt); !errors.Is(err, bundle.ErrMediaType) {
			t.Errorf("%q: %v", mt, err)
		}
	}
}
