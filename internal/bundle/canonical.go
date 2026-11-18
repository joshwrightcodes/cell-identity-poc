package bundle

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	yamlv3 "go.yaml.in/yaml/v3"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
	"sigs.k8s.io/yaml"
	goyaml "sigs.k8s.io/yaml/goyaml.v2"
)

func init() { goyaml.FutureLineWrap() }

// ErrNotCanonical means that manifests are not in the canonical form, or that they break a rule
// that the applier checks before the policy runs.
var ErrNotCanonical = errors.New("manifests are not in the canonical form")

// ManifestError is a refusal of manifests. Detail is one of layout, list, items_list, too_large and
// not_canonical. The applier reports it as the detail of component_not_allowed.
type ManifestError struct{ Detail string }

func (e *ManifestError) Error() string { return "manifests refused: " + e.Detail }

func refuse(detail string) error { return &ManifestError{Detail: detail} }

var docSeparator = []byte("---\n")

// sorted converts a decoded value into a yaml.MapSlice tree with every map in byte order of its keys.
// The library map sort of yaml.v2 is not transitive for keys such as 21, 2B22 and 9YAC, so it can
// give another order on each run.
func sorted(v any) any {
	switch t := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		out := make(goyaml.MapSlice, 0, len(keys))
		for _, k := range keys {
			out = append(out, goyaml.MapItem{Key: k, Value: sorted(t[k])})
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, e := range t {
			out[i] = sorted(e)
		}
		return out
	default:
		return v
	}
}

// encode writes objects in the canonical form without checking that the applier accepts the result.
func encode(objs []map[string]any) ([]byte, error) {
	var buf bytes.Buffer
	for i, o := range objs {
		b, err := goyaml.Marshal(sorted(o))
		if err != nil {
			return nil, fmt.Errorf("encode object %d: %w", i, err)
		}
		if i > 0 {
			buf.Write(docSeparator)
		}
		buf.Write(b)
	}
	return buf.Bytes(), nil
}

// Canonical writes objects in the one form that the applier accepts. Each object is block-style
// YAML with every map in byte order of its keys, and the objects are joined by a line of three
// dashes, with no separator before the first object. The form is plain UTF-8 with no comment, byte
// order mark, carriage return, anchor, tag or flow-style document, so every YAML and JSON reader sees
// the same objects. The same objects always give the same bytes. Canonical returns an error that
// wraps ErrNotCanonical for objects that have no accepted form, for example a string with a line
// separator character or an object with an items field. A publisher canonicalises the render before
// it packs and signs it.
func Canonical(objs []map[string]any) ([]byte, error) {
	b, err := encode(objs)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNotCanonical, err)
	}
	if _, err := DecodeCanonical(b, len(objs)); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNotCanonical, err)
	}
	return b, nil
}

// CheckCanonical returns an error that wraps ErrNotCanonical unless body is the output of Canonical.
func CheckCanonical(body []byte) error {
	if _, err := DecodeCanonical(body, MaxObjects); err != nil {
		return fmt.Errorf("%w: %v", ErrNotCanonical, err)
	}
	return nil
}

// DecodeCanonical decodes manifests with DecodeManifests, and refuses them with detail not_canonical
// unless they are the canonical form of their own objects. Only that form reads the same in every
// YAML and JSON reader, so the objects that a policy sees are the objects that Argo CD applies.
func DecodeCanonical(manifests []byte, maxObjects int) ([]map[string]any, error) {
	objs, err := DecodeManifests(manifests, maxObjects)
	if err != nil {
		return nil, err
	}
	canon, err := encode(objs)
	if err != nil {
		return nil, refuse("layout")
	}
	if !bytes.Equal(canon, manifests) {
		return nil, refuse("not_canonical")
	}
	return objs, nil
}

// DecodeManifests reads the documents of manifests. Every refusal is a *ManifestError. A document of
// kind List gives detail list. Any other document with an items field gives items_list, because Argo
// CD expands every object that has an items array and a policy checks only the outer object. More
// than maxObjects objects give too_large. Anything else that is not plain gives layout: text with a
// byte order mark, NUL, invalid UTF-8 or an odd line break, a document that starts with a flow
// construct, a chunk with more than one document, an anchor, alias, merge key, tag or duplicate key,
// and a document that is not an object with apiVersion, kind and a name. A null namespace is removed
// from the object, and an empty document is skipped.
func DecodeManifests(manifests []byte, maxObjects int) ([]map[string]any, error) {
	if !plainText(manifests) {
		return nil, refuse("layout")
	}
	rd := utilyaml.NewYAMLReader(bufio.NewReader(bytes.NewReader(manifests)))
	var objs []map[string]any
	for {
		doc, err := rd.Read()
		if errors.Is(err, io.EOF) {
			return objs, nil
		}
		if err != nil {
			return nil, refuse("layout")
		}
		if !singlePlainDocument(doc) {
			return nil, refuse("layout")
		}
		var raw map[string]any
		if err := yaml.Unmarshal(doc, &raw); err != nil {
			return nil, refuse("layout")
		}
		if len(raw) == 0 {
			continue
		}
		if k, _ := raw["kind"].(string); k == "List" {
			return nil, refuse("list")
		}
		if _, has := raw["items"]; has {
			return nil, refuse("items_list")
		}
		if !validObject(raw) {
			return nil, refuse("layout")
		}
		if len(objs) >= maxObjects {
			return nil, refuse("too_large")
		}
		objs = append(objs, raw)
	}
}

// validObject checks the shape of an object and removes a null namespace.
func validObject(raw map[string]any) bool {
	if s, ok := raw["apiVersion"].(string); !ok || s == "" || strings.Count(s, "/") > 1 {
		return false
	}
	if s, ok := raw["kind"].(string); !ok || s == "" {
		return false
	}
	meta, ok := raw["metadata"].(map[string]any)
	if !ok {
		return false
	}
	if s, ok := meta["name"].(string); !ok || s == "" {
		return false
	}
	if v, present := meta["namespace"]; present {
		if v == nil {
			delete(meta, "namespace")
		} else if _, ok := v.(string); !ok {
			return false
		}
	}
	for _, field := range []string{"labels", "annotations"} {
		v, present := meta[field]
		if !present || v == nil {
			continue
		}
		m, ok := v.(map[string]any)
		if !ok {
			return false
		}
		for _, val := range m {
			if _, ok := val.(string); !ok {
				return false
			}
		}
	}
	return true
}

// plainText reports whether the bytes hold only text that every YAML reader splits into lines in
// the same way: valid UTF-8 with no byte order mark, no NUL byte, no lone carriage return, no
// NEL, line separator or paragraph separator, and no line that starts a YAML document end marker.
func plainText(b []byte) bool {
	if !utf8.Valid(b) || bytes.IndexByte(b, 0) >= 0 || bytes.Contains(b, []byte("\xef\xbb\xbf")) {
		return false
	}
	for i := 0; i < len(b); i++ {
		if b[i] == '\r' && (i+1 >= len(b) || b[i+1] != '\n') {
			return false
		}
	}
	for _, r := range string(b) {
		if r == '\u0085' || r == '\u2028' || r == '\u2029' {
			return false
		}
	}
	for _, line := range bytes.Split(b, []byte("\n")) {
		if bytes.HasPrefix(line, []byte("...")) && (len(line) == 3 || line[3] == ' ' || line[3] == '\t' || line[3] == '\r') {
			return false
		}
	}
	return true
}

// singlePlainDocument reports whether chunk is zero or one YAML document that starts with a block
// construct and holds no anchor, alias, merge key, tag or duplicate key.
func singlePlainDocument(chunk []byte) bool {
	first := bytes.TrimLeftFunc(chunk, unicode.IsSpace)
	if len(first) > 0 && (first[0] == '{' || first[0] == '[') {
		return false
	}
	dec := yamlv3.NewDecoder(bytes.NewReader(chunk))
	var n yamlv3.Node
	if err := dec.Decode(&n); err != nil {
		return errors.Is(err, io.EOF)
	}
	var again yamlv3.Node
	if err := dec.Decode(&again); !errors.Is(err, io.EOF) {
		return false
	}
	return plainNode(&n)
}

// stringKey reports whether a map key reads as a string in YAML 1.1, the reading of yaml.v2. An
// unquoted key such as y, on, 1 or 1.5 is a bool or a number there, and two such keys can merge
// into one. A quoted key is always a string.
func stringKey(k *yamlv3.Node) bool {
	if k.Style&(yamlv3.DoubleQuotedStyle|yamlv3.SingleQuotedStyle|yamlv3.LiteralStyle|yamlv3.FoldedStyle) != 0 {
		return true
	}
	var v any
	if err := goyaml.Unmarshal([]byte(k.Value), &v); err != nil {
		return false
	}
	_, isString := v.(string)
	return isString
}

func plainNode(n *yamlv3.Node) bool {
	if n.Anchor != "" || n.Kind == yamlv3.AliasNode || n.Style&yamlv3.TaggedStyle != 0 {
		return false
	}
	if n.Kind == yamlv3.MappingNode {
		seen := make(map[string]bool, len(n.Content)/2)
		for i := 0; i+1 < len(n.Content); i += 2 {
			k := n.Content[i]
			if k.Kind == yamlv3.ScalarNode {
				if k.Tag == "!!merge" || seen[k.Value] || !stringKey(k) {
					return false
				}
				seen[k.Value] = true
			}
		}
	}
	for _, c := range n.Content {
		if !plainNode(c) {
			return false
		}
	}
	return true
}
