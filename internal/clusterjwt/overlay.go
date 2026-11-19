package clusterjwt

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"slices"
	"strings"

	"github.com/hashicorp/hcl"

	"github.com/joshwrightcodes/cell-identity-poc/internal/revoke"
	envspec "github.com/joshwrightcodes/cell-identity-poc/internal/spec"
)

// overlayFile is the key of the local revocations in the records directory: a JSON array of
// envelopes that envd wrote.
const overlayFile = "local-revocations.json"

// The sources of a revoked cell in a RevokedSet. The first two also appear as the source field of a
// refusal in the log.
const (
	SourceRecord  = "record"
	SourceOverlay = "overlay"
	SourceRetired = "retired"
)

// loadOverlay returns the overlay of one load and the count of entries that the load skipped. An entry
// that does not verify under the operator keys or names another environment is skipped, and it never
// refuses a cell. A file that exists and cannot be read keeps the overlay of base, because dropping
// held entries would admit cells that an operator revoked.
func (p *Plugin) loadOverlay(raw *rawLoad, cfg, base *state, note func(func(string, ...any), string, string, ...any)) (revoke.Held, int) {
	var keep revoke.Held
	if base != nil && keysEqual(base.operatorKeys, cfg.operatorKeys) {
		keep = maps.Clone(base.overlay)
	}
	fail := func(reason string) (revoke.Held, int) {
		note(p.log.Error, "overlay_unreadable", overlayFile, "reason", reason)
		return keep, 0
	}
	if raw.overlayErr != nil {
		return fail("the file is not a small regular file")
	}
	if raw.overlay == nil || len(cfg.operatorKeys) == 0 {
		return nil, 0
	}
	var items []json.RawMessage
	dec := json.NewDecoder(bytes.NewReader(raw.overlay))
	if err := dec.Decode(&items); err != nil || dec.More() {
		return fail("the file is not a JSON array")
	}
	envelopes := make([][]byte, len(items))
	for i, it := range items {
		envelopes[i] = it
	}
	held, refusals := revoke.Load(envelopes, cfg.operatorKeys, cfg.env)
	for i, r := range refusals {
		note(p.log.Warn, "overlay_entry_refused", overlayFile, "reason", r.Reason, "detail", r.Detail, "cell", r.Cell, "id", r.ID, "entry", i)
	}
	return held, len(refusals)
}

func keysEqual(a, b []ed25519.PublicKey) bool {
	return slices.EqualFunc(a, b, func(x, y ed25519.PublicKey) bool { return x.Equal(y) })
}

func overlayEqual(a, b revoke.Held) bool {
	return maps.EqualFunc(a, b, bytes.Equal)
}

// RevokedSet is the set of cells that the plugin refuses.
type RevokedSet struct {
	// Cells maps each refused cell to its source: record, overlay or retired. A cell that has more
	// than one source gets the first of record, retired and overlay.
	Cells map[string]string
	// Spec is the revision of the spec that the set comes from.
	Spec envspec.Revision
}

// pluginData returns the plugin_data block of the cluster_jwt NodeAttestor in a decoded SPIRE server
// configuration. HCL decodes each block as a list of maps.
func pluginData(doc map[string]any) (map[string]any, bool) {
	var found []map[string]any
	for _, plugins := range blocks(doc["plugins"]) {
		for _, attestor := range blocks(plugins["NodeAttestor"]) {
			for _, plugin := range blocks(attestor[PluginName]) {
				found = append(found, blocks(plugin["plugin_data"])...)
			}
		}
	}
	if len(found) != 1 {
		return nil, false
	}
	return found[0], true
}

func blocks(v any) []map[string]any {
	l, _ := v.([]map[string]any)
	return l
}

// ReadRevoked reads the SPIRE server configuration at serverConfigPath and returns the cells that the
// cluster_jwt plugin refuses: cells whose record is revoked, cells that a verified local revocation
// names, and retired cells. It applies the checks of the plugin to the records directory and the marks
// file, and it writes nothing. It fails when no verified spec loads, so a caller never reads an empty
// set as "nothing is revoked".
func ReadRevoked(serverConfigPath string) (RevokedSet, error) {
	text, err := os.ReadFile(serverConfigPath)
	if err != nil {
		return RevokedSet{}, fmt.Errorf("read server config: %w", err)
	}
	var doc map[string]any
	if err := hcl.Decode(&doc, string(text)); err != nil {
		return RevokedSet{}, fmt.Errorf("parse server config: %w", err)
	}
	data, ok := pluginData(doc)
	if !ok {
		return RevokedSet{}, errors.New("server config needs exactly one cluster_jwt plugin_data block")
	}
	pluginText, err := encodeHCL(data)
	if err != nil {
		return RevokedSet{}, err
	}
	p := New()
	st, err := p.parse(pluginText, "")
	if err != nil {
		return RevokedSet{}, err
	}
	p.markMu.Lock()
	usable := p.ensureMarks(st, func(_ func(string, ...any), msg, _ string, kv ...any) {
		p.log.Error(msg, clip(kv)...)
	})
	p.markMu.Unlock()
	if !usable {
		return RevokedSet{}, errors.New("the marks file cannot be used")
	}
	snap, err := p.load(st, nil, false)
	if err != nil {
		return RevokedSet{}, err
	}
	if snap.spec == (envspec.Revision{}) {
		return RevokedSet{}, errors.New("no verified spec loaded")
	}
	out := RevokedSet{Cells: map[string]string{}, Spec: snap.spec}
	for name := range snap.overlay {
		if _, ok := snap.records[name]; ok {
			out.Cells[name] = SourceOverlay
		}
	}
	for name := range snap.retired {
		if snap.retired[name] {
			out.Cells[name] = SourceRetired
		}
	}
	for name, rec := range snap.records {
		if rec.Revoked {
			out.Cells[name] = SourceRecord
		}
	}
	return out, nil
}

// encodeHCL writes the decoded values of a plugin_data block as HCL text for parse. It handles the
// types that the settings of the plugin use: strings, numbers, booleans and lists of strings.
func encodeHCL(m map[string]any) (string, error) {
	var b strings.Builder
	for _, k := range slices.Sorted(maps.Keys(m)) {
		v, err := json.Marshal(m[k])
		if err != nil {
			return "", fmt.Errorf("plugin_data %s: %w", k, err)
		}
		fmt.Fprintf(&b, "%s = %s\n", k, v)
	}
	return b.String(), nil
}
