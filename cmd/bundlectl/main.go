// Command bundlectl packs, pushes and composes bundle sets on the Mac.
//
//	bundlectl set --target <t> [--build <dir>] [--root <dir>] <component>:<wave>:<namespace>...
//	bundlectl push --target <t> --registry <host:port> [--build <dir>] [--root <dir>] <entry>...
//	bundlectl bootstrap --role <role> --target <t> --registry <host:port> [--build <dir>] [--root <dir>] <entry>...
//	bundlectl compose --role <role> --set <file>|-
//	bundlectl push-root --role <role> --target <t> --set <file>|- --registry <host:port>
//	bundlectl attach --target <t> --digest <sha256:hex> --bundle <file> --registry <host:port> [--lock <file>] [--lock-wait <d>]
//	bundlectl projects --role <role> [--root <dir>]
//	bundlectl pubkey-pem
//
// Each entry names a hydrated bundle in <build>/<target>/bundles/<component>/manifests.yaml, as in
// COMPONENTS of scripts/lib.sh. The command parses the render, writes it in the canonical form of
// internal/bundle and packs it, so the same objects always give the same digest.
//
// set prints the components of the set as one JSON array, in order of name. push also puts each
// bundle on the mirror under bundles/<target>/<component>. bootstrap puts the bundles and the root
// of a cluster in the store of that cluster, under bundles/<component> and bundles/root, and
// points the tag current at the root. push-root puts the root of a signed set on the mirror under
// bundles/<target>/root. Every registry address must be a loopback host with a port.
//
// Standard output carries only data on success, and one JSON error line on failure.
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"

	yamlv3 "go.yaml.in/yaml/v3"
	"sigs.k8s.io/yaml"

	"github.com/joshwrightcodes/cell-identity-poc/internal/bundle"
	"github.com/joshwrightcodes/cell-identity-poc/internal/cli"
	"github.com/joshwrightcodes/cell-identity-poc/internal/ocistore"
)

const (
	usage = "usage: bundlectl set|push|bootstrap|push-root|compose|attach|projects|pubkey-pem (see the package comment of cmd/bundlectl)"

	appProjectFile  = "components/argocd/project.yaml"
	allowAnnotation = "poc.internal/allow-sha256"
	maxSmallInput   = 1 << 20
	maxKeyInput     = 4 << 10
)

var labelRE = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)

// storeTransport carries the requests to a registry. Tests replace it.
var storeTransport http.RoundTripper

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := execute(ctx, os.Args[1:], os.Stdin, os.Stdout)
	stop()
	os.Exit(code)
}

// execute runs one command and returns the exit code.
func execute(ctx context.Context, args []string, stdin io.Reader, stdout io.Writer) int {
	return cli.Run(stdout, "bundlectl", func(out io.Writer) error { return run(ctx, args, stdin, out) })
}

func run(ctx context.Context, args []string, stdin io.Reader, out io.Writer) error {
	if len(args) == 0 {
		return errors.New(usage)
	}
	cmd, rest := args[0], args[1:]
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var f flags
	f.register(fs)
	if err := fs.Parse(rest); err != nil {
		return fmt.Errorf("%s: %w", cmd, err)
	}
	f.entries = fs.Args()
	if f.lock == "" {
		f.lock = filepath.Join(f.build, "bundle-attach.lock")
	}
	switch cmd {
	case "set":
		return cmdSet(ctx, f, out, false)
	case "push":
		return cmdSet(ctx, f, out, true)
	case "bootstrap":
		return cmdBootstrap(ctx, f, out)
	case "compose":
		return cmdCompose(f, stdin, out)
	case "push-root":
		return cmdPushRoot(ctx, f, stdin, out)
	case "attach":
		return cmdAttach(ctx, f, out)
	case "projects":
		return cmdProjects(f, out)
	case "pubkey-pem":
		if len(rest) != 0 {
			return errors.New("pubkey-pem takes no arguments: the key comes on standard input")
		}
		return cmdPubkeyPEM(stdin, out)
	}
	return fmt.Errorf("unknown command %q; %s", cmd, usage)
}

type flags struct {
	target, build, root, registry, role, set, bundleFile, lock, digest string
	lockWait                                                           lockWait
	entries                                                            []string
}

func (f *flags) register(fs *flag.FlagSet) {
	fs.StringVar(&f.target, "target", "", "cluster that the set is for")
	fs.StringVar(&f.build, "build", "build", "directory with <target>/bundles/<component>/manifests.yaml")
	fs.StringVar(&f.root, "root", ".", "repository root")
	fs.StringVar(&f.digest, "digest", "", "digest of the root manifest as sha256:<hex> (attach)")
	fs.StringVar(&f.registry, "registry", "", "loopback host:port of the registry")
	fs.StringVar(&f.role, "role", "", "cluster role: cell, cp or open")
	fs.StringVar(&f.set, "set", "", "file with the components as a JSON array, or - for standard input")
	fs.StringVar(&f.bundleFile, "bundle", "", "file with the cosign bundle (attach)")
	fs.StringVar(&f.lock, "lock", "", "lock file of attach (default <build>/bundle-attach.lock)")
	f.lockWait = defaultLockWait
	fs.Var(&f.lockWait, "lock-wait", "how long attach waits for the lock")
}

// entry is one component to publish: <component>:<wave>:<namespace>.
type entry struct {
	name, namespace string
	wave            int
}

func parseEntries(args []string) ([]entry, error) {
	if len(args) == 0 {
		return nil, errors.New("no components: give each as <component>:<wave>:<namespace>")
	}
	var out []entry
	seen := map[string]bool{}
	for _, a := range args {
		p := strings.Split(a, ":")
		if len(p) != 3 {
			return nil, fmt.Errorf("entry %q is not <component>:<wave>:<namespace>", a)
		}
		wave, err := strconv.Atoi(p[1])
		if err != nil || wave < bundle.MinWave || wave > bundle.MaxWave {
			return nil, fmt.Errorf("entry %q: wave is not a number from %d to %d", a, bundle.MinWave, bundle.MaxWave)
		}
		if !labelRE.MatchString(p[0]) || !labelRE.MatchString(p[2]) {
			return nil, fmt.Errorf("entry %q: the component and the namespace must be DNS labels", a)
		}
		if seen[p[0]] {
			return nil, fmt.Errorf("component %q is listed twice", p[0])
		}
		seen[p[0]] = true
		out = append(out, entry{name: p[0], wave: wave, namespace: p[2]})
	}
	return out, nil
}

func checkTarget(t string) error {
	if len(t) > 40 || !labelRE.MatchString(t) {
		return fmt.Errorf("target %q is not a DNS label of at most 40 characters", t)
	}
	return nil
}

// built is the packed set of one target.
type built struct {
	components []bundle.Component
	artifacts  map[string]bundle.Artifact
}

// load reads the render of each entry, writes it in the canonical form and packs it. It reads and
// writes only files, so a failure leaves a registry untouched.
func load(f flags) (built, error) {
	if err := checkTarget(f.target); err != nil {
		return built{}, err
	}
	entries, err := parseEntries(f.entries)
	if err != nil {
		return built{}, err
	}
	b := built{artifacts: map[string]bundle.Artifact{}}
	for _, e := range entries {
		art, err := packRender(filepath.Join(f.build, f.target, "bundles", e.name, bundle.ManifestsFile), e.name)
		if err != nil {
			return built{}, err
		}
		extra, err := readExtras(f.root, e.name)
		if err != nil {
			return built{}, err
		}
		b.artifacts[e.name] = art
		b.components = append(b.components, bundle.Component{
			Name: e.name, Wave: e.wave, Namespace: e.namespace, Digest: art.Digest, IgnoreDifferences: extra,
		})
	}
	slices.SortFunc(b.components, func(x, y bundle.Component) int { return strings.Compare(x.Name, y.Name) })
	raw, err := json.Marshal(b.components)
	if err != nil {
		return built{}, err
	}
	if b.components, err = bundle.ParseComponents(raw); err != nil {
		return built{}, fmt.Errorf("set is not valid: %w", err)
	}
	return b, nil
}

func packRender(path, name string) (bundle.Artifact, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return bundle.Artifact{}, fmt.Errorf("component %q: %w", name, err)
	}
	if fi.Size() > bundle.MaxLayerBytes {
		return bundle.Artifact{}, fmt.Errorf("component %q: render of %d bytes is above %d", name, fi.Size(), bundle.MaxLayerBytes)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return bundle.Artifact{}, fmt.Errorf("component %q: %w", name, err)
	}
	objs, err := bundle.DecodeManifests(raw, bundle.MaxObjects)
	if err != nil {
		return bundle.Artifact{}, fmt.Errorf("component %q: the render has no canonical form (anchors, aliases, merge keys, tags, duplicate keys, lists and flow documents are not accepted)%s: %w", name, boolHint(raw), err)
	}
	if len(objs) == 0 {
		return bundle.Artifact{}, fmt.Errorf("component %q: the render holds no object", name)
	}
	if k := lostKey(raw, objs); k != "" {
		return bundle.Artifact{}, fmt.Errorf("component %q: key %q: %s", name, k, boolText)
	}
	canon, err := bundle.Canonical(objs)
	if err != nil {
		return bundle.Artifact{}, fmt.Errorf("component %q: %w", name, err)
	}
	art, err := bundle.Pack(map[string][]byte{bundle.ManifestsFile: canon})
	if err != nil {
		return bundle.Artifact{}, fmt.Errorf("component %q: %w", name, err)
	}
	return art, nil
}

var boolRE = regexp.MustCompile(`(?mi)^[ \t-]*(y|n|yes|no|on|off)[ \t]*:|:[ \t]+(y|n|yes|no|on|off)[ \t]*$`)

const boolText = "an unquoted y, n, yes, no, on or off is read as a boolean, so quote it"

// lostKey returns a map key of the render that the readers of the cluster change: they read the
// key y as the boolean true and write it as "true", so the key is lost or merged with another one.
// It compares the keys that a YAML 1.2 reader sees with the keys of objs, and returns "" for none.
func lostKey(raw []byte, objs []map[string]any) string {
	have := map[string]bool{}
	var collect func(v any)
	collect = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			for k, e := range x {
				have[k] = true
				collect(e)
			}
		case []any:
			for _, e := range x {
				collect(e)
			}
		}
	}
	for _, o := range objs {
		collect(o)
	}
	dec := yamlv3.NewDecoder(bytes.NewReader(raw))
	for {
		var doc any
		if err := dec.Decode(&doc); err != nil {
			return ""
		}
		var bad string
		var walk func(v any)
		walk = func(v any) {
			switch x := v.(type) {
			case map[string]any:
				for k, e := range x {
					if !have[k] && (bad == "" || k < bad) {
						bad = k
					}
					walk(e)
				}
			case []any:
				for _, e := range x {
					walk(e)
				}
			}
		}
		walk(doc)
		if bad != "" {
			return bad
		}
	}
}

// boolHint names a likely cause of a refusal: the YAML readers of the cluster read an unquoted y, n,
// yes, no, on or off as a boolean, so a name or a key with such a text is not a string.
func boolHint(raw []byte) string {
	if boolRE.Match(raw) {
		return "; " + boolText
	}
	return ""
}

// readExtras returns the ignoreDifferences list of components/<name>/application.yaml, or nil when
// the file is absent. The root of a set carries nothing else of that file, so any other field is an error.
func readExtras(root, name string) (json.RawMessage, error) {
	path := filepath.Join(root, "components", name, "application.yaml")
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	fail := func(format string, a ...any) error {
		return fmt.Errorf("application.yaml of component %q: %s", name, fmt.Sprintf(format, a...))
	}
	var doc map[string]any
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return nil, fail("%v", err)
	}
	spec, _ := doc["spec"].(map[string]any)
	if len(doc) != 1 || spec == nil || len(spec) != 1 {
		return nil, fail("only spec.ignoreDifferences is supported")
	}
	list, ok := spec["ignoreDifferences"].([]any)
	if !ok || len(list) == 0 {
		return nil, fail("only spec.ignoreDifferences is supported, and it needs at least one entry")
	}
	b, err := json.Marshal(list)
	if err != nil {
		return nil, fail("%v", err)
	}
	return b, nil
}

// openStore returns a store for addr. It refuses an address that is not a loopback host with a port.
func openStore(addr string) (*ocistore.Store, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("registry %q is not host:port: %w", addr, err)
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return nil, fmt.Errorf("registry %q has no valid port", addr)
	}
	if ip, err := netip.ParseAddr(host); host != "localhost" && (err != nil || !ip.IsLoopback()) {
		return nil, fmt.Errorf("registry %q is not a loopback address: bundlectl pushes only to the mirror and to a port-forward of the store", addr)
	}
	return ocistore.New(ocistore.Client{Base: addr, Transport: storeTransport})
}

func pushArtifact(ctx context.Context, s *ocistore.Store, repo, tag string, a bundle.Artifact) error {
	if err := s.PushBlob(ctx, repo, a.ConfigDigest, a.Config); err != nil {
		return fmt.Errorf("push config to %s: %w", repo, err)
	}
	if err := s.PushBlob(ctx, repo, a.LayerDigest, a.Layer); err != nil {
		return fmt.Errorf("push layer to %s: %w", repo, err)
	}
	d, err := s.PushManifest(ctx, repo, tag, bundle.MediaTypeManifest, a.Manifest)
	if err != nil {
		return fmt.Errorf("push manifest to %s: %w", repo, err)
	}
	if d != a.Digest {
		return fmt.Errorf("push to %s gave digest %s, want %s", repo, d, a.Digest)
	}
	return nil
}

func writeJSON(out io.Writer, v any) error {
	enc := json.NewEncoder(out)
	enc.SetEscapeHTML(false)
	return enc.Encode(v)
}

func cmdSet(ctx context.Context, f flags, out io.Writer, push bool) error {
	var s *ocistore.Store
	if push {
		var err error
		if s, err = openStore(f.registry); err != nil {
			return err
		}
	}
	b, err := load(f)
	if err != nil {
		return err
	}
	if push {
		for _, c := range b.components {
			if err := pushArtifact(ctx, s, "bundles/"+f.target+"/"+c.Name, "", b.artifacts[c.Name]); err != nil {
				return err
			}
		}
	}
	return writeJSON(out, b.components)
}

// rootResult is the root bundle of a set: its digest and the base64 of its manifest.
type rootResult struct {
	Digest     string            `json:"digest"`
	Manifest   string            `json:"manifest"`
	Components map[string]string `json:"components,omitempty"`
}

func composeRoot(role string, comps []bundle.Component) (bundle.Artifact, error) {
	p := bundle.DefaultPolicy()
	r, ok := p.Roles[role]
	if !ok {
		return bundle.Artifact{}, fmt.Errorf("unknown role %q", role)
	}
	if len(r.Components) == 0 {
		return bundle.Artifact{}, fmt.Errorf("role %q has no signed root", role)
	}
	return bundle.ComposeRoot(role, bundle.Set{Components: comps}, p)
}

func cmdBootstrap(ctx context.Context, f flags, out io.Writer) error {
	s, err := openStore(f.registry)
	if err != nil {
		return err
	}
	b, err := load(f)
	if err != nil {
		return err
	}
	root, err := composeRoot(f.role, b.components)
	if err != nil {
		return err
	}
	res := rootResult{Digest: root.Digest, Manifest: base64.StdEncoding.EncodeToString(root.Manifest), Components: map[string]string{}}
	for _, c := range b.components {
		if err := pushArtifact(ctx, s, "bundles/"+c.Name, "", b.artifacts[c.Name]); err != nil {
			return err
		}
		res.Components[c.Name] = c.Digest
	}
	if err := pushArtifact(ctx, s, "bundles/root", "", root); err != nil {
		return err
	}
	if _, err := s.PushManifest(ctx, "bundles/root", "current", bundle.MediaTypeManifest, root.Manifest); err != nil {
		return fmt.Errorf("tag current: %w", err)
	}
	return writeJSON(out, res)
}

func readSet(f flags, stdin io.Reader) ([]bundle.Component, error) {
	if f.set == "" {
		return nil, errors.New("--set is required")
	}
	var r io.Reader = stdin
	if f.set != "-" {
		file, err := os.Open(f.set)
		if err != nil {
			return nil, err
		}
		defer file.Close()
		r = file
	}
	raw, err := io.ReadAll(io.LimitReader(r, maxSmallInput+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maxSmallInput {
		return nil, errors.New("set is larger than 1 MiB")
	}
	return bundle.ParseComponents(raw)
}

func cmdCompose(f flags, stdin io.Reader, out io.Writer) error {
	comps, err := readSet(f, stdin)
	if err != nil {
		return err
	}
	root, err := composeRoot(f.role, comps)
	if err != nil {
		return err
	}
	return writeJSON(out, rootResult{Digest: root.Digest, Manifest: base64.StdEncoding.EncodeToString(root.Manifest)})
}

func cmdPushRoot(ctx context.Context, f flags, stdin io.Reader, out io.Writer) error {
	s, err := openStore(f.registry)
	if err != nil {
		return err
	}
	if err := checkTarget(f.target); err != nil {
		return err
	}
	comps, err := readSet(f, stdin)
	if err != nil {
		return err
	}
	root, err := composeRoot(f.role, comps)
	if err != nil {
		return err
	}
	if err := pushArtifact(ctx, s, "bundles/"+f.target+"/root", "", root); err != nil {
		return err
	}
	return writeJSON(out, rootResult{Digest: root.Digest, Manifest: base64.StdEncoding.EncodeToString(root.Manifest)})
}

func cmdProjects(f flags, out io.Writer) error {
	p := bundle.DefaultPolicy()
	r, ok := p.Roles[f.role]
	if !ok {
		return fmt.Errorf("unknown role %q", f.role)
	}
	if len(r.AppProjects) == 0 {
		raw, err := os.ReadFile(filepath.Join(f.root, appProjectFile))
		if err != nil {
			return err
		}
		_, err = out.Write(raw)
		return err
	}
	var objs []map[string]any
	for _, name := range r.AppProjects {
		spec, err := bundle.ExpectedAppProjectSpec(f.role, name, p)
		if err != nil {
			return err
		}
		objs = append(objs, map[string]any{
			"apiVersion": "argoproj.io/v1alpha1",
			"kind":       "AppProject",
			"metadata": map[string]any{
				"name":        name,
				"namespace":   "argocd",
				"annotations": map[string]any{allowAnnotation: bundle.AllowSHA256()},
			},
			"spec": spec,
		})
	}
	body, err := bundle.Canonical(objs)
	if err != nil {
		return err
	}
	_, err = out.Write(body)
	return err
}

// cmdPubkeyPEM reads the key that mgmtd ctl pubkey prints, as its JSON line or as bare base64 of
// the 32 bytes of the Ed25519 key, and prints a PKIX PEM block.
func cmdPubkeyPEM(stdin io.Reader, out io.Writer) error {
	raw, err := io.ReadAll(io.LimitReader(stdin, maxKeyInput+1))
	if err != nil {
		return err
	}
	if len(raw) > maxKeyInput {
		return errors.New("input is larger than 4 KiB")
	}
	text := string(bytes.TrimSpace(raw))
	if strings.HasPrefix(text, "{") {
		var line map[string]json.RawMessage
		if err := json.Unmarshal([]byte(text), &line); err != nil {
			return fmt.Errorf("input is not a JSON object: %w", err)
		}
		if err := json.Unmarshal(line["spec.pub"], &text); err != nil {
			return errors.New("the JSON object has no string spec.pub")
		}
	}
	key, err := base64.StdEncoding.DecodeString(text)
	if err != nil {
		return fmt.Errorf("the key is not base64: %w", err)
	}
	if len(key) != ed25519.PublicKeySize {
		return fmt.Errorf("the key has %d bytes, want %d", len(key), ed25519.PublicKeySize)
	}
	der, err := x509.MarshalPKIXPublicKey(ed25519.PublicKey(key))
	if err != nil {
		return err
	}
	return pem.Encode(out, &pem.Block{Type: "PUBLIC KEY", Bytes: der})
}
