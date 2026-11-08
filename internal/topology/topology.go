// Package topology describes the clusters of the PoC harness and checks that
// their addresses and names cannot collide.
package topology

import (
	"fmt"
	"net/netip"
	"os"
	"regexp"

	"sigs.k8s.io/yaml"
)

// Cluster is one kind cluster of the harness.
type Cluster struct {
	Name          string   `json:"name"`
	PodSubnet     string   `json:"podSubnet"`
	ServiceSubnet string   `json:"serviceSubnet"`
	Issuer        string   `json:"issuer"`
	Components    []string `json:"components,omitempty"`
}

// Topology is the full set of harness clusters and the node image they share.
type Topology struct {
	NodeImage string    `json:"nodeImage"`
	Clusters  []Cluster `json:"clusters"`
}

var nodeImagePinned = regexp.MustCompile(`^[^@\s]+@sha256:[0-9a-f]{64}$`)

var dnsLabel = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$`)

// Load reads a topology from a YAML file. Unknown fields are an error.
func Load(path string) (*Topology, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read topology: %w", err)
	}
	var t Topology
	if err := yaml.UnmarshalStrict(data, &t); err != nil {
		return nil, fmt.Errorf("parse topology %s: %w", path, err)
	}
	return &t, nil
}

// Cluster returns the cluster with the given name.
func (t *Topology) Cluster(name string) (Cluster, bool) {
	for _, c := range t.Clusters {
		if c.Name == name {
			return c, true
		}
	}
	return Cluster{}, false
}

type claim struct {
	owner  string
	prefix netip.Prefix
}

// Validate checks the node image pin, cluster names, issuers and subnets. No subnet may overlap
// another subnet or a reserved prefix. Both IPv4 and IPv6 prefixes are checked.
func (t *Topology) Validate(reserved []netip.Prefix) error {
	if !nodeImagePinned.MatchString(t.NodeImage) {
		return fmt.Errorf("node image %q is not pinned by an @sha256 digest", t.NodeImage)
	}
	names := map[string]bool{}
	issuers := map[string]string{}
	var claims []claim

	for _, r := range reserved {
		claims = append(claims, claim{owner: "reserved", prefix: r})
	}
	for _, c := range t.Clusters {
		if !dnsLabel.MatchString(c.Name) {
			return fmt.Errorf("cluster name %q is not a DNS label", c.Name)
		}
		if names[c.Name] {
			return fmt.Errorf("cluster name %q appears twice", c.Name)
		}
		names[c.Name] = true

		if c.Issuer == "" {
			return fmt.Errorf("cluster %s has no issuer", c.Name)
		}
		if other, ok := issuers[c.Issuer]; ok {
			return fmt.Errorf("clusters %s and %s share the issuer %s", other, c.Name, c.Issuer)
		}
		issuers[c.Issuer] = c.Name

		for _, s := range []struct{ kind, value string }{
			{"pod subnet", c.PodSubnet},
			{"service subnet", c.ServiceSubnet},
		} {
			p, err := netip.ParsePrefix(s.value)
			if err != nil {
				return fmt.Errorf("cluster %s %s %q: %w", c.Name, s.kind, s.value, err)
			}
			if p != p.Masked() {
				return fmt.Errorf("cluster %s %s %q has host bits set, want %s", c.Name, s.kind, s.value, p.Masked())
			}
			claims = append(claims, claim{owner: c.Name + " " + s.kind, prefix: p})
		}
	}

	for i, a := range claims {
		for _, b := range claims[i+1:] {
			if a.prefix.Overlaps(b.prefix) {
				return fmt.Errorf("%s %s overlaps %s %s", a.owner, a.prefix, b.owner, b.prefix)
			}
		}
	}
	return nil
}
