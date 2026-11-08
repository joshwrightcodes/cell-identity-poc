package topology

import (
	"net/netip"
	"strings"
	"testing"
)

func reserved() []netip.Prefix {
	return []netip.Prefix{
		netip.MustParsePrefix("172.18.0.0/16"),
		netip.MustParsePrefix("192.168.5.0/24"),
	}
}

func cluster(name, pod, svc string) Cluster {
	return Cluster{
		Name:          name,
		PodSubnet:     pod,
		ServiceSubnet: svc,
		Issuer:        "https://" + name + ".issuer.poc.internal",
	}
}

func TestValidateAcceptsHarnessTopology(t *testing.T) {
	topo, err := Load("../../harness/topology.yaml")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if err := topo.Validate(reserved()); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if got := len(topo.Clusters); got != 5 {
		t.Fatalf("clusters = %d, want 5", got)
	}
	c, ok := topo.Cluster("dev-cell-1")
	if !ok || c.PodSubnet != "10.20.0.0/16" || c.ServiceSubnet != "10.120.0.0/16" {
		t.Fatalf("Cluster(dev-cell-1) = %+v, %v", c, ok)
	}
	if _, ok := topo.Cluster("missing"); ok {
		t.Fatal("Cluster(missing) found a cluster")
	}
}

func TestValidateAcceptsIPv6Reserved(t *testing.T) {
	topo := &Topology{Clusters: []Cluster{cluster("a", "10.1.0.0/16", "10.2.0.0/16")}}
	res := append(reserved(), netip.MustParsePrefix("fc00:f853:ccd:e793::/64"))
	if err := topo.Validate(res); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	topo.Clusters[0].PodSubnet = "fc00:f853:ccd:e793:1::/80"
	err := topo.Validate(res)
	if err == nil || !strings.Contains(err.Error(), "fc00:f853:ccd:e793:1::/80") ||
		!strings.Contains(err.Error(), "fc00:f853:ccd:e793::/64") {
		t.Fatalf("Validate = %v, want IPv6 overlap naming both prefixes", err)
	}
}

func TestValidateRejectsOverlap(t *testing.T) {
	tests := []struct {
		name     string
		clusters []Cluster
		want     [2]string
	}{
		{
			name:     "pod and service in one cluster",
			clusters: []Cluster{cluster("a", "10.1.0.0/16", "10.1.128.0/17")},
			want:     [2]string{"10.1.0.0/16", "10.1.128.0/17"},
		},
		{
			name: "two clusters",
			clusters: []Cluster{
				cluster("a", "10.1.0.0/16", "10.101.0.0/16"),
				cluster("b", "10.2.0.0/16", "10.1.4.0/24"),
			},
			want: [2]string{"10.1.0.0/16", "10.1.4.0/24"},
		},
		{
			name:     "reserved prefix",
			clusters: []Cluster{cluster("a", "10.1.0.0/16", "172.18.5.0/24")},
			want:     [2]string{"172.18.5.0/24", "172.18.0.0/16"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := (&Topology{Clusters: tt.clusters}).Validate(reserved())
			if err == nil {
				t.Fatal("Validate returned nil")
			}
			for _, p := range tt.want {
				if !strings.Contains(err.Error(), p) {
					t.Errorf("error %q does not name %s", err, p)
				}
			}
		})
	}
}

func TestValidateRejectsBadPrefix(t *testing.T) {
	topo := &Topology{Clusters: []Cluster{cluster("a", "10.1.0.0", "10.2.0.0/16")}}
	if err := topo.Validate(nil); err == nil {
		t.Fatal("Validate accepted an address with no prefix length")
	}
}

func TestValidateRejectsBadNames(t *testing.T) {
	tests := []struct {
		name     string
		clusters []Cluster
	}{
		{"empty", []Cluster{cluster("", "10.1.0.0/16", "10.2.0.0/16")}},
		{"duplicate", []Cluster{
			cluster("a", "10.1.0.0/16", "10.2.0.0/16"),
			func() Cluster {
				c := cluster("a", "10.3.0.0/16", "10.4.0.0/16")
				c.Issuer = "https://other.issuer.poc.internal"
				return c
			}(),
		}},
		{"upper case", []Cluster{cluster("Dev", "10.1.0.0/16", "10.2.0.0/16")}},
		{"underscore", []Cluster{cluster("dev_cp", "10.1.0.0/16", "10.2.0.0/16")}},
		{"leading hyphen", []Cluster{cluster("-dev", "10.1.0.0/16", "10.2.0.0/16")}},
		{"too long", []Cluster{cluster(strings.Repeat("a", 64), "10.1.0.0/16", "10.2.0.0/16")}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := (&Topology{Clusters: tt.clusters}).Validate(nil); err == nil {
				t.Fatal("Validate returned nil")
			}
		})
	}
}

func TestValidateRejectsSharedIssuer(t *testing.T) {
	a := cluster("a", "10.1.0.0/16", "10.2.0.0/16")
	b := cluster("b", "10.3.0.0/16", "10.4.0.0/16")
	b.Issuer = a.Issuer
	err := (&Topology{Clusters: []Cluster{a, b}}).Validate(nil)
	if err == nil || !strings.Contains(err.Error(), a.Issuer) {
		t.Fatalf("Validate = %v, want an error naming the issuer", err)
	}
}
