// Package hostsvc is the one provisioning path for harness clusters. It
// creates, describes and deletes kind clusters from the topology.
package hostsvc

import (
	"fmt"

	"sigs.k8s.io/kind/pkg/apis/config/v1alpha4"

	"github.com/joshwrightcodes/cell-identity-poc/internal/topology"
)

// KindConfig returns the kind configuration for one topology cluster.
func KindConfig(c topology.Cluster, nodeImage string) *v1alpha4.Cluster {
	patch := fmt.Sprintf(`kind: ClusterConfiguration
apiServer:
  extraArgs:
    - name: service-account-issuer
      value: %q
    - name: service-account-max-token-expiration
      value: "1h"
    - name: service-account-extend-token-expiration
      value: "false"
`, c.Issuer)

	return &v1alpha4.Cluster{
		TypeMeta: v1alpha4.TypeMeta{Kind: "Cluster", APIVersion: "kind.x-k8s.io/v1alpha4"},
		Name:     c.Name,
		Networking: v1alpha4.Networking{
			PodSubnet:     c.PodSubnet,
			ServiceSubnet: c.ServiceSubnet,
		},
		Nodes: []v1alpha4.Node{{
			Role:  v1alpha4.ControlPlaneRole,
			Image: nodeImage,
		}},
		KubeadmConfigPatches: []string{patch},
	}
}
