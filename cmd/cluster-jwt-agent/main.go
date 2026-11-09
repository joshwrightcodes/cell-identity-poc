// Command cluster-jwt-agent is the SPIRE agent half of the cluster_jwt NodeAttestor.
//
// With no arguments it runs as an external SPIRE plugin. SPIRE starts it and speaks gRPC to it
// over go-plugin, and the plugin logs through the SPIRE logger. With the argument "install <dir>"
// it copies its own binary into dir, so that an init container in a distroless image can hand
// the plugin to the SPIRE agent container.
package main

import (
	"os"

	"github.com/spiffe/spire-plugin-sdk/pluginmain"
	nodeattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/nodeattestor/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"

	"github.com/joshwrightcodes/cell-identity-poc/internal/clusterjwt"
	"github.com/joshwrightcodes/cell-identity-poc/internal/install"
)

const binaryName = "cluster-jwt-agent"

func main() {
	if len(os.Args) > 1 {
		os.Exit(install.Run(binaryName, os.Args[1:], os.Stdout, os.Executable))
	}
	p := clusterjwt.NewAgent()
	pluginmain.Serve(
		nodeattestorv1.NodeAttestorPluginServer(p),
		configv1.ConfigServiceServer(p),
	)
}
