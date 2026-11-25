// Command cluster-jwt-server is the SPIRE server half of the cluster_jwt NodeAttestor.
//
// With no arguments it runs as an external SPIRE plugin. SPIRE starts it and speaks gRPC to it
// over go-plugin, and the plugin logs through the SPIRE logger. With the argument "install <dir>"
// it copies its own binary into dir, so that an init container in a distroless image can hand
// the plugin to the SPIRE server container.
//
// With the argument "ban-agents" it runs the ban container that sits next to the SPIRE server. It reads the
// cells that the plugin refuses from the server configuration and bans their agents through the SPIRE
// server API:
//
//	cluster-jwt-server ban-agents [--server-config /run/spire/config/server.conf]
//	  [--socket /run/spire/sockets/api.sock] [--every 10s] [--health 127.0.0.1:8086]
//
// The trust domain comes from the server configuration. The marks file that the configuration names has
// to be readable at the same path in this container. Without it the container does not apply the
// rollback marks of the plugin: after a restore to an older spec it can ban a cell that the plugin
// admits. The deployment mounts the data directory read-only.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/spiffe/spire-plugin-sdk/pluginmain"
	nodeattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/nodeattestor/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"

	"github.com/joshwrightcodes/cell-identity-poc/internal/clusterjwt"
	"github.com/joshwrightcodes/cell-identity-poc/internal/install"
)

const binaryName = "cluster-jwt-server"

func main() {
	if len(os.Args) > 1 && os.Args[1] == banMode {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		code := banAgents(ctx, os.Args[2:], os.Stdout, realBanDeps())
		stop()
		os.Exit(code)
	}
	if len(os.Args) > 1 {
		os.Exit(install.Run(binaryName, os.Args[1:], os.Stdout, os.Executable))
	}
	p := clusterjwt.New()
	pluginmain.Serve(
		nodeattestorv1.NodeAttestorPluginServer(p),
		configv1.ConfigServiceServer(p),
	)
}
