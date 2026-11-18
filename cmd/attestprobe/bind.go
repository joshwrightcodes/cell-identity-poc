package main

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/spiffe/go-spiffe/v2/spiffeid"

	"github.com/joshwrightcodes/cell-identity-poc/internal/bind"
	"github.com/joshwrightcodes/cell-identity-poc/internal/clusterjwt"
	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmtapi"
	"github.com/joshwrightcodes/cell-identity-poc/internal/satoken"
)

const (
	targetSpire  = "spire"
	targetGWBind = "gw-bind"

	bindTokenTTL = satoken.PodTokenTTL
)

// bindConfig holds the flags that only the gw-bind target reads.
type bindConfig struct {
	upstream, expectID, trustBundle, nonce string
	reuseNonce, nonceOnly                  bool
}

// bindVariants maps each variant of the gw-bind target to the audience of its token. The token
// is the same as for a good bind in every other respect.
var bindVariants = map[string]func(cell, env, nonce string) (string, error){
	"good": func(cell, _, nonce string) (string, error) { return mgmtapi.BindAudience(cell, nonce), nil },
	// The audience is that of a bind nonce that the server did not send.
	"other-nonce": func(cell, _, _ string) (string, error) {
		other, err := randomNonce()
		if err != nil {
			return "", err
		}
		return mgmtapi.BindAudience(cell, other), nil
	},
	// The audience is that of a SPIRE attestation in the environment, as a replayed token has.
	"attest-audience": func(_, env, nonce string) (string, error) { return clusterjwt.Audience(env, nonce), nil },
}

func bindVariantNames() []string { return slices.Sorted(maps.Keys(bindVariants)) }

func parseBind(cfg config, lookupEnv func(string) (string, bool)) (config, error) {
	b := cfg.bind
	switch {
	case b.upstream == "":
		return config{}, errors.New("--upstream is required")
	case b.expectID == "":
		return config{}, errors.New("--expect-id is required")
	case b.trustBundle == "":
		return config{}, errors.New("--trust-bundle is required")
	case cfg.cell == "":
		return config{}, errors.New("--cell is required")
	case cfg.timeout <= 0:
		return config{}, errors.New("--timeout must be positive")
	case b.nonceOnly && (b.nonce != "" || cfg.tokenFile != "" || b.reuseNonce):
		return config{}, errors.New("--nonce-only cannot go with --nonce, --token-file or --reuse-nonce")
	case b.nonceOnly:
		return cfg, nil
	}
	if _, ok := bindVariants[cfg.variant]; !ok {
		return config{}, fmt.Errorf("--variant must be one of %s, got %q", strings.Join(bindVariantNames(), ", "), cfg.variant)
	}
	switch {
	case (b.nonce == "") != (cfg.tokenFile == ""):
		return config{}, errors.New("--nonce and --token-file go together")
	case cfg.variant == "attest-audience" && cfg.env == "" && cfg.tokenFile == "":
		return config{}, errors.New("--env is required for --variant attest-audience")
	}
	if cfg.tokenFile == "" {
		for _, e := range []struct {
			name string
			dst  *string
		}{
			{clusterjwt.EnvPodName, &cfg.pod.name}, {clusterjwt.EnvPodUID, &cfg.pod.uid},
			{clusterjwt.EnvPodNamespace, &cfg.pod.namespace}, {clusterjwt.EnvServiceAccount, &cfg.pod.serviceAccount},
		} {
			v, ok := lookupEnv(e.name)
			if !ok || v == "" {
				return config{}, fmt.Errorf("environment variable %s is required", e.name)
			}
			*e.dst = v
		}
	}
	return cfg, nil
}

// runBind sends the requests of the gw-bind target and returns the lines to print. A refusal of
// the gateway is the result denied:<request ID>. Every other failure fails the probe.
func runBind(ctx context.Context, cfg config, d deps) (string, error) {
	id, err := spiffeid.FromString(cfg.bind.expectID)
	if err != nil {
		return "", fmt.Errorf("--expect-id: %w", err)
	}
	tlsCfg := bind.ClientTLS(bind.FileBundle(cfg.bind.trustBundle, id.TrustDomain()), id)
	client := bind.NewClient(bind.Config{Cell: cfg.cell, Upstream: cfg.bind.upstream, TLS: tlsCfg, LocalIP: cfg.source})
	defer client.Close()

	var lines []string
	nonce := cfg.bind.nonce
	if nonce == "" {
		n, err := client.Nonce(ctx)
		if err != nil {
			return "", fmt.Errorf("request a nonce: %w", err)
		}
		if err := bind.CheckNonce(cfg.cell, n); err != nil {
			return "", err
		}
		nonce = n.Nonce
		lines = append(lines, "nonce:"+n.Nonce+" "+n.Audience)
		if cfg.bind.nonceOnly {
			return strings.Join(lines, "\n"), nil
		}
	}

	token, err := bindToken(ctx, cfg, d, nonce)
	if err != nil {
		return "", err
	}
	sends := 1
	if cfg.bind.reuseNonce {
		sends = 2
	}
	for range sends {
		resp, err := client.BindWait(ctx, mgmtapi.BindRequest{Nonce: nonce, Token: token}, bind.DefaultPollEvery, nil)
		var refused *bind.Refused
		switch {
		case errors.As(err, &refused):
			lines = append(lines, "denied:"+refused.RequestID)
		case err != nil:
			return "", err
		default:
			lines = append(lines, "bound:"+resp.Status)
		}
	}
	return strings.Join(lines, "\n"), nil
}

func bindToken(ctx context.Context, cfg config, d deps, nonce string) (string, error) {
	if cfg.tokenFile != "" {
		raw, err := d.readFile(cfg.tokenFile)
		if err != nil {
			return "", fmt.Errorf("read --token-file: %w", err)
		}
		token := strings.TrimSpace(string(raw))
		if token == "" {
			return "", errors.New("--token-file is empty")
		}
		return token, nil
	}
	audience, err := bindVariants[cfg.variant](cfg.cell, cfg.env, nonce)
	if err != nil {
		return "", err
	}
	client, err := d.tokenClient()
	if err != nil {
		return "", err
	}
	token, err := satoken.Create(ctx, client, satoken.Request{
		Namespace: cfg.pod.namespace, ServiceAccount: cfg.pod.serviceAccount, PodName: cfg.pod.name, PodUID: cfg.pod.uid,
		Audience: audience, TTL: bindTokenTTL,
	})
	if err != nil {
		return "", fmt.Errorf("token request: %w", err)
	}
	return token, nil
}
