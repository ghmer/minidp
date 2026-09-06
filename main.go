// Command minidp is a minimal OIDC/OAuth2 identity provider implementing the
// public-client Authorization Code flow with PKCE (S256). It issues signed
// access tokens, id tokens and rotating refresh tokens, and is designed to work
// out of the box as the IdP for github.com/ghmer/rego-adventure.
//
// Configuration is done entirely through environment variables, see the
// README.md for the full list.
package main

import (
	"log/slog"
	"net/http"
	"os"
	"time"

	"minidp/internal/idp"
)

func main() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, nil)))

	cfg := idp.LoadConfig()
	server, err := idp.New(cfg)
	if err != nil {
		slog.Error("failed to initialise identity provider", "error", err)
		os.Exit(1)
	}

	addr := cfg.Host + ":" + cfg.Port
	slog.Info("listening", "addr", addr, "issuer", cfg.Issuer)
	srv := &http.Server{
		Addr:              addr,
		Handler:           server.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	if err := srv.ListenAndServe(); err != nil {
		slog.Error("server exited", "error", err)
		os.Exit(1)
	}
}
