// Command minidp is a minimal OIDC/OAuth2 identity provider implementing the
// Authorization Code flow with PKCE (S256) for public clients and, with
// MINIDP_MODE=confidential, the confidential-client profile with client
// authentication at the token endpoint. It issues signed
// access tokens, id tokens and rotating refresh tokens, and is designed to work
// out of the box as the IdP for github.com/ghmer/rego-adventure.
//
// Configuration is done entirely through environment variables, see the
// README.md for the full list.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ghmer/minidp/internal/idp"
)

const shutdownGrace = 10 * time.Second

func main() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, nil)))

	cfg, err := idp.LoadConfig()
	if err != nil {
		slog.Error("invalid configuration", "error", err)
		os.Exit(1)
	}
	server, err := idp.New(cfg)
	if err != nil {
		slog.Error("failed to initialise identity provider", "error", err)
		os.Exit(1)
	}

	addr := cfg.Host + ":" + cfg.Port
	srv := &http.Server{
		Addr:              addr,
		Handler:           server.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	// Shut down gracefully on SIGTERM/SIGINT so container orchestrators can
	// drain in-flight logins and token exchanges during rolling updates.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		slog.Info("listening", "addr", addr, "issuer", cfg.Issuer)
		errCh <- srv.ListenAndServe()
	}()

	select {
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("server exited", "error", err)
			os.Exit(1)
		}
	case <-ctx.Done():
		slog.Info("shutdown signal received, draining connections")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			slog.Error("graceful shutdown failed", "error", err)
		}
	}
	slog.Info("minidp stopped")
}
