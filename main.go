// Command minidp is a minimal OIDC/OAuth2 identity provider. Every
// registered client — declared in the clients file, with its own redirect
// policy, audience and user accounts — speaks the Authorization Code flow
// with PKCE for public clients and, for confidential clients, the
// confidential-client flow with client authentication (client_secret_basic /
// client_secret_post) at the token endpoint. Clients and users are managed
// with the bundled clientctl tool.
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

func main() {
	cfg, err := idp.LoadConfig()
	if err != nil {
		slog.Error("configuration error", "error", err)
		os.Exit(1)
	}
	srv, err := idp.New(cfg)
	if err != nil {
		slog.Error("startup failed", "error", err)
		os.Exit(1)
	}

	addr := cfg.Host + ":" + cfg.Port
	httpServer := &http.Server{
		Addr:              addr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		slog.Info("http server listening", "addr", addr)
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("http server failed", "error", err)
			os.Exit(1)
		}
	}()

	// Graceful shutdown: on SIGINT/SIGTERM stop accepting new connections,
	// give in-flight requests (login round-trips, token exchanges) 10
	// seconds, then exit. In-memory state (codes, refresh tokens) is
	// intentionally dropped: clients recover by re-authorizing.
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop
	slog.Info("shutting down")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := httpServer.Shutdown(ctx); err != nil {
		slog.Error("graceful shutdown failed", "error", err)
	}
}
