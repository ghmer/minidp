// Command minidp is a minimal OIDC/OAuth2 identity provider. Every
// registered client — declared in the clients file, with its own redirect
// policy, audience and user accounts — speaks the Authorization Code flow
// with PKCE for public clients and, for confidential clients, the
// confidential-client flow with client authentication (client_secret_basic /
// client_secret_post) at the token endpoint. Clients and users are managed
// with the bundled clientctl tool.
//
// Besides serving, minidp supports one offline command for staged signing-key
// rotation:
//
//	minidp rotate-keys
//
// It requires IDP_KEY_DIR, marks the currently active signing key as
// retiring (still published in the JWKS so outstanding tokens verify until
// the retention horizon passes) and activates a fresh key. The next server
// start picks up the new material.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ghmer/minidp/internal/idp"
)

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "rotate-keys":
			if err := rotateKeys(); err != nil {
				slog.Error("key rotation failed", "error", err)
				os.Exit(1)
			}
			return
		case "help", "-h", "--help":
			usage()
			return
		default:
			fmt.Fprintf(os.Stderr, "unknown argument %q\n\n", os.Args[1])
			usage()
			os.Exit(2)
		}
	}

	cfg, err := idp.LoadConfig()
	if err != nil {
		slog.Error("configuration error", "error", err)
		os.Exit(1)
	}
	srv, err := idp.New(&cfg)
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

// rotateKeys runs the offline rotation command: it resolves the retiring-key
// retention horizon (IDP_KEY_RETENTION, defaulting to the configured token
// TTLs plus clock-skew margin) and stages the rotation inside IDP_KEY_DIR.
func rotateKeys() error {
	retention, err := idp.LoadKeyRetention()
	if err != nil {
		return fmt.Errorf("resolve key retention: %w", err)
	}
	if err := idp.RotateKeys(os.Getenv("IDP_KEY_DIR"), retention); err != nil {
		return fmt.Errorf("rotate signing keys: %w", err)
	}
	return nil
}

// usage prints the command summary.
func usage() {
	fmt.Fprint(os.Stderr, `minidp — a minimal OIDC/OAuth2 identity provider

Usage:
  minidp                    serve the IdP (configured via IDP_* environment variables)
  minidp rotate-keys        stage a signing-key rotation inside IDP_KEY_DIR
  minidp help               print this summary

rotate-keys marks the active signing key as retiring (still published in the
JWKS so outstanding tokens verify until the retention horizon passes) and
activates a fresh key; the next server start picks up the new material. The
retention horizon is IDP_KEY_RETENTION (seconds) or, by default, the sum of
IDP_ACCESS_TOKEN_TTL and IDP_REFRESH_TOKEN_TTL plus a five-minute skew margin.
`)
}
