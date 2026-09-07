# syntax=docker/dockerfile:1

# ---- build stage ------------------------------------------------------------
# Versioned tags AND digests, so builds are reproducible and a poisoned tag
# cannot flow into the image. Bump deliberately (go1.x.y + matching alpine).
FROM golang:1.27.1-alpine3.24@sha256:cf6fca6641884b8433441b2b0652976f975e1d0fdd26d177eaaf8596087f3125 AS build
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /minidp .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /clientctl ./cmd/clientctl

# ---- runtime stage ----------------------------------------------------------
FROM alpine:3.24.1@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b

# Non-root user; the signing key lives in /data (volume or secret mount).
RUN addgroup -g 10001 minidp \
 && adduser -D -H -u 10001 -G minidp minidp \
 && mkdir /data && chown minidp:minidp /data

# clientctl (clients-file manager) ships alongside the server; run it
# host-side with docker — see docs/clients.md
COPY --from=build /minidp /usr/local/bin/minidp
COPY --from=build /clientctl /usr/local/bin/clientctl

# Workdir anchors the fixed assets location: mounting login.css / logo.svg at
# /app/assets overrides the embedded login page branding per file (see README).
WORKDIR /app

USER 10001:10001

ENV IDP_KEY_DIR=/data
VOLUME /data
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s \
  CMD wget -q -O /dev/null http://127.0.0.1:8080/healthz || exit 1

ENTRYPOINT ["/usr/local/bin/minidp"]
