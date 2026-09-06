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

# ---- runtime stage ----------------------------------------------------------
FROM alpine:3.22@sha256:14358309a308569c32bdc37e2e0e9694be33a9d99e68afb0f5ff33cc1f695dce

# Non-root user; the signing key lives in /data (volume or secret mount).
RUN addgroup -g 10001 minidp \
 && adduser -D -H -u 10001 -G minidp minidp \
 && mkdir /data && chown minidp:minidp /data

COPY --from=build /minidp /usr/local/bin/minidp

USER 10001:10001

ENV IDP_KEY_DIR=/data
VOLUME /data
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s \
  CMD wget -q -O /dev/null http://127.0.0.1:8080/healthz || exit 1

ENTRYPOINT ["/usr/local/bin/minidp"]
