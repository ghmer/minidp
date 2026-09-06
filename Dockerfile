# syntax=docker/dockerfile:1

# ---- build stage ------------------------------------------------------------
FROM golang:1.27-alpine AS build
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /minidp .

# ---- runtime stage ----------------------------------------------------------
FROM alpine:latest

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
