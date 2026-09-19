ARG GO_VERSION=1.27
ARG ALPINE_VERSION=3.23

FROM golang:${GO_VERSION}-alpine${ALPINE_VERSION} AS builder

WORKDIR /app

RUN apk add --no-cache \
    build-base \
    libvirt-dev \
    nodejs \
    npm \
    pkgconf

RUN npm install -g typescript@5.5.4

ENV GOOS=linux \
    GOARCH=amd64


# Copy module files first (better caching). go.mod replaces the SauronAgent
# module with the ./SauronAgent tree, so its module files are needed as well.
COPY go.mod go.sum  ./
COPY SauronAgent/go.mod SauronAgent/go.sum SauronAgent/
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download


# Copy source; from SauronAgent only the packages the embedded collector needs.
COPY cmd cmd
COPY internal internal
COPY SauronAgent/collector SauronAgent/collector
COPY SauronAgent/internal SauronAgent/internal
COPY ui ui
COPY tsconfig.json ./

RUN tsc -p tsconfig.json
# Build
RUN --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=1 go build -o /app/devbox-gateway ./cmd/devbox-gateway


# ---------- runtime stage ----------
FROM alpine:${ALPINE_VERSION} AS runtime

WORKDIR /app

RUN apk add --no-cache \
    ca-certificates \
    libvirt-libs

COPY --from=builder /app/devbox-gateway /app/devbox-gateway

EXPOSE 443


ENTRYPOINT ["/app/devbox-gateway"]
