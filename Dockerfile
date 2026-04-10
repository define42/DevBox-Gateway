ARG GO_VERSION=1.25
ARG ALPINE_VERSION=3.22

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


# Copy module files first (better caching)
COPY go.mod go.sum  ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download


# Copy source
COPY *.go ./
COPY internal internal
COPY static static
COPY ui ui
COPY tsconfig.json ./

RUN tsc -p tsconfig.json
# Build
RUN --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=1 go build -o /app/remotegateway


# ---------- runtime stage ----------
FROM alpine:${ALPINE_VERSION} AS runtime

WORKDIR /app

RUN apk add --no-cache \
    ca-certificates \
    libvirt-libs

COPY --from=builder /app/remotegateway /app/remotegateway

EXPOSE 443


ENTRYPOINT ["/app/remotegateway"]
