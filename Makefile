all: ui
	docker compose build

# VERSION/RELEASE feed native package metadata and output filenames. Gateway
# packages currently target x86_64/amd64; SauronAgent also accepts other arches.
VERSION  ?= 0.0.0
RELEASE  ?= 1
ARCH     ?= x86_64
DEB_ARCH ?= amd64
BINARY   := dist/devbox-gateway
GO_VERSION := $(shell awk '/^go / {print $$2; exit}' go.mod)
SAURON_RPM_GOARCH = $(patsubst x86_64,amd64,$(patsubst aarch64,arm64,$(patsubst i686,386,$(patsubst armhfp,arm,$(patsubst loongarch64,loong64,$(ARCH))))))
SAURON_DEB_GOARCH = $(patsubst i386,386,$(patsubst armhf,arm,$(patsubst ppc64el,ppc64le,$(DEB_ARCH))))

.PHONY: all build rpm deb sauron-build sauron-rpm sauron-deb lint lint2 gosec test run ui

# build compiles the UI and a native (CGO/libvirt-linked) binary into dist/.
# Requires the libvirt development headers and a C toolchain on the build host.
build: ui
	mkdir -p dist
	CGO_ENABLED=1 go build -o $(BINARY) ./cmd/devbox-gateway

# Native packages are compiled and inspected inside their distribution baseline.
# Each target installs and checks its package before exporting it to dist/.
# Never package the host-linked development binary produced by `make build`.
rpm:
	@test "$(ARCH)" = x86_64 || { echo "Gateway RPM builds support ARCH=x86_64" >&2; exit 1; }
	docker buildx build --platform linux/amd64 -f Dockerfile.native --target rpm \
		--build-arg GO_VERSION=$(GO_VERSION) --build-arg VERSION=$(VERSION) \
		--build-arg RELEASE=$(RELEASE) --output type=local,dest=dist .

deb:
	@test "$(DEB_ARCH)" = amd64 || { echo "Gateway deb builds support DEB_ARCH=amd64" >&2; exit 1; }
	docker buildx build --platform linux/amd64 -f Dockerfile.native --target deb \
		--build-arg GO_VERSION=$(GO_VERSION) --build-arg VERSION=$(VERSION) \
		--output type=local,dest=dist .

# sauron-build compiles SauronAgent's static guest agent and hypervisor collector
# with SauronAgent's own Makefile (into SauronAgent/bin), stamping VERSION into
# both binaries so the version a guest reports matches the package it came from.
sauron-build:
	$(MAKE) -C SauronAgent build VERSION=$(VERSION)

# sauron-rpm / sauron-deb package those binaries with their units, sysusers and
# tmpfiles entries, example configs, and docs into a single sauronagent package
# via the pure-Go cmd/mksauronagent helper. Derive GOARCH from package metadata
# and isolate outputs by format/architecture so parallel builds cannot mix them.
sauron-rpm:
	$(MAKE) -C SauronAgent build VERSION=$(VERSION) GOOS=linux GOARCH=$(SAURON_RPM_GOARCH) GOARM=7 BINDIR=bin/rpm-$(ARCH)
	mkdir -p dist
	go run ./cmd/mksauronagent -format rpm -version $(VERSION) -release $(RELEASE) -arch $(ARCH) -bindir SauronAgent/bin/rpm-$(ARCH)

sauron-deb:
	$(MAKE) -C SauronAgent build VERSION=$(VERSION) GOOS=linux GOARCH=$(SAURON_DEB_GOARCH) GOARM=7 BINDIR=bin/deb-$(DEB_ARCH)
	mkdir -p dist
	go run ./cmd/mksauronagent -format deb -version $(VERSION) -arch $(DEB_ARCH) -bindir SauronAgent/bin/deb-$(DEB_ARCH)

lint:
	go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest run 
lint2:
	go run github.com/golangci/golangci-lint/cmd/golangci-lint@latest run --enable=stylecheck --enable=gochecknoinits
gosec:
	go run github.com/securego/gosec/v2/cmd/gosec@v2.28.0 ./...
test:
	go test ./... -coverprofile=coverage.out -coverpkg=./...
	go tool cover -html=coverage.out -o coverage.html
run: 
	docker compose stop
	docker compose build
	docker compose up

ui:
	tsc -p tsconfig.json
