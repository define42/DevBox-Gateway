all: ui
	docker compose build

# VERSION/RELEASE/ARCH feed the rpm metadata and output filename. Override on the
# command line, e.g. `make rpm VERSION=1.4.0`. DEB_ARCH is the Debian spelling of
# ARCH (amd64 vs x86_64); override it for cross-arch deb builds.
VERSION  ?= 0.0.0
RELEASE  ?= 1
ARCH     ?= x86_64
DEB_ARCH ?= amd64
BINARY   := dist/devbox-gateway

# build compiles the UI and a native (CGO/libvirt-linked) binary into dist/.
# Requires the libvirt development headers and a C toolchain on the build host.
build: ui
	mkdir -p dist
	CGO_ENABLED=1 go build -o $(BINARY) .

# rpm packages the prebuilt binary, systemd unit, and sample env file into an RPM
# via the pure-Go cmd/mkrpm helper (no rpmbuild/spec file needed).
rpm: build
	go run ./cmd/mkrpm -version $(VERSION) -release $(RELEASE) -arch $(ARCH)

# deb packages the same artifacts into a Debian .deb via the pure-Go cmd/mkdeb
# helper (no dpkg-deb/debian tree needed).
deb: build
	go run ./cmd/mkdeb -version $(VERSION) -arch $(DEB_ARCH)

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
