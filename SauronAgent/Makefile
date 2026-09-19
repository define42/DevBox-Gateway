# SauronAgent -- build, test and packaging.
#
#   make build     both binaries into ./bin
#   make test      unit tests
#   make fuzz      a short run of every fuzz target in the tree
#   make install   binaries, systemd units, sysusers/tmpfiles, example configs
#
# Nothing here needs a tool that is not in the Go distribution: a security
# agent whose build depends on a linter downloaded at build time has a supply
# chain nobody reviewed. "make lint" is therefore go vet and nothing else.

MODULE := github.com/define42/SauronAgent

# VERSION is compiled into the binaries and reported to the collector in the
# HELLO message, which is the only way to tell from the host which build a
# guest is running. git describe marks a dirty tree so an unreproducible build
# says so in its own telemetry.
VERSION ?= $(shell git describe --tags --dirty --always 2>/dev/null || echo dev)

GO           ?= go
GOOS         ?= linux
GOARCH       ?= amd64
BINDIR       ?= bin
FUZZTIME     ?= 20s
COVERPROFILE ?= coverage.out

# CGO is off. The binaries are copied into guests whose libc is not the build
# host's, and an agent that will not start because of a symbol version is a
# guest that is silently not being audited. It also keeps the dynamic loader
# out of the attack surface of a process that holds CAP_AUDIT_READ.
GOBUILDENV := CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH)

# -s -w drop the symbol and DWARF tables; -trimpath keeps build-host paths out
# of the binary. The version string above, not the symbol table, is what
# identifies a build in the field.
LDFLAGS := -s -w -X $(MODULE)/internal/identity.Version=$(VERSION)

GOFILES := $(shell find . -name '*.go' -not -path './.git/*')

# Installation layout. The systemd units ship with ExecStart=/usr/bin/..., so
# PREFIX=/usr is the combination that works out of the box; a different PREFIX
# means editing ExecStart= to match. DESTDIR is for package builds.
PREFIX      ?= /usr
DESTDIR     ?=
SYSCONFDIR  ?= /etc
UNITDIR     ?= $(PREFIX)/lib/systemd/system
SYSUSERSDIR ?= $(PREFIX)/lib/sysusers.d
TMPFILESDIR ?= $(PREFIX)/lib/tmpfiles.d
DOCDIR      ?= $(PREFIX)/share/doc/sauronagent

.PHONY: all help build build-agent build-host test test-race vet lint fmt fuzz cover clean install

all: build

help:
	@echo "targets: build build-agent build-host test test-race vet lint fmt fuzz cover clean install"
	@echo "vars:    VERSION=$(VERSION) GOOS=$(GOOS) GOARCH=$(GOARCH) FUZZTIME=$(FUZZTIME) PREFIX=$(PREFIX)"

build: build-agent build-host

build-agent:
	$(GOBUILDENV) $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(BINDIR)/sauronagent ./cmd/sauronagent

build-host:
	$(GOBUILDENV) $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(BINDIR)/sauronhost ./cmd/sauronhost

# -count=1 defeats the test cache. A cached "ok" from a previous revision is
# not evidence that this one works.
test:
	$(GO) test ./... -count=1

# The race detector needs cgo, so this is the one target that does not build
# with CGO_ENABLED=0.
test-race:
	CGO_ENABLED=1 $(GO) test ./... -race -count=1

vet:
	$(GO) vet ./...

lint: vet

fmt:
	@changed=$$(gofmt -l -w $(GOFILES)); \
	if [ -n "$$changed" ]; then echo "reformatted:"; echo "$$changed"; fi

# A short run of every fuzz target, for CI and for a pre-commit check. It is
# not a substitute for a long soak: -fuzztime=$(FUZZTIME) per target only
# re-checks the committed corpus and explores a little past it.
#
# A package that cannot be listed is a failure, not a skip: silently running
# zero fuzz targets because a package stopped compiling is exactly the kind of
# invisible gap this project refuses to have.
fuzz:
	@fail=0; found=0; \
	pkgs=$$($(GO) list ./...) || exit 1; \
	for pkg in $$pkgs; do \
		out=$$($(GO) test -list='^Fuzz' $$pkg 2>&1); \
		if [ $$? -ne 0 ]; then \
			echo "$$out" >&2; \
			echo "FAIL: cannot list fuzz targets in $$pkg" >&2; \
			fail=1; continue; \
		fi; \
		targets=$$(echo "$$out" | grep '^Fuzz' || true); \
		for t in $$targets; do \
			found=$$((found+1)); \
			echo "==> $$pkg $$t ($(FUZZTIME))"; \
			$(GO) test $$pkg -run='^$$' -fuzz="^$$t$$" -fuzztime=$(FUZZTIME) || fail=1; \
		done; \
	done; \
	echo "fuzz: $$found target(s) run"; \
	exit $$fail

cover:
	$(GO) test ./... -count=1 -covermode=atomic -coverprofile=$(COVERPROFILE)
	@$(GO) tool cover -func=$(COVERPROFILE) | tail -n 1

clean:
	rm -rf $(BINDIR) $(COVERPROFILE)

# The agent runs on its built-in defaults and needs no configuration file. The
# collector's example is installed as a .example file: overwriting a running
# deployment's configuration from a package upgrade could silently re-enable
# something an operator turned off.
install: build
	install -D -m 0755 $(BINDIR)/sauronagent $(DESTDIR)$(PREFIX)/bin/sauronagent
	install -D -m 0755 $(BINDIR)/sauronhost $(DESTDIR)$(PREFIX)/bin/sauronhost
	install -D -m 0644 packaging/systemd/sauronagent.service $(DESTDIR)$(UNITDIR)/sauronagent.service
	install -D -m 0644 packaging/systemd/sauronhost.service $(DESTDIR)$(UNITDIR)/sauronhost.service
	install -D -m 0644 packaging/systemd/sauronagent.sysusers.conf $(DESTDIR)$(SYSUSERSDIR)/sauronagent.conf
	install -D -m 0644 packaging/systemd/sauronagent.tmpfiles.conf $(DESTDIR)$(TMPFILESDIR)/sauronagent.conf
	install -D -m 0644 examples/sauronhost.yaml $(DESTDIR)$(SYSCONFDIR)/sauronhost/sauronhost.yaml.example
	install -d $(DESTDIR)$(DOCDIR)
	install -m 0644 README.md docs/protocol.md docs/security.md docs/deployment.md examples/qemu-vsock.md $(DESTDIR)$(DOCDIR)/
	@echo
	@echo "Installed. On the guest:      systemd-sysusers && systemd-tmpfiles --create"
	@echo "                              systemctl daemon-reload && systemctl enable --now sauronagent"
	@echo "On the hypervisor:            cp $(SYSCONFDIR)/sauronhost/sauronhost.yaml.example $(SYSCONFDIR)/sauronhost/sauronhost.yaml"
	@echo "                              edit the vms: CID map, then systemctl enable --now sauronhost"
