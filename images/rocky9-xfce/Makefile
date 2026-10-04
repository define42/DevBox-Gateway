VERSION ?= 0.0.0
IMAGE_VERSION ?= $(VERSION)
RECIPE_DIR := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
OUTPUT := $(RECIPE_DIR)/../../dist/images/rocky9-xfce/rocky9-xfce-v$(IMAGE_VERSION).img
QEMU_SYSTEM ?= qemu-system-x86_64
RUN_MEMORY ?= 4096
RUN_CPUS ?= 2
RUN_SSH_PORT ?= 2222
RUN_RDP_PORT ?= 3390
RUN_ACCEL := $(if $(wildcard /dev/kvm),-enable-kvm -cpu host,)
RUN_QEMU_ARGS ?=

.PHONY: all build check test run clean

all: build

# Local and CI builds share checksum verification, packaging and compression.
build:
	bash "$(RECIPE_DIR)/build.sh" "$(IMAGE_VERSION)"

check:
	bash "$(RECIPE_DIR)/build.sh" --check

test:
	bash "$(RECIPE_DIR)/smoke-test.sh" "$(OUTPUT)"

run:
	@command -v $(QEMU_SYSTEM) >/dev/null || { echo "Missing $(QEMU_SYSTEM)" >&2; exit 1; }
	@test -f "$(OUTPUT)" || { echo "Run 'make build' first." >&2; exit 1; }
	$(QEMU_SYSTEM) $(RUN_ACCEL) \
		-m $(RUN_MEMORY) -smp $(RUN_CPUS) \
		-drive "file=$(OUTPUT),format=qcow2,if=virtio,snapshot=on" \
		-nic user,model=virtio-net-pci,hostfwd=tcp::$(RUN_SSH_PORT)-:22,hostfwd=tcp::$(RUN_RDP_PORT)-:3389 \
		-serial mon:stdio -display none -no-reboot $(RUN_QEMU_ARGS)

clean:
	rm -f -- "$(OUTPUT)" "$(OUTPUT).sha256" "$(OUTPUT).manifest.json"
