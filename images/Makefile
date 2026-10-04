IMAGE ?= ubuntu26.04-xfce
IMAGE_VERSION ?= 0.0.0

.PHONY: image image-check image-test

image:
	bash "$(IMAGE)/build.sh" "$(IMAGE_VERSION)"

image-check:
	bash "$(IMAGE)/build.sh" --check

image-test:
	bash "$(IMAGE)/smoke-test.sh" "../dist/images/$(IMAGE)/$(IMAGE)-v$(IMAGE_VERSION).img"
