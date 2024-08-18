# Makefile for building docker images and pushing them to Docker Hub.
# When pushing to Docker Hub, you must be logged in:
# docker login -u $(DOCKER_REGISTRY)
#
# When pulling from Docker Hub, the SHA256 digest uniquely identifies the image.
#
# To change the an image:
# 1. Update the Dockerfile as you like.
# 2. Run `make build-<image>` to build the image.
# 3. Run `make push-<image>` to push the image to Docker Hub.
# 4. Run `make update-<image>-digest` to store the SHA256 digest of the image.

# Docker Hub variables
DOCKER_REGISTRY = streun
DOCKER_IMAGE_NAME = lightning-filter

# With DPDK_MINIMAL_BUILD set to true, DPDK is build without host machine optimization, e.g., SSE2,
# providing better compatibility with different systems (useful for CI pipelines).
DPDK_MINIMAL_BUILD = true

.PHONY: all
all: build-base-image update-digest

# Base image
TAG_BASE = $(shell cat base.version)
build-base-image:
	@echo "Building $(DOCKER_REGISTRY)/$(DOCKER_IMAGE_NAME):$(TAG_BASE)"
	docker build --target lf-base -t $(DOCKER_REGISTRY)/$(DOCKER_IMAGE_NAME):$(TAG_BASE) \
	 --build-arg DPDK_MINIMAL_BUILD=$(DPDK_MINIMAL_BUILD) \
	 -f base.Dockerfile .

pull-base-image:
	@echo "Pulling $(DOCKER_REGISTRY)/$(DOCKER_IMAGE_NAME) by SHA256 digest"
	docker pull $(DOCKER_REGISTRY)/$(DOCKER_IMAGE_NAME):$(TAG_BASE)@$(shell cat base.digest)

push-base-image:
	@echo "Pushing $(DOCKER_REGISTRY)/$(DOCKER_IMAGE_NAME):$(TAG_BASE) to Docker Hub."
	docker push $(DOCKER_REGISTRY)/$(DOCKER_IMAGE_NAME):$(TAG_BASE)

update-base-digest:
	@echo "Storing SHA256 digest of $(DOCKER_REGISTRY)/$(DOCKER_IMAGE_NAME)"
	docker inspect --format='{{index .RepoDigests 0}}' $(DOCKER_REGISTRY)/$(DOCKER_IMAGE_NAME):$(TAG_BASE) | cut -d '@' -f 2 > base.digest

# Development image
TAG_DEV = $(shell cat dev.version)
build-dev-image:
	@echo "Building $(DOCKER_REGISTRY)/$(DOCKER_IMAGE_NAME):$(TAG_DEV)"
	docker build --target lf-dev -t $(DOCKER_REGISTRY)/$(DOCKER_IMAGE_NAME):$(TAG_DEV) \
	 --build-arg DPDK_MINIMAL_BUILD=$(DPDK_MINIMAL_BUILD) \
	 -f base.Dockerfile .

pull-dev-image:
	@echo "Pulling $(DOCKER_REGISTRY)/$(DOCKER_IMAGE_NAME):$(TAG_DEV) by SHA256 digest"
	docker pull $(DOCKER_REGISTRY)/$(DOCKER_IMAGE_NAME):$(TAG_DEV)@$(shell cat dev.digest)
	docker tag $(DOCKER_REGISTRY)/$(DOCKER_IMAGE_NAME):$(TAG_DEV) lf-dev:latest

push-dev-image:
	@echo "Pushing $(DOCKER_REGISTRY)/$(DOCKER_IMAGE_NAME):$(TAG_DEV) to Docker Hub."
	docker push $(DOCKER_REGISTRY)/$(DOCKER_IMAGE_NAME):$(TAG_DEV)

update-dev-digest:
	@echo "Storing SHA256 digest of $(DOCKER_REGISTRY)/$(DOCKER_IMAGE_NAME):$(TAG_DEV)"
	docker inspect --format='{{index .RepoDigests 0}}' $(DOCKER_REGISTRY)/$(DOCKER_IMAGE_NAME):$(TAG_DEV) | cut -d '@' -f 2 > dev.digest
