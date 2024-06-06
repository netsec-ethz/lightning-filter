# Makefile for building the base image for the lightning-filter container.
#
# The base image is stored in Docker Hub (see variables below).
#
# When pushing to Docker Hub, you must be logged in:
# docker login -u $(DOCKER_USERNAME)
#
# When pulling from Docker Hub, the SHA256 digest uniquely identifies the image.
#
# To change the base image:
# 1. Update the Dockerfile accordingly.
# 2. Run `make build-base-image` to build the image.
# 3. Run `make push-base-image` to push the image to Docker Hub.
# 4. Run `make update-base-digest` to store the SHA256 digest of the image.

# Variables
DOCKER_USERNAME = streun
DOCKER_IMAGE_NAME = lightning-filter
TAG_BASE = $(shell cat base.version)
TAG_DEV = $(shell cat dev.version)

.PHONY: all
all: build-base-image update-digest

# Base image
build-base-image:
	@echo "Building $(DOCKER_USERNAME)/$(DOCKER_IMAGE_NAME):$(TAG_BASE) -f base.Dockerfile ."
	docker build --target lf-base -t $(DOCKER_USERNAME)/$(DOCKER_IMAGE_NAME):$(TAG_BASE) --build-arg DPDK_MINIMAL_BUILD=true -f base.Dockerfile .

pull-base-image:
	@echo "Pulling $(DOCKER_USERNAME)/$(DOCKER_IMAGE_NAME) by SHA256 digest"
	docker pull $(DOCKER_USERNAME)/$(DOCKER_IMAGE_NAME):$(TAG_BASE)@$(shell cat base.digest)

push-base-image:
	@echo "Pushing $(DOCKER_USERNAME)/$(DOCKER_IMAGE_NAME):$(TAG_BASE) to Docker Hub."
	docker push $(DOCKER_USERNAME)/$(DOCKER_IMAGE_NAME):$(TAG_BASE)

update-base-digest:
	@echo "Storing SHA256 digest of $(DOCKER_USERNAME)/$(DOCKER_IMAGE_NAME)"
	docker inspect --format='{{index .RepoDigests 0}}' $(DOCKER_USERNAME)/$(DOCKER_IMAGE_NAME):$(TAG_BASE) | cut -d '@' -f 2 > base.digest

# Development image
build-dev-image:
	@echo "Building $(DOCKER_USERNAME)/$(DOCKER_IMAGE_NAME):$(TAG_DEV) -f dev.Dockerfile"
	docker build --target lf-dev -t $(DOCKER_USERNAME)/$(DOCKER_IMAGE_NAME):$(TAG_DEV) --build-arg BASE_VERSION=$(TAG_BASE) -f dev.Dockerfile .

pull-dev-image:
	@echo "Pulling $(DOCKER_USERNAME)/$(DOCKER_IMAGE_NAME):$(TAG_DEV) by SHA256 digest"
	docker pull $(DOCKER_USERNAME)/$(DOCKER_IMAGE_NAME):$(TAG_DEV)@$(shell cat dev.digest)
	docker tag $(DOCKER_USERNAME)/$(DOCKER_IMAGE_NAME):$(TAG_DEV) lf-dev:latest

push-dev-image:
	@echo "Pushing $(DOCKER_USERNAME)/$(DOCKER_IMAGE_NAME):$(TAG_DEV) to Docker Hub."
	docker push $(DOCKER_USERNAME)/$(DOCKER_IMAGE_NAME):$(TAG_DEV)

update-dev-digest:
	@echo "Storing SHA256 digest of $(DOCKER_USERNAME)/$(DOCKER_IMAGE_NAME):$(TAG_DEV)"
	docker inspect --format='{{index .RepoDigests 0}}' $(DOCKER_USERNAME)/$(DOCKER_IMAGE_NAME):$(TAG_DEV) | cut -d '@' -f 2 > dev.digest
