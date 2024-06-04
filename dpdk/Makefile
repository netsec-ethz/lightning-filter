# Makefile for building the base image for the lightning-filter container.
#
# The base image is stored in Docker Hub (see variables below).
# To obtain the base image, run `make pull`.
#
# To change the base image,
# 1. Update the Dockerfile accordingly.
# 2. Run `make build-base-image` to build the image.
# 3. Run `make push` to push the image to Docker Hub.
# 4. Run `make update-digest` to store the SHA256 digest of the image.


# Variables
DOCKER_USERNAME = streun
DOCKER_IMAGE_NAME = lightning-filter
DOCKER_TAG = lf-base
DOCKER_IMAGE_SHA_FILE = digest.txt

.PHONY: all
all: build-base-image update-digest

build-base-image:
	@echo "Building $(DOCKER_USERNAME)/$(DOCKER_IMAGE_NAME):$(DOCKER_TAG) ."
	docker build --target lf-base -t $(DOCKER_USERNAME)/$(DOCKER_IMAGE_NAME):$(DOCKER_TAG) .

update-digest:
	@echo "Storing SHA256 digest of $(DOCKER_USERNAME)/$(DOCKER_IMAGE_NAME)"
	docker inspect --format='{{index .RepoDigests 0}}' $(DOCKER_USERNAME)/$(DOCKER_IMAGE_NAME):$(DOCKER_TAG) | cut -d '@' -f 2 > $(DOCKER_IMAGE_SHA_FILE)

# Target to pull the image from Docker Hub using the SHA256 digest
pull:
	@echo "Pulling $(DOCKER_USERNAME)/$(DOCKER_IMAGE_NAME) by SHA256 digest"
	docker pull $(DOCKER_USERNAME)/$(DOCKER_IMAGE_NAME):$(DOCKER_TAG)@$(shell cat $(DOCKER_IMAGE_SHA_FILE))

# Target to push the image to Docker Hub using the API key
# Must be logged in to Docker Hub:
# docker login -u $(DOCKER_USERNAME)
push:
	@echo "Pushing $(DOCKER_USERNAME)/$(DOCKER_IMAGE_NAME):$(DOCKER_TAG) to Docker Hub."
	docker push $(DOCKER_USERNAME)/$(DOCKER_IMAGE_NAME):$(DOCKER_TAG)
