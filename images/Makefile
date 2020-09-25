# Copyright 2020 Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

REGISTRIES ?= quay.io/cilium

PUSH ?= false

OUTPUT := "type=image"
ifeq ($(PUSH),true)
OUTPUT := "type=registry,push=true"
endif

all-images: lint cilium-envoy-image

lint:
	scripts/lint.sh

.buildx_builder:
	# see https://github.com/docker/buildx/issues/308
	mkdir -p ../.buildx
	docker buildx create --platform linux/amd64,linux/arm64 --buildkitd-flags '--debug' > $@

.PHONY: cilium-envoy-image

cilium-envoy-image: .buildx_builder
	if [[ -n "$${GCP_SERVICE_ACCOUNT_KEY+x}" ]] ; then \
	  echo "$${GCP_SERVICE_ACCOUNT_KEY}" | base64 -d > /tmp/gcp-service-account-key.json ;\
	  SECRETS="${SECRETS};id=gcp-service-account-key,src=/tmp/gcp-service-account-key.json;" ;\
	  BUILD_ARGS="${BUILD_ARGS};BAZEL_BUILD_EXTRA_OPTS=--remote_cache=https://storage.googleapis.com/cilium-bazel-build-cache --google_credentials=gcp-service-account-key.json;" ;\
        fi ;\
	if [[ -n "$${PRUNE_DISK_CACHE+x}" ]] ; then \
	  BUILD_ARGS="${BUILD_ARGS};PRUNE_DISK_CACHE=${PRUNE_DISK_CACHE};" ;\
	fi ;\
	export SECRETS BUILD_ARGS ;\
	ROOT_CONTEXT=true scripts/build-image.sh cilium-envoy-dev images/cilium-envoy linux/amd64,linux/arm64 $(OUTPUT) "$$(cat .buildx_builder)" $(REGISTRIES)
