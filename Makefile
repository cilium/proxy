# Copyright 2017-2019 Authors of Cilium
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

include Makefile.defs

CILIUM_ENVOY_BIN = ./bazel-bin/cilium-envoy
CILIUM_ENVOY_RELEASE_BIN = ./cilium-envoy
ENVOY_BINS = \
	$(CILIUM_ENVOY_BIN) \
	$(CILIUM_ENVOY_RELEASE_BIN) \
	./bazel-bin/cilium_integration_test
CHECK_FORMAT ?= ./bazel-bin/check_format.py.runfiles/envoy/tools/check_format.py

SHELL=/bin/bash -o pipefail
BAZEL ?= $(QUIET) bazel
BAZEL_FILTER ?=
BAZEL_OPTS ?=
BAZEL_TEST_OPTS ?= --jobs=1 --test_timeout=2000
BAZEL_CACHE ?= ~/.cache/bazel
BAZEL_ARCHIVE ?= ~/bazel-cache.tar.bz2
CLANG ?= clang
CLANG_FORMAT ?= clang-format
BUILDIFIER ?= buildifier
STRIP ?= $(QUIET) strip
ISTIO_VERSION = $(shell grep "ARG ISTIO_VERSION=" Dockerfile.istio_proxy | cut -d = -f2)

DOCKER=$(QUIET)docker

BAZEL_BUILD_OPTS ?= --jobs=3

SLASH = -
ARCH=$(subst aarch64,arm64,$(subst x86_64,amd64,$(patsubst i%86,386,$(shell uname -m))))
IMAGE_ARCH = $(SLASH)$(ARCH)

DOCKERFILE_ARCH = .multi_arch

BAZEL_ARCH = $(subst x86_64,k8,$(shell uname -m))
ENVOY_LINKSTAMP_O = bazel-bin/_objs/cilium-envoy/envoy/source/common/common/version_linkstamp.o

ifdef PKG_BUILD
all: precheck install-bazel clean-bins $(CILIUM_ENVOY_RELEASE_BIN) shutdown-bazel
else
all: precheck install-bazel clean-bins envoy-default api shutdown-bazel
endif

# Fetch and install Bazel if needed
install-bazel:
	tools/install_bazel.sh `cat .bazelversion`

ifdef KEEP_BAZEL_RUNNING
shutdown-bazel:
else
shutdown-bazel:
	$(BAZEL) shutdown
endif

SOURCE_VERSION :=

# Use git only if in a Git repo
ifneq ($(wildcard $(dir $(lastword $(MAKEFILE_LIST)))/.git),)
	SOURCE_VERSION := $(shell git rev-parse HEAD)
else
	SOURCE_VERSION := $(shell cat SOURCE_VERSION)
endif

DOCKER_IMAGE_TAG:=$(SOURCE_VERSION)
DOCKER_ARCH_TAG:=$(DOCKER_IMAGE_TAG)$(IMAGE_ARCH)
DOCKER_BUILD_OPTS ?=
ifdef DOCKER_BUILDX
DOCKER=$(QUIET)DOCKER_BUILDKIT=1 docker buildx
DOCKER_BUILDER := $(shell docker buildx ls | grep -E -e "[a-zA-Z0-9-]+ \*" | cut -d ' ' -f1)
ifneq ($(DOCKER_BUILDER),default)
	DOCKER_BUILD_OPTS += --push --platform=linux/arm64,linux/amd64
	DOCKER_ARCH_TAG:=$(SOURCE_VERSION)
endif
$(info Using Docker Buildx builder "$(DOCKER_BUILDER)" with build flags "$(DOCKER_BUILD_OPTS)".)
endif

docker-image-builder: Dockerfile.builder clean
	$(DOCKER) build -f $< -t "quay.io/cilium/cilium-envoy-builder:$(DOCKER_ARCH_TAG)" .

docker-image-envoy: Dockerfile clean
	@$(ECHO_GEN) docker-image-envoy
	$(DOCKER) build $(DOCKER_BUILD_OPTS) --build-arg BAZEL_BUILD_OPTS="$(BAZEL_BUILD_OPTS)" -t "quay.io/cilium/cilium-envoy:$(DOCKER_ARCH_TAG)" .
	$(QUIET)echo "Push like this when ready:"
	$(QUIET)echo "docker push quay.io/cilium/cilium-envoy:$(DOCKER_ARCH_TAG)"

#Build multi-arch Envoy image builder
docker-image-builder-multiarch: Dockerfile.builder$(DOCKERFILE_ARCH) clean
	$(DOCKER) build -f $< -t "quay.io/cilium/cilium-envoy-builder-dev:$(SOURCE_VERSION)$(IMAGE_ARCH)" --build-arg ARCH=$(ARCH) .
	$(DOCKER) tag "quay.io/cilium/cilium-envoy-builder-dev:$(SOURCE_VERSION)$(IMAGE_ARCH)" \
		"quay.io/cilium/cilium-envoy-builder-dev:latest$(IMAGE_ARCH)"
ifeq ($(ARCH),amd64)
	$(DOCKER) tag "quay.io/cilium/cilium-envoy-builder-dev:$(SOURCE_VERSION)$(IMAGE_ARCH)" \
		"quay.io/cilium/cilium-envoy-builder-dev:$(SOURCE_VERSION)"
	$(DOCKER) tag "quay.io/cilium/cilium-envoy-builder-dev:$(SOURCE_VERSION)" \
		"quay.io/cilium/cilium-envoy-builder-dev:latest"
endif

#Build multi-arch Envoy image
docker-image-envoy-multiarch: Dockerfile$(DOCKERFILE_ARCH) clean
	@$(ECHO_GEN) docker-image-envoy
	$(DOCKER) build -t "quay.io/cilium/cilium-envoy:$(SOURCE_VERSION)$(IMAGE_ARCH)" \
	          -f Dockerfile$(DOCKERFILE_ARCH) .
	$(DOCKER) tag "quay.io/cilium/cilium-envoy:$(SOURCE_VERSION)$(IMAGE_ARCH)" \
		"quay.io/cilium/cilium-envoy:latest$(IMAGE_ARCH)"
ifeq ($(ARCH),amd64)
	$(DOCKER) tag "quay.io/cilium/cilium-envoy:$(SOURCE_VERSION)$(IMAGE_ARCH)" \
		"quay.io/cilium/cilium-envoy:$(SOURCE_VERSION)"
	$(DOCKER) tag "quay.io/cilium/cilium-envoy:$(SOURCE_VERSION)$(IMAGE_ARCH)" \
		"quay.io/cilium/cilium-envoy:latest"
endif
	$(QUIET)echo "Push like this when ready:"
	$(QUIET)echo "docker push quay.io/cilium/cilium-envoy:$(SOURCE_VERSION)$(IMAGE_ARCH)"
ifeq ($(ARCH),amd64)
	$(QUIET)echo "docker push quay.io/cilium/cilium-envoy:$(SOURCE_VERSION)"
	$(QUIET)echo "docker push quay.io/cilium/cilium-envoy:latest"
endif

#Push multi-arch support with fat-manifest:

envoy-builder-manifest:
	tools/push_manifest.sh cilium-envoy-builder $(DOCKER_IMAGE_TAG)
	tools/push_manifest.sh cilium-envoy-builder latest

docker-envoy-manifest:
	tools/push_manifest.sh cilium-envoy $(DOCKER_IMAGE_TAG)
	tools/push_manifest.sh cilium-envoy latest

#Push multi-arch support with images uploaded:
envoy-builder-image-manifest:
	tools/push_manifest.sh -i cilium-envoy-builder $(DOCKER_IMAGE_TAG)
	tools/push_manifest.sh -i cilium-envoy-builder latest

docker-envoy-image-manifest:
	tools/push_manifest.sh -i cilium-envoy $(DOCKER_IMAGE_TAG)
	tools/push_manifest.sh -i cilium-envoy latest

debug: envoy-debug

api: force-non-root Makefile.api
	$(MAKE) -f Makefile.api all

bazel-bin-fastbuild: force-non-root
	-rm -f bazel-bin
	ln -s $(shell bazel info bazel-bin) bazel-bin

envoy-default: bazel-bin-fastbuild
	@$(ECHO_BAZEL)
	-rm -f ${ENVOY_LINKSTAMP_O}
	$(BAZEL) $(BAZEL_OPTS) build $(BAZEL_BUILD_OPTS) //:cilium-envoy $(BAZEL_FILTER)

# Allow root build for release
bazel-bin-opt: force
	-rm -f bazel-bin
	ln -s $(shell bazel info -c opt bazel-bin) bazel-bin

$(CILIUM_ENVOY_BIN): bazel-bin-opt
	@$(ECHO_BAZEL)
	-rm -f ${ENVOY_LINKSTAMP_O}
	$(BAZEL) $(BAZEL_OPTS) build $(BAZEL_BUILD_OPTS) -c opt //:cilium-envoy $(BAZEL_FILTER)

$(CILIUM_ENVOY_RELEASE_BIN): $(CILIUM_ENVOY_BIN)
	$(STRIP) -o $(CILIUM_ENVOY_RELEASE_BIN) $(CILIUM_ENVOY_BIN)

docker-istio-proxy: Dockerfile.istio_proxy envoy_bootstrap_tmpl.json
	@$(ECHO_GEN) docker-istio-proxy
	$(DOCKER) build -f $< -t cilium/istio_proxy:$(ISTIO_VERSION) .
	$(QUIET)echo "Push like this when ready:"
	$(QUIET)echo "docker push cilium/istio_proxy:$(ISTIO_VERSION)"

bazel-bin-dbg: force-non-root
	-rm -f bazel-bin
	ln -s $(shell bazel info -c dbg bazel-bin) bazel-bin

envoy-debug: bazel-bin-dbg
	@$(ECHO_BAZEL)
	-rm -f ${ENVOY_LINKSTAMP_O}
	$(BAZEL) $(BAZEL_OPTS) build $(BAZEL_BUILD_OPTS) -c dbg //:cilium-envoy $(BAZEL_FILTER)

$(CHECK_FORMAT): force-non-root
	$(BAZEL) $(BAZEL_OPTS) build $(BAZEL_BUILD_OPTS) //:check_format.py

install: force-root
	$(INSTALL) -m 0755 -d $(DESTDIR)$(BINDIR)
	$(INSTALL) -m 0755 -T $(CILIUM_ENVOY_BIN) $(DESTDIR)$(BINDIR)/cilium-envoy
# Strip only non-debug builds
ifeq "$(findstring -dbg,$(realpath bazel-bin))" ""
ifeq "$(NOSTRIP)" ""
	$(STRIP) $(DESTDIR)$(BINDIR)/cilium-envoy
endif
endif

bazel-archive: force-non-root tests clean-bins
	-sudo rm -f $(BAZEL_ARCHIVE)
	echo "Archiving bazel cache ($(BAZEL_CACHE)), this will take some time..."
	cd $(dir $(BAZEL_CACHE)) && sudo tar cjf $(BAZEL_ARCHIVE) --atime-preserve=system $(notdir $(BAZEL_CACHE))

bazel-clean-archive: force-non-root veryclean bazel-archive

bazel-restore: $(BAZEL_ARCHIVE)
	echo "Clearing & restoring bazel archive ($(BAZEL_ARCHIVE))..."
	-sudo rm -Rf $(BAZEL_CACHE)
	-mkdir $(dir $(BAZEL_CACHE))
	cd $(dir $(BAZEL_CACHE)) && sudo tar xjf $(BAZEL_ARCHIVE) --warning=no-timestamp

# Remove the binaries to get fresh version SHA
clean-bins: force
	@$(ECHO_CLEAN) $(notdir $(shell pwd))
	-$(QUIET) rm -f $(ENVOY_BINS)

clean: force clean-bins
	@$(ECHO_CLEAN) $(notdir $(shell pwd))
	-rm .dockerignore
	git status
	@echo "Bazel clean skipped, try 'make veryclean' instead."

veryclean: force clean-bins
	-sudo $(BAZEL) $(BAZEL_OPTS) clean
	-sudo rm -Rf $(BAZEL_CACHE)

precheck:
	tools/check_repositories.sh

check: $(CHECK_FORMAT) force-non-root
	CLANG_FORMAT=$(CLANG_FORMAT) BUILDIFIER=$(BUILDIFIER) $(CHECK_FORMAT) --add-excluded-prefixes="./linux/" check

fix: $(CHECK_FORMAT) force-non-root
	CLANG_FORMAT=$(CLANG_FORMAT) BUILDIFIER=$(BUILDIFIER) $(CHECK_FORMAT) --add-excluded-prefixes="./linux/" fix

# Run tests using the fastbuild by default.
tests: force-non-root
	$(BAZEL) $(BAZEL_OPTS) test $(BAZEL_BUILD_OPTS) -c fastbuild //:envoy_binary_test $(BAZEL_FILTER)
	$(BAZEL) $(BAZEL_OPTS) test $(BAZEL_BUILD_OPTS) -c fastbuild $(BAZEL_TEST_OPTS) //:cilium_integration_test $(BAZEL_FILTER)

debug-tests: force-non-root
	$(BAZEL) $(BAZEL_OPTS) test $(BAZEL_BUILD_OPTS) -c debug $(BAZEL_TEST_OPTS) //:envoy_binary_test $(BAZEL_FILTER)
	$(BAZEL) $(BAZEL_OPTS) test $(BAZEL_BUILD_OPTS) -c debug $(BAZEL_TEST_OPTS) //:cilium_integration_test $(BAZEL_FILTER)

.PHONY: \
	install-bazel \
	shutdown-bazel \
	bazel-restore \
	docker-istio-proxy \
	force \
	force-non-root \
	force-root

force :;

force-root:
ifndef PKG_BUILD
ifneq ($(USER),root)
	$(error This target must be run as root!)
endif
endif

force-non-root:
ifeq ($(USER),root)
	$(error This target cannot be run as root!)
endif
