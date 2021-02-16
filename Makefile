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

# This image is used to extract proxylib/libcilium.so only for "tests" target
# This will be changed to an official image as soon as they support multi-arch
CILIUM_REF=docker.io/jrajahalme/cilium:latest

CILIUM_ENVOY_BIN = ./bazel-bin/cilium-envoy
CILIUM_ENVOY_RELEASE_BIN = ./cilium-envoy
ENVOY_BINS = \
	$(CILIUM_ENVOY_BIN) \
	$(CILIUM_ENVOY_RELEASE_BIN) \
	./bazel-bin/cilium_integration_test
CHECK_FORMAT ?= ./bazel-bin/check_format.py.runfiles/envoy/tools/code_format/check_format.py

SHELL=/bin/bash -o pipefail
BAZEL ?= $(QUIET) bazel
BAZEL_FILTER ?=
BAZEL_OPTS ?=
BAZEL_TEST_OPTS ?= --jobs=1 --test_timeout=2000
BAZEL_CACHE ?= ~/.cache/bazel
BAZEL_ARCHIVE ?= ~/bazel-cache.tar.bz2
# COMPILER_DEP:=clang.bazelrc
CLANG ?= clang
CLANG_FORMAT ?= clang-format
BUILDIFIER ?= buildifier
ISTIO_VERSION = $(shell grep "ARG ISTIO_VERSION=" Dockerfile.istio_proxy | cut -d = -f2)

DOCKER=$(QUIET)docker

# BAZEL_BUILD_OPTS ?= --jobs=3

SLASH = -
ARCH ?= $(subst aarch64,arm64,$(subst x86_64,amd64,$(patsubst i%86,386,$(shell uname -m))))
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
#	$(info $(shell git status)
else
	SOURCE_VERSION := $(shell cat SOURCE_VERSION)
endif

SOURCE_VERSION: force
	@if [ "$(SOURCE_VERSION)" != "`cat 2>/dev/null SOURCE_VERSION`" ] ; then echo "$(SOURCE_VERSION)" >SOURCE_VERSION; fi

DOCKER_IMAGE_TAG:=$(SOURCE_VERSION)
DOCKER_ARCH_TAG:=$(DOCKER_IMAGE_TAG)$(IMAGE_ARCH)

DOCKER_DEV_ACCOUNT ?= quay.io/cilium
DOCKER_BUILD_OPTS ?=
ifdef DOCKER_BUILDX
DOCKER=$(QUIET)DOCKER_BUILDKIT=1 docker buildx
DOCKER_BUILDER := $(shell docker buildx ls | grep -E -e "[a-zA-Z0-9-]+ \*" | cut -d ' ' -f1)
ifneq ($(DOCKER_BUILDER),default)
	DOCKER_BUILD_OPTS += --push
ifeq ($(ARCH),amd64)
	DOCKER_BUILD_OPTS += --platform=linux/amd64
else ifeq ($(ARCH),arm64)
	DOCKER_BUILD_OPTS += --platform=linux/arm64
else ifeq ($(ARCH),multi)
	DOCKER_BUILD_OPTS += --platform=linux/arm64,linux/amd64
	DOCKER_ARCH_TAG:=$(SOURCE_VERSION)
endif
endif
$(info Using Docker Buildx builder "$(DOCKER_BUILDER)" with build flags "$(DOCKER_BUILD_OPTS)".)
endif

.PHONY: dockerignore-builder
dockerignore-builder: dockerignore-release
	echo "/cilium/" >>.dockerignore
	echo "/linux/" >>.dockerignore
	echo "/proxylib/" >>.dockerignore

.PHONY: dockerignore-release
dockerignore-release:
	echo "/.git/" >.dockerignore
	sed -e '# Remove lines with white space, comments and files that must be passed to docker, "$$" due to make. #' \
		-e '/^[[:space:]]*$$/d' -e '/^#/d' -e '/SOURCE_VERSION/d' \
	    -e '# Apply pattern in all directories if it contains no "/", keep "!" up front. #' \
		-e '/^[^!/][^/]*$$/s<^<**/<' -e '/^![^/]*$$/s<^!<!**/<' \
	    -e '# Remove leading "./", keep "!" up front. #' \
		-e 's<^\./<<' -e 's<^!\./<!<' \
	    -e '# Append newline to the last line if missing. GNU sed does not do this automatically. #' \
		-e "$$a" \
	    .gitignore >> .dockerignore
	echo "/.gitignore" >>.dockerignore
	echo "/.clang-format" >>.dockerignore
	echo "/go/" >>.dockerignore
	echo "/go.*" >>.dockerignore
	echo "/tests/" >>.dockerignore
	echo "/Dockerfile*" >>.dockerignore
	echo "/Makefile.api" >>.dockerignore
	echo "/envoy_binary_test.sh" >>.dockerignore
	echo "/README*" >>.dockerignore
	echo "/envoy_bootstrap_v2.patch" >>.dockerignore

.PHONY: docker-image-builder
docker-image-builder: Dockerfile.builder SOURCE_VERSION dockerignore-builder
	$(DOCKER) build $(DOCKER_BUILD_OPTS) --build-arg BAZEL_BUILD_OPTS="$(BAZEL_BUILD_OPTS)" -f $< -t "$(DOCKER_DEV_ACCOUNT)/cilium-envoy-builder:$(DOCKER_ARCH_TAG)" .

# Extract the current builder reference from Dockerfile and combine with the deps build from Dockerfile.builder
# This way we do not need to maintain multiple references to the current builder
.PRECIOUS: Dockerfile.builder-refresh
Dockerfile.builder-refresh: Dockerfile.builder Dockerfile Makefile
	sed -n '/^FROM .*as builder/p' Dockerfile >$@
	sed -n '1,/^FROM base as builder/d; p; /^RUN .*make envoy-deps/q' Dockerfile.builder >>$@

.PHONY: docker-image-builder-refresh
docker-image-builder-refresh: Dockerfile.builder-refresh SOURCE_VERSION dockerignore-builder
	$(DOCKER) build $(DOCKER_BUILD_OPTS) --build-arg BAZEL_BUILD_OPTS="$(BAZEL_BUILD_OPTS)" -f $< -t "$(DOCKER_DEV_ACCOUNT)/cilium-envoy-builder:$(DOCKER_ARCH_TAG)" .

.PHONY: docker-image-envoy
docker-image-envoy: Dockerfile SOURCE_VERSION dockerignore-release
	@$(ECHO_GEN) docker-image-envoy
	$(DOCKER) build $(DOCKER_BUILD_OPTS) --build-arg BAZEL_BUILD_OPTS="$(BAZEL_BUILD_OPTS)" -t "$(DOCKER_DEV_ACCOUNT)/cilium-envoy:$(DOCKER_ARCH_TAG)" .
ifndef DOCKER_BUILDX
	$(QUIET)echo "Push like this when ready:"
	$(QUIET)echo "docker push $(DOCKER_DEV_ACCOUNT)/cilium-envoy:$(DOCKER_ARCH_TAG)"
endif

#Build multi-arch Envoy image builder
docker-image-builder-multiarch: Dockerfile.builder$(DOCKERFILE_ARCH) SOURCE_VERSION dockerignore-builder
	$(DOCKER) build -f $< -t "$(DOCKER_DEV_ACCOUNT)/cilium-envoy-builder-dev:$(SOURCE_VERSION)$(IMAGE_ARCH)" --build-arg ARCH=$(ARCH) .
	$(DOCKER) tag "$(DOCKER_DEV_ACCOUNT)/cilium-envoy-builder-dev:$(SOURCE_VERSION)$(IMAGE_ARCH)" \
		"$(DOCKER_DEV_ACCOUNT)/cilium-envoy-builder-dev:latest$(IMAGE_ARCH)"
ifeq ($(ARCH),amd64)
	$(DOCKER) tag "$(DOCKER_DEV_ACCOUNT)/cilium-envoy-builder-dev:$(SOURCE_VERSION)$(IMAGE_ARCH)" \
		"$(DOCKER_DEV_ACCOUNT)/cilium-envoy-builder-dev:$(SOURCE_VERSION)"
	$(DOCKER) tag "$(DOCKER_DEV_ACCOUNT)/cilium-envoy-builder-dev:$(SOURCE_VERSION)" \
		"$(DOCKER_DEV_ACCOUNT)/cilium-envoy-builder-dev:latest"
endif

#Build multi-arch Envoy image
docker-image-envoy-multiarch: Dockerfile$(DOCKERFILE_ARCH) SOURCE_VERSION dockerignore-release
	@$(ECHO_GEN) docker-image-envoy
	$(DOCKER) build -t "$(DOCKER_DEV_ACCOUNT)/cilium-envoy:$(SOURCE_VERSION)$(IMAGE_ARCH)" \
	          -f Dockerfile$(DOCKERFILE_ARCH) .
	$(DOCKER) tag "$(DOCKER_DEV_ACCOUNT)/cilium-envoy:$(SOURCE_VERSION)$(IMAGE_ARCH)" \
		"$(DOCKER_DEV_ACCOUNT)/cilium-envoy:latest$(IMAGE_ARCH)"
ifeq ($(ARCH),amd64)
	$(DOCKER) tag "$(DOCKER_DEV_ACCOUNT)/cilium-envoy:$(SOURCE_VERSION)$(IMAGE_ARCH)" \
		"$(DOCKER_DEV_ACCOUNT)/cilium-envoy:$(SOURCE_VERSION)"
	$(DOCKER) tag "$(DOCKER_DEV_ACCOUNT)/cilium-envoy:$(SOURCE_VERSION)$(IMAGE_ARCH)" \
		"$(DOCKER_DEV_ACCOUNT)/cilium-envoy:latest"
endif
	$(QUIET)echo "Push like this when ready:"
	$(QUIET)echo "docker push $(DOCKER_DEV_ACCOUNT)/cilium-envoy:$(SOURCE_VERSION)$(IMAGE_ARCH)"
ifeq ($(ARCH),amd64)
	$(QUIET)echo "docker push $(DOCKER_DEV_ACCOUNT)/cilium-envoy:$(SOURCE_VERSION)"
	$(QUIET)echo "docker push $(DOCKER_DEV_ACCOUNT)/cilium-envoy:latest"
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

/usr/lib/llvm-10:
	sudo apt install clang-10 llvm-10-dev clang-format-10 lld-10

clang.bazelrc: bazel/setup_clang.sh /usr/lib/llvm-10
	bazel/setup_clang.sh /usr/lib/llvm-10
	echo "build --config=clang" >> $@

bazel-bin-fastbuild: force-non-root
	-rm -f bazel-bin
	ln -s $(shell bazel info bazel-bin) bazel-bin

envoy-deps-fastbuild: bazel-bin-fastbuild $(COMPILER_DEP)
	@$(ECHO_BAZEL)
	$(BAZEL) $(BAZEL_OPTS) build $(BAZEL_BUILD_OPTS) //:cilium-envoy-deps $(BAZEL_FILTER)
	-rm -f bazel-bin/cilium-envoy-deps
	$(BAZEL) shutdown

envoy-default: bazel-bin-fastbuild $(COMPILER_DEP)
	@$(ECHO_BAZEL)
	-rm -f ${ENVOY_LINKSTAMP_O}
	$(BAZEL) $(BAZEL_OPTS) build $(BAZEL_BUILD_OPTS) //:cilium-envoy $(BAZEL_FILTER)

# Allow root build for release
bazel-bin-release: force
	-rm -f bazel-bin
	ln -s $(shell bazel info --config=release bazel-bin) bazel-bin

envoy-deps-release: bazel-bin-release $(COMPILER_DEP)
	@$(ECHO_BAZEL)
	$(BAZEL) $(BAZEL_OPTS) build $(BAZEL_BUILD_OPTS) --config=release //:cilium-envoy-deps $(BAZEL_FILTER)
	-rm -f bazel-bin/cilium-envoy-deps
	$(BAZEL) shutdown

$(CILIUM_ENVOY_BIN): bazel-bin-release $(COMPILER_DEP)
	@$(ECHO_BAZEL)
	-rm -f ${ENVOY_LINKSTAMP_O}
	$(BAZEL) $(BAZEL_OPTS) build $(BAZEL_BUILD_OPTS) --config=release //:cilium-envoy $(BAZEL_FILTER)

$(CILIUM_ENVOY_RELEASE_BIN): $(CILIUM_ENVOY_BIN)
	mv $< $@

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

install: $(CILIUM_ENVOY_BIN)
	$(INSTALL) -m 0755 -d $(DESTDIR)$(BINDIR)
	$(INSTALL) -m 0755 -T $(CILIUM_ENVOY_BIN) $(DESTDIR)$(BINDIR)/cilium-envoy

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
	@echo "Bazel clean skipped, try 'make veryclean' instead."

veryclean: force clean-bins
	-sudo $(BAZEL) $(BAZEL_OPTS) clean
	-sudo rm -Rf $(BAZEL_CACHE)

precheck:
	tools/check_repositories.sh

check: $(CHECK_FORMAT) force-non-root
	CLANG_FORMAT=$(CLANG_FORMAT) BUILDIFIER=$(BUILDIFIER) $(CHECK_FORMAT) --skip_envoy_build_rule_check --add-excluded-prefixes "./linux/" "./proxylib/" --build_fixer_check_excluded_paths="./" check

fix: $(CHECK_FORMAT) force-non-root
	CLANG_FORMAT=$(CLANG_FORMAT) BUILDIFIER=$(BUILDIFIER) $(CHECK_FORMAT) --skip_envoy_build_rule_check --add-excluded-prefixes "./linux/" "./proxylib/" --build_fixer_check_excluded_paths="./" fix

# Run rule even if file exists, as it can be for a wrong architecture
.PHONY: proxylib/libcilium.so
proxylib/libcilium.so:
	if ! file $@ | grep $(shell uname -m | tr "_" "-"); then \
		docker create -ti --name cilium-proxylib $(CILIUM_REF) bash && \
		docker cp -L cilium-proxylib:/usr/lib/libcilium.so $@ && \
		docker rm -fv cilium-proxylib ; \
	fi

# Run tests using the fastbuild by default.
tests: proxylib/libcilium.so force-non-root
	$(BAZEL) $(BAZEL_OPTS) test $(BAZEL_BUILD_OPTS) -c fastbuild //:envoy_binary_test $(BAZEL_FILTER)
	$(BAZEL) $(BAZEL_OPTS) test $(BAZEL_BUILD_OPTS) -c fastbuild $(BAZEL_TEST_OPTS) //tests/... $(BAZEL_FILTER)

debug-tests: proxylib/libcilium.so force-non-root
	$(BAZEL) $(BAZEL_OPTS) test $(BAZEL_BUILD_OPTS) -c debug $(BAZEL_TEST_OPTS) //:envoy_binary_test $(BAZEL_FILTER)
	$(BAZEL) $(BAZEL_OPTS) test $(BAZEL_BUILD_OPTS) -c debug $(BAZEL_TEST_OPTS) //tests/... $(BAZEL_FILTER)

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
