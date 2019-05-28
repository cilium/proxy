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
BAZEL_FILTER ?= 2>&1 | grep -v -e "INFO: From .*:" -e "external/.*: warning: directory does not exist."
BAZEL_OPTS ?=
BAZEL_TEST_OPTS ?= --jobs=1
BAZEL_CACHE ?= ~/.cache/bazel
BAZEL_ARCHIVE ?= ~/bazel-cache.tar.bz2
CLANG ?= clang
CLANG_FORMAT ?= clang-format
BUILDIFIER ?= buildifier
STRIP ?= $(QUIET) strip

ISTIO_VERSION = 1.1.7

DOCKER=$(QUIET)docker

BAZEL_BUILD_OPTS ?= --jobs=3

# Dockerfile builds require special options
ifdef PKG_BUILD
BAZEL_BUILD_OPTS += --local_resources 4096,2.0,1.0
all: precheck install-bazel clean-bins $(CILIUM_ENVOY_RELEASE_BIN) shutdown-bazel
else
all: precheck install-bazel clean-bins envoy-default api shutdown-bazel
endif

# Fetch and install Bazel if needed
install-bazel:
	tools/install_bazel.sh `cat BAZEL_VERSION`

ifdef KEEP_BAZEL_RUNNING
shutdown-bazel:
else
shutdown-bazel:
	$(BAZEL) shutdown
endif

SOURCE_VERSION =

# Use git only if in a Git repo
ifneq ($(wildcard $(dir $(lastword $(MAKEFILE_LIST)))/.git),)
	SOURCE_VERSION = $(shell git rev-parse HEAD)
else
	SOURCE_VERSION = $(shell cat SOURCE_VERSION)
endif

SOURCE_VERSION: .git
	echo $(SOURCE_VERSION) >SOURCE_VERSION

docker-image-builder: Dockerfile.builder
	$(DOCKER) build -f $< -t "quay.io/cilium/cilium-envoy-builder:$(SOURCE_VERSION)" .

.dockerignore: .gitignore SOURCE_VERSION
	echo $(SOURCE_VERSION)
	$(QUIET)grep -v -E "(SOURCE|GIT)_VERSION" .gitignore >.dockerignore
	$(QUIET)echo ".*" >>.dockerignore # .git pruned out

docker-image-envoy: Dockerfile clean .dockerignore 
	@$(ECHO_GEN) docker-image-envoy
	$(DOCKER) build -t "quay.io/cilium/cilium-envoy:$(SOURCE_VERSION)" .
	$(QUIET)echo "Push like this when ready:"
	$(QUIET)echo "docker push quay.io/cilium/cilium-envoy:$(SOURCE_VERSION)"

debug: envoy-debug

api: force-non-root Makefile.api
	$(MAKE) -f Makefile.api all

envoy-default: force-non-root
	@$(ECHO_BAZEL)
	-rm -f bazel-out/k8-fastbuild/bin/_objs/cilium-envoy/external/envoy/source/common/common/version_linkstamp.o
	$(BAZEL) $(BAZEL_OPTS) build $(BAZEL_BUILD_OPTS) //:cilium-envoy $(BAZEL_FILTER)

# Allow root build for release
$(CILIUM_ENVOY_BIN) $(CILIUM_ENVOY_RELEASE_BIN): force
	@$(ECHO_BAZEL)
	-rm -f bazel-out/k8-opt/bin/_objs/cilium-envoy/external/envoy/source/common/common/version_linkstamp.o
	$(BAZEL) $(BAZEL_OPTS) build $(BAZEL_BUILD_OPTS) -c opt //:cilium-envoy $(BAZEL_FILTER)
	$(STRIP) -o $(CILIUM_ENVOY_RELEASE_BIN) $(CILIUM_ENVOY_BIN)

Dockerfile.%: Dockerfile.%.in
	-sed "s/@ISTIO_VERSION@/$(ISTIO_VERSION)/" <$< >$@

docker-istio-proxy: Dockerfile.istio_proxy envoy_bootstrap_tmpl.json .dockerignore
	@$(ECHO_GEN) docker-istio-proxy
	$(DOCKER) build -f $< -t cilium/istio_proxy:$(ISTIO_VERSION) .
	$(QUIET)echo "Push like this when ready:"
	$(QUIET)echo "docker push cilium/istio_proxy:$(ISTIO_VERSION)"

docker-istio-proxy-debug: Dockerfile.istio_proxy_debug envoy_bootstrap_tmpl.json .dockerignore 
	@$(ECHO_GEN) docker-istio-proxy-debug
	$(DOCKER) build -f $< -t cilium/istio_proxy_debug:$(ISTIO_VERSION) .
	$(QUIET)echo "Push like this when ready:"
	$(QUIET)echo "docker push cilium/istio_proxy_debug:$(ISTIO_VERSION)"

envoy-debug: force-non-root
	@$(ECHO_BAZEL)
	-rm -f bazel-out/k8-dbg/bin/_objs/envoy/external/envoy/source/common/common/version_linkstamp.o
	$(BAZEL) $(BAZEL_OPTS) build $(BAZEL_BUILD_OPTS) -c dbg //:cilium-envoy $(BAZEL_FILTER)

$(CHECK_FORMAT): force-non-root
	$(BAZEL) $(BAZEL_OPTS) build $(BAZEL_BUILD_OPTS) //:check_format.py

install: force-root
	$(INSTALL) -m 0755 -d $(DESTDIR)$(BINDIR)
	$(INSTALL) -m 0755 -T $(CILIUM_ENVOY_BIN) $(DESTDIR)$(BINDIR)/cilium-envoy
# Strip only non-debug builds
ifeq "$(findstring -dbg,$(realpath bazel-bin))" ""
	$(STRIP) $(DESTDIR)$(BINDIR)/cilium-envoy
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
	-$(QUIET) rm -f $(ENVOY_BINS) \
		Dockerfile.istio_proxy \
		Dockerfile.istio_proxy_debug

clean: force clean-bins
	@$(ECHO_CLEAN) $(notdir $(shell pwd))
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
	$(BAZEL) $(BAZEL_OPTS) test $(BAZEL_BUILD_OPTS) -c fastbuild $(BAZEL_TEST_OPTS) //:envoy_binary_test $(BAZEL_FILTER)
	$(BAZEL) $(BAZEL_OPTS) test $(BAZEL_BUILD_OPTS) -c fastbuild $(BAZEL_TEST_OPTS) //:cilium_integration_test $(BAZEL_FILTER)

debug-tests: force-non-root
	$(BAZEL) $(BAZEL_OPTS) test $(BAZEL_BUILD_OPTS) -c debug $(BAZEL_TEST_OPTS) //:envoy_binary_test $(BAZEL_FILTER)
	$(BAZEL) $(BAZEL_OPTS) test $(BAZEL_BUILD_OPTS) -c debug $(BAZEL_TEST_OPTS) //:cilium_integration_test $(BAZEL_FILTER)

.PHONY: \
	install-bazel \
	shutdown-bazel \
	bazel-restore \
	docker-istio-proxy \
	docker-istio-proxy-debug \
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
