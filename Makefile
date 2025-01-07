# Copyright 2017-2021 Authors of Cilium
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

COMPILER_DEP := clang.bazelrc

ENVOY_BINS = cilium-envoy bazel-bin/cilium-envoy cilium-envoy-starter bazel-bin/cilium-envoy-starter
ENVOY_TESTS = bazel-bin/tests/*_test

BUILD_DEP_FILES = ENVOY_VERSION WORKSPACE .bazelrc envoy.bazelrc bazel/toolchains/BUILD bazel/toolchains/cc_toolchain_config.bzl

SHELL=/bin/bash -o pipefail
BAZEL ?= $(QUIET) bazel
BAZEL_FILTER ?=
BAZEL_OPTS ?=
BAZEL_BUILD_OPTS ?=
ifdef BAZEL_REMOTE_CACHE
  BAZEL_BUILD_OPTS += --remote_cache=$(BAZEL_REMOTE_CACHE)
endif

BAZEL_TEST_OPTS ?= --jobs=HOST_RAM*.0003 --test_timeout=300 --local_test_jobs=1 --flaky_test_attempts=3
BAZEL_TEST_OPTS += --test_output=errors

BUILDARCH := $(subst aarch64,arm64,$(subst x86_64,amd64,$(shell uname -m)))
# Default for the host architecture
ifndef TARGETARCH
  TARGETARCH := $(BUILDARCH)
endif

# ARCH=multi is only valid for docker builds, and gets resolved to individual targets for builds
# within the Dockerfile.
ifdef ARCH
  ifneq ($(ARCH),multi)
    TARGETARCH := $(ARCH)
  else
    # Split the cores when building for both targets
    BAZEL_BUILD_OPTS += --jobs=HOST_CPUS*.5
  endif
endif

# Extra opts are passed to docker targets, which will choose the bazel platform themselves
EXTRA_BAZEL_BUILD_OPTS := $(BAZEL_BUILD_OPTS)
BAZEL_PLATFORM := //bazel:linux_$(subst amd64,x86_64,$(subst arm64,aarch64,$(TARGETARCH)))
$(info BUILDING on $(BUILDARCH) for $(TARGETARCH) using $(BAZEL_PLATFORM))
BAZEL_BUILD_OPTS += --platforms=$(BAZEL_PLATFORM)

ifdef DEBUG
  BAZEL_BUILD_OPTS += -c dbg
else
  BAZEL_BUILD_OPTS += --config=release
endif

SUDO=
ifneq ($(shell whoami),root)
  SUDO=$(shell if sudo -h 1>/dev/null 2>/dev/null; then echo "sudo"; fi)
endif

define add_clang_apt_source
	if [ ! -f /etc/apt/trusted.gpg.d/apt.llvm.org.asc ]; then \
	  $(SUDO) wget -q -O /etc/apt/trusted.gpg.d/apt.llvm.org.asc https://apt.llvm.org/llvm-snapshot.gpg.key; \
	fi
	apt_source="deb http://apt.llvm.org/$(1)/ llvm-toolchain-$(1)-17 main" && \
	$(SUDO) apt-add-repository -y "$${apt_source}" && \
	$(SUDO) apt update
endef

ifdef PKG_BUILD
  $(info Registering C++ toolchains via BAZEL_BUILD_OPTS)
  BAZEL_BUILD_OPTS += --extra_toolchains=//bazel/toolchains:all

  all: cilium-envoy-starter cilium-envoy

  .PHONY: install-bazelisk
  install-bazelisk:
	echo "Bazel assumed to be installed in the builder image"

  define install_clang
	echo "Clang assumed to be installed in the builder image"
  endef
else
  $(info Skip registering C++ toolchains via BAZEL_BUILD_OPTS. Local C++ toolchain needs to be available!)

  all: precheck cilium-envoy-starter cilium-envoy

  include Makefile.docker

  # Fetch and install Bazel if needed
  .PHONY: install-bazelisk
  install-bazelisk:
	tools/install_bazelisk.sh

  # Install clang if needed
  define install_clang
	$(SUDO) apt info clang-17 || $(call add_clang_apt_source,$(shell lsb_release -cs))
	$(SUDO) apt install -y clang-17 llvm-17-dev lld-17 clang-format-17
  endef
endif

include Makefile.dev

BUILD_DEP_HASHES: $(BUILD_DEP_FILES)
	sha256sum $^ >$@

clang.bazelrc: bazel/setup_clang.sh
	$(call install_clang)
	bazel/setup_clang.sh /usr/lib/llvm-17
	echo "build --config=clang" >> $@

.PHONY: bazel-bin/cilium-envoy
bazel-bin/cilium-envoy: $(COMPILER_DEP) SOURCE_VERSION install-bazelisk
	@$(ECHO_BAZEL)
	$(BAZEL) $(BAZEL_OPTS) build $(BAZEL_BUILD_OPTS) //:cilium-envoy $(BAZEL_FILTER)

cilium-envoy: bazel-bin/cilium-envoy
	mv $< $@

.PHONY: bazel-bin/cilium-envoy-starter
bazel-bin/cilium-envoy-starter: $(COMPILER_DEP) SOURCE_VERSION install-bazelisk
	@$(ECHO_BAZEL)
	$(BAZEL) $(BAZEL_OPTS) build $(BAZEL_BUILD_OPTS) //:cilium-envoy-starter $(BAZEL_FILTER)

cilium-envoy-starter: bazel-bin/cilium-envoy-starter
	mv $< $@

BAZEL_CACHE := $(subst --disk_cache=,,$(filter --disk_cache=%, $(BAZEL_BUILD_OPTS)))

GLIBC_VERSION ?= $(shell ldd --version | sed -n 's/.*GLIBC \([0-9.]\+\).*/\1/p')
GLIBC_DIR ?= $(LIBDIR)/glibc-$(GLIBC_VERSION)

$(DESTDIR)$(GLIBC_DIR): bazel-bin/cilium-envoy
	$(SUDO) $(INSTALL) -m 0755 -d $@
	LIBS=$$(readelf -d bazel-bin/cilium-envoy | sed -n 's/.*(NEEDED).*Shared library: \[\(.*\)\]/\1/p'); \
	ARCH_TAG=$$(echo $$LIBS | sed -n 's/.*ld-linux-\(.*\)\.so.*/\1/p' | tr - _); \
	echo "BUILD for $${ARCH_TAG}"; \
	for lib in $${LIBS}; do \
		$(SUDO) cp /usr/$${ARCH_TAG}-linux-gnu/lib/$$lib $@; \
	done

install: bazel-bin/cilium-envoy-starter bazel-bin/cilium-envoy
	$(SUDO) $(INSTALL) -m 0755 -d $(DESTDIR)$(BINDIR)
	$(SUDO) $(INSTALL) -m 0755 -T bazel-bin/cilium-envoy-starter $(DESTDIR)$(BINDIR)/cilium-envoy-starter
	$(SUDO) $(INSTALL) -m 0755 -T bazel-bin/cilium-envoy $(DESTDIR)$(BINDIR)/cilium-envoy

install-glibc: install $(DESTDIR)$(GLIBC_DIR)
	LD_LINUX=$$(basename $$(patchelf --print-interpreter bazel-bin/cilium-envoy)); \
	$(SUDO) patchelf --set-interpreter $(GLIBC_DIR)/$${LD_LINUX} --set-rpath $(GLIBC_DIR) $(DESTDIR)$(BINDIR)/cilium-envoy-starter
	$(SUDO) patchelf --set-interpreter $(GLIBC_DIR)/$${LD_LINUX} --set-rpath $(GLIBC_DIR) $(DESTDIR)$(BINDIR)/cilium-envoy

# Remove the binaries
clean: force
	@$(ECHO_CLEAN) $(notdir $(shell pwd))
	-$(QUIET) rm -f $(ENVOY_BINS) $(ENVOY_TESTS)

proxylib/libcilium.so:
	make -C proxylib

.PHONY: envoy-test-deps
envoy-test-deps: $(COMPILER_DEP) SOURCE_VERSION proxylib/libcilium.so
	@$(ECHO_BAZEL)
	$(BAZEL) $(BAZEL_OPTS) build $(BAZEL_BUILD_OPTS) $(BAZEL_TEST_OPTS) //tests/... @envoy//test/integration:tcp_proxy_integration_test $(BAZEL_FILTER)

.PHONY: envoy-tests
envoy-tests: $(COMPILER_DEP) SOURCE_VERSION proxylib/libcilium.so
	@$(ECHO_BAZEL)
	# Upstream tcp_proxy_integration_test included to validate that our custom patches
	# didn't break anything
	$(BAZEL) $(BAZEL_OPTS) test $(BAZEL_BUILD_OPTS) $(BAZEL_TEST_OPTS) //tests/... @envoy//test/integration:tcp_proxy_integration_test $(BAZEL_FILTER)

.PHONY: \
	install \
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
