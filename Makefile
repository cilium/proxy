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

ENVOY_BINS = cilium-envoy bazel-bin/cilium-envoy
ENVOY_TESTS = bazel-bin/tests/*_test

SHELL=/bin/bash -o pipefail
BAZEL ?= $(QUIET) bazel
BAZEL_FILTER ?=
BAZEL_OPTS ?=
BAZEL_BUILD_OPTS ?=
ifdef BAZEL_REMOTE_CACHE
  BAZEL_BUILD_OPTS += --remote_cache=$(BAZEL_REMOTE_CACHE)
endif

BAZEL_TEST_OPTS ?= --jobs=HOST_RAM*.0003 --test_timeout=300
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

ifdef PKG_BUILD
  all: cilium-envoy
else
  include Makefile.dev
  include Makefile.docker

  # Fetch and install Bazel if needed
  .PHONY: install-bazel
  install-bazel:
	tools/install_bazel.sh `cat .bazelversion`
endif

ifeq ($(shell whoami),root)
  SUDO=
else
  SUDO=sudo
endif

define add_clang_apt_source
	if [ ! -f /etc/apt/trusted.gpg.d/apt.llvm.org.asc ]; then \
	  $(SUDO) wget -q -O /etc/apt/trusted.gpg.d/apt.llvm.org.asc https://apt.llvm.org/llvm-snapshot.gpg.key; \
	fi
	apt_source="deb http://apt.llvm.org/$(1)/ llvm-toolchain-$(1)-15 main" && \
	grep $${apt_source} /etc/apt/sources.list || echo $${apt_source} | $(SUDO) tee -a /etc/apt/sources.list
	apt_source="deb-src http://apt.llvm.org/$(1)/ llvm-toolchain-$(1)-15 main" && \
	grep $${apt_source} /etc/apt/sources.list || echo $${apt_source} | $(SUDO) tee -a /etc/apt/sources.list
	$(SUDO) apt update
endef

/usr/lib/llvm-15:
	$(SUDO) apt info clang-15 || $(call add_clang_apt_source,$(shell lsb_release -cs))
	$(SUDO) apt install -y clang-15 llvm-15-dev lld-15 clang-format-15

clang.bazelrc: bazel/setup_clang.sh /usr/lib/llvm-15
	bazel/setup_clang.sh /usr/lib/llvm-15
	echo "build --config=clang" >> $@

bazel-bin/cilium-envoy: $(COMPILER_DEP) SOURCE_VERSION
	@$(ECHO_BAZEL)
	$(BAZEL) $(BAZEL_OPTS) build $(BAZEL_BUILD_OPTS) --config=release //:cilium-envoy $(BAZEL_FILTER)

cilium-envoy: bazel-bin/cilium-envoy
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

install: bazel-bin/cilium-envoy
	$(SUDO) $(INSTALL) -m 0755 -d $(DESTDIR)$(BINDIR)
	$(SUDO) $(INSTALL) -m 0755 -T $< $(DESTDIR)$(BINDIR)/cilium-envoy

install-glibc: install $(DESTDIR)$(GLIBC_DIR)
	LD_LINUX=$$(basename $$(patchelf --print-interpreter bazel-bin/cilium-envoy)); \
	$(SUDO) patchelf --set-interpreter $(GLIBC_DIR)/$${LD_LINUX} --set-rpath $(GLIBC_DIR) $(DESTDIR)$(BINDIR)/cilium-envoy

# Remove the binaries
clean: force
	@$(ECHO_CLEAN) $(notdir $(shell pwd))
	-$(QUIET) rm -f $(ENVOY_BINS) $(ENVOY_TESTS)

.PHONY: envoy-test-deps
envoy-test-deps: $(COMPILER_DEP) proxylib/libcilium.so SOURCE_VERSION
	@$(ECHO_BAZEL)
	$(BAZEL) $(BAZEL_OPTS) build --build_tests_only $(BAZEL_BUILD_OPTS) --config=release -c fastbuild $(BAZEL_TEST_OPTS) //tests/... $(BAZEL_FILTER)

.PHONY: envoy-tests
envoy-tests: $(COMPILER_DEP) proxylib/libcilium.so SOURCE_VERSION
	@$(ECHO_BAZEL)
	$(BAZEL) $(BAZEL_OPTS) test $(BAZEL_BUILD_OPTS) --config=release -c fastbuild $(BAZEL_TEST_OPTS) //tests/... $(BAZEL_FILTER)

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
