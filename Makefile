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

# COMPILER_DEP:=clang.bazelrc

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

BAZEL_TEST_OPTS ?= --jobs=HOST_RAM*0.0002 --test_timeout=2000
BAZEL_TEST_OPTS += --test_output=errors

BUILDARCH := $(subst aarch64,arm64,$(subst x86_64,amd64,$(shell uname -m)))
BAZEL_ARCH := $(subst x86_64,k8,$(subst arm64,aarch64,$(shell uname -m)))

# ARCH overrides TARGETARCH, but not if ARCH=multi
ifdef ARCH
  ifneq ($(ARCH),multi)
    TARGETARCH := $(ARCH)
  endif
endif

ifdef TARGETARCH
  ifneq "$(TARGETARCH)" "$(BUILDARCH)"
    $(info CROSS-COMPILING for $(TARGETARCH))
    BAZEL_ARCH := $(subst amd64,k8,$(subst arm64,aarch64,$(TARGETARCH)))
    BAZEL_BUILD_OPTS += --cpu=$(BAZEL_ARCH)
  else
    $(info BUILDING for $(TARGETARCH) ($(BAZEL_ARCH)))
  endif
else
  TARGETARCH := $(BUILDARCH)
  $(info BUILDING on $(TARGETARCH) ($(BAZEL_ARCH)))
endif

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

/usr/lib/llvm-15:
	$(SUDO) apt install clang-15 llvm-15-dev

/usr/lib/lld-15:
	$(SUDO) apt install lld-15

/usr/lib/clang-format-15:
	$(SUDO) apt install clang-format-15

clang.bazelrc: bazel/setup_clang.sh /usr/lib/llvm-15 /usr/lib/lld-15 /usr/lib/clang-format-15
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
ifdef COPY_CACHE_EXT
  ifneq ($(BAZEL_CACHE),)
	cp -ra $(BAZEL_CACHE) $(BAZEL_CACHE)$(COPY_CACHE_EXT)
  endif
endif

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
ifdef COPY_CACHE_EXT
  ifneq ($(BAZEL_CACHE),)
	cp -ra $(BAZEL_CACHE) $(BAZEL_CACHE)$(COPY_CACHE_EXT)
  endif
endif

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
