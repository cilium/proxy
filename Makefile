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

ifdef CROSSARCH
  $(info CROSS-COMPILING for arm64)
  BAZEL_BUILD_OPTS += --incompatible_enable_cc_toolchain_resolution --platforms=//bazel/platforms:aarch64_cross --define=cross=aarch64
endif

BAZEL_ARCH = $(subst x86_64,k8,$(shell uname -m))
ENVOY_LINKSTAMP_O = bazel-bin/_objs/cilium-envoy/envoy/source/common/common/version_linkstamp.o

ifdef PKG_BUILD
  all: cilium-envoy
else
  all: envoy-default api

  include Makefile.dev
  include Makefile.docker

  # Fetch and install Bazel if needed
  .PHONY: install-bazel
  install-bazel:
	tools/install_bazel.sh `cat .bazelversion`
endif

.PHONY: shutdown-bazel
shutdown-bazel:
	$(BAZEL) shutdown

/usr/lib/llvm-10:
	sudo apt install clang-10 llvm-10-dev clang-format-10 lld-10

clang.bazelrc: bazel/setup_clang.sh /usr/lib/llvm-10
	bazel/setup_clang.sh /usr/lib/llvm-10
	echo "build --config=clang" >> $@

# Allow root build for release
bazel-bin-release: clean-bins force
	-rm -f bazel-bin
	ln -s $(shell bazel info --config=release bazel-bin) bazel-bin

envoy-deps-release: bazel-bin-release $(COMPILER_DEP)
	@$(ECHO_BAZEL)
	$(BAZEL) $(BAZEL_OPTS) build $(BAZEL_BUILD_OPTS) --config=release //:cilium-envoy-deps $(BAZEL_FILTER)
	-rm -f bazel-bin/cilium-envoy-deps
	$(BAZEL) shutdown

bazel-bin/cilium-envoy: bazel-bin-release $(COMPILER_DEP)
	@$(ECHO_BAZEL)
	-rm -f ${ENVOY_LINKSTAMP_O}
	$(BAZEL) $(BAZEL_OPTS) build $(BAZEL_BUILD_OPTS) --config=release //:cilium-envoy $(BAZEL_FILTER)

cilium-envoy: bazel-bin/cilium-envoy
	mv $< $@

install: bazel-bin/cilium-envoy
	$(INSTALL) -m 0755 -d $(DESTDIR)$(BINDIR)
	$(INSTALL) -m 0755 -T bazel-bin/cilium-envoy $(DESTDIR)$(BINDIR)/cilium-envoy

# Remove the binaries to get fresh version SHA
clean-bins: force
	@$(ECHO_CLEAN) $(notdir $(shell pwd))
	-$(QUIET) rm -f $(ENVOY_BINS) $(ENVOY_TESTS)

.PHONY: \
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
