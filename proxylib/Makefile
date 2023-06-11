# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

include ../Makefile.defs

# Support CGO cross-compiling for amd64 and arm64 targets
NATIVE_ARCH = $(shell GOARCH= $(GO) env GOARCH)
CGO_CC =
CROSS_ARCH =
ifneq ($(GOARCH),$(NATIVE_ARCH))
    CROSS_ARCH = $(GOARCH)
endif
ifeq ($(CROSS_ARCH),arm64)
    CGO_CC = CC=aarch64-linux-gnu-gcc
else ifeq ($(CROSS_ARCH),amd64)
    CGO_CC = CC=x86_64-linux-gnu-gcc
endif
GO_BUILD_WITH_CGO = CGO_ENABLED=1 $(CGO_CC) $(GO) build

EXTRA_GO_BUILD_LDFLAGS = -extldflags -Wl,-soname,libcilium.so

TARGET := libcilium.so

.PHONY: all $(TARGET) clean header libcilium.h

all: $(TARGET)

$(TARGET):
	$(QUIET)$(GO_BUILD_WITH_CGO) -ldflags '$(EXTRA_GO_BUILD_LDFLAGS)' -o $@ -buildmode=c-shared

clean:
	-$(QUIET)rm -f $(TARGET)
	$(QUIET)$(GO_CLEAN)

header: libcilium.h
libcilium.h: proxylib.go
	$(GO) tool cgo -exportheader libcilium.h proxylib.go
