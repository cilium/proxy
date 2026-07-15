#
# Builder dependencies. This takes a long time to build from scratch!
# Also note that if build fails due to C++ internal error or similar,
# it is possible that the image build needs more RAM than available by
# default on non-Linux docker installs.
FROM docker.io/library/ubuntu:24.04@sha256:786a8b558f7be160c6c8c4a54f9a57274f3b4fb1491cf65146521ae77ff1dc54 AS base
LABEL maintainer="maintainer@cilium.io"
ARG TARGETARCH
# Setup TimeZone to prevent tzdata package asking for it interactively
ENV TZ=Etc/UTC

# renovate: datasource=golang-version depName=go
ENV GO_VERSION=1.26.5

RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone
RUN apt-get update && \
    apt-get upgrade -y --no-install-recommends && \
    apt-get install -y --no-install-recommends \
      ca-certificates \
      # Multi-arch cross-compilation packages
      gcc-aarch64-linux-gnu g++-aarch64-linux-gnu libc6-dev-arm64-cross binutils-aarch64-linux-gnu \
      gcc-x86-64-linux-gnu g++-x86-64-linux-gnu libc6-dev-amd64-cross binutils-x86-64-linux-gnu \
      libc6-dev \
      # Envoy Build dependencies
      autoconf automake cmake coreutils curl git libtool make ninja-build patch patchelf libatomic1 \
	python3 python-is-python3 unzip virtualenv wget xz-utils zip && \
    apt-get purge --auto-remove && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

#
# Install Clang/LLVM from the official upstream release tarball.
#
# Ubuntu noble only ships clang 18.1.3, and the apt.llvm.org snapshot repo
# serves inconsistent package versions across mirrors (a release-versioned
# libllvm18 paired with a still-snapshot llvm-18-dev), which intermittently
# breaks apt dependency resolution. The upstream release tarball is an
# immutable, checksummed artifact pinned to exactly LLVM_VERSION. It needs the
# libtinfo.so.5 ABI (dropped by noble), provided by the jammy libtinfo5 compat
# package. The toolchain runs on noble but links the host (glibc 2.39) libc,
# so binaries it produces stay compatible with the ubuntu:24.04 runtime image.
#
# LLVM_VERSION must match MIN_CLANG_VERSION in the Makefile; bump both together
# (deliberately, alongside Envoy upgrades) rather than via automated updates.
ENV LLVM_VERSION=18.1.8
ENV LIBTINFO5_VERSION=6.3-2ubuntu0.1
ENV UBUNTU_SNAPSHOT=20240501T120000Z
RUN case "$TARGETARCH" in \
      amd64) LLVM_ARCH=x86_64-linux-gnu-ubuntu-18.04 ;; \
      arm64) LLVM_ARCH=aarch64-linux-gnu ;; \
      *) echo "unsupported TARGETARCH: $TARGETARCH" >&2; exit 1 ;; \
    esac && \
    # libtinfo.so.5 compat ABI, required to run the upstream clang on noble
    curl -sfL "https://snapshot.ubuntu.com/ubuntu/${UBUNTU_SNAPSHOT}/pool/universe/n/ncurses/libtinfo5_${LIBTINFO5_VERSION}_${TARGETARCH}.deb" -o /tmp/libtinfo5.deb && \
    dpkg -i /tmp/libtinfo5.deb && \
    rm /tmp/libtinfo5.deb && \
    # upstream LLVM toolchain, extracted into the path the bazel toolchain expects
    curl -sfL "https://github.com/llvm/llvm-project/releases/download/llvmorg-${LLVM_VERSION}/clang+llvm-${LLVM_VERSION}-${LLVM_ARCH}.tar.xz" -o /tmp/llvm.tar.xz && \
    mkdir -p /usr/lib/llvm-18 && \
    tar -xJf /tmp/llvm.tar.xz -C /usr/lib/llvm-18 --strip-components=1 && \
    rm /tmp/llvm.tar.xz && \
    # The upstream tarball bundles the entire LLVM suite (Flang, MLIR, BOLT,
    # clangd, static archives, ...) the Envoy build never uses. Keep only the
    # toolchain binaries referenced by //bazel/toolchains plus clang-format and
    # clang-tidy, and drop static archives, tooling shared libs and docs.
    cd /usr/lib/llvm-18/bin && \
    keep=" clang-18 lld clang-format clang-tidy clang-apply-replacements run-clang-tidy llvm-ar llvm-nm llvm-strip llvm-objcopy llvm-objdump llvm-dwp llvm-cov llvm-config llvm-symbolizer " && \
    for f in $(find . -maxdepth 1 -type f -printf '%f\n'); do case "$keep" in *" $f "*) : ;; *) rm -f "$f" ;; esac; done && \
    cd /usr/lib/llvm-18 && \
    find lib -maxdepth 1 -name '*.a' ! -name 'libc++*.a' ! -name 'libunwind*.a' -delete && \
    rm -f lib/libclang-cpp.so* lib/libclang.so* lib/liblldb.so* lib/libLTO.so* lib/libomptarget* lib/LLVMPolly.so lib/libmlir* lib/liblldbIntel* && \
    rm -rf share libexec && \
    # Create unversioned and -18 suffixed symlinks so tools are on PATH either way
    for tool in clang clang++ clang-cpp lld ld.lld clang-format clang-tidy run-clang-tidy clang-apply-replacements \
                llvm-ar llvm-nm llvm-strip llvm-objcopy llvm-objdump llvm-dwp llvm-cov llvm-config llvm-symbolizer; do \
      ln -sf /usr/lib/llvm-18/bin/$tool /usr/bin/$tool && \
      ln -sf /usr/lib/llvm-18/bin/$tool /usr/bin/$tool-18; \
    done && \
    /usr/lib/llvm-18/bin/llvm-symbolizer --version

#
# Install Bazelisk
#
# renovate: datasource=github-releases depName=bazelbuild/bazelisk
ENV BAZELISK_VERSION=v1.29.0

RUN ARCH=$TARGETARCH \
	&& curl -sfL https://github.com/bazelbuild/bazelisk/releases/download/${BAZELISK_VERSION}/bazelisk-linux-${ARCH} -o /usr/bin/bazel \
	&& chmod +x /usr/bin/bazel
#
# Install Go
#
RUN curl -sfL https://go.dev/dl/go${GO_VERSION}.linux-${TARGETARCH}.tar.gz -o go.tar.gz \
	&& tar -C /usr/local -xzf go.tar.gz \
	&& rm go.tar.gz \
	&& export PATH=$PATH:/usr/local/go/bin \
	&& go version
#
# Switch to non-root user for builds
#
RUN groupadd -f -g 1337 cilium && useradd -m -d /cilium/proxy -g cilium -u 1337 cilium
USER 1337:1337
WORKDIR /cilium/proxy
