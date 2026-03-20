#
# Builder dependencies. This takes a long time to build from scratch!
# Also note that if build fails due to C++ internal error or similar,
# it is possible that the image build needs more RAM than available by
# default on non-Linux docker installs.
FROM docker.io/library/ubuntu:24.04@sha256:186072bba1b2f436cbb91ef2567abca677337cfc786c86e107d25b7072feef0c AS base
LABEL maintainer="maintainer@cilium.io"
ARG TARGETARCH
# Setup TimeZone to prevent tzdata package asking for it interactively
ENV TZ=Etc/UTC

# renovate: datasource=golang-version depName=go
ENV GO_VERSION=1.24.13

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
	python3 python-is-python3 unzip virtualenv wget zip \
      # Cilium-envoy build dependencies
      software-properties-common && \
    wget -qO- https://apt.llvm.org/llvm-snapshot.gpg.key | tee /etc/apt/trusted.gpg.d/apt.llvm.org.asc && \
    apt-add-repository -y "deb http://apt.llvm.org/noble/ llvm-toolchain-noble-18 main" && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
      clang-18 clang-tidy-18 clang-tools-18 llvm-18-dev lldb-18 lld-18 clang-format-18 libc++-18-dev libc++abi-18-dev && \
    # Create unversioned symlinks so tools are available without -18 suffix
    ln -sf /usr/bin/clang-18 /usr/bin/clang && \
    ln -sf /usr/bin/clang++-18 /usr/bin/clang++ && \
    ln -sf /usr/bin/clang-cpp-18 /usr/bin/clang-cpp && \
    ln -sf /usr/bin/lld-18 /usr/bin/lld && \
    ln -sf /usr/bin/ld.lld-18 /usr/bin/ld.lld && \
    ln -sf /usr/bin/lldb-18 /usr/bin/lldb && \
    ln -sf /usr/bin/clang-format-18 /usr/bin/clang-format && \
    ln -sf /usr/bin/clang-tidy-18 /usr/bin/clang-tidy && \
    ln -sf /usr/bin/run-clang-tidy-18 /usr/bin/run-clang-tidy && \
    ln -sf /usr/bin/llvm-ar-18 /usr/bin/llvm-ar && \
    ln -sf /usr/bin/llvm-nm-18 /usr/bin/llvm-nm && \
    ln -sf /usr/bin/llvm-strip-18 /usr/bin/llvm-strip && \
    ln -sf /usr/bin/llvm-objcopy-18 /usr/bin/llvm-objcopy && \
    ln -sf /usr/bin/llvm-objdump-18 /usr/bin/llvm-objdump && \
    ln -sf /usr/bin/llvm-dwp-18 /usr/bin/llvm-dwp && \
    ln -sf /usr/bin/llvm-cov-18 /usr/bin/llvm-cov && \
    ln -sf /usr/bin/llvm-config-18 /usr/bin/llvm-config && \
    apt-get purge --auto-remove && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

#
# Install Bazelisk
#
# renovate: datasource=github-releases depName=bazelbuild/bazelisk
ENV BAZELISK_VERSION=v1.28.1

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
