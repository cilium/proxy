#
# Builder dependencies. This takes a long time to build from scratch!
# Also note that if build fails due to C++ internal error or similar,
# it is possible that the image build needs more RAM than available by
# default on non-Linux docker installs.
FROM docker.io/library/ubuntu:20.04@sha256:33a5cc25d22c45900796a1aca487ad7a7cb09f09ea00b779e3b2026b4fc2faba as base
LABEL maintainer="maintainer@cilium.io"
ARG TARGETARCH
# Setup TimeZone to prevent tzdata package asking for it interactively
ENV TZ=Etc/UTC
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
      autoconf automake cmake coreutils curl git libtool make ninja-build patch patchelf \
	python3 python-is-python3 unzip virtualenv wget zip \
      # Cilium-envoy build dependencies
      software-properties-common && \
    wget -qO- https://apt.llvm.org/llvm-snapshot.gpg.key | tee /etc/apt/trusted.gpg.d/apt.llvm.org.asc && \
    apt-add-repository -y "deb http://apt.llvm.org/focal/ llvm-toolchain-focal-15 main" && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
      clang-15 clang-tools-15 lldb-15 lld-15 clang-format-15 libc++-15-dev libc++abi-15-dev && \
    apt-get purge --auto-remove && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

#
# Install Bazel
#
COPY .bazelversion ./
RUN export BAZEL_VERSION=$(cat .bazelversion) \
	&& ARCH=$TARGETARCH && [ "$ARCH" != "amd64" ] || ARCH="x86_64" \
	&& curl -sfL https://github.com/bazelbuild/bazel/releases/download/${BAZEL_VERSION}/bazel-${BAZEL_VERSION}-linux-${ARCH} -o /usr/bin/bazel \
	&& chmod +x /usr/bin/bazel
#
# Install Go
#
# renovate: datasource=golang-version depName=go
RUN export GO_VERSION=1.21.2 \
	&& curl -sfL https://go.dev/dl/go${GO_VERSION}.linux-${TARGETARCH}.tar.gz -o go.tar.gz \
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
