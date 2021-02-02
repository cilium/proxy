#
# Builder dependencies. This takes a long time to build from scratch!
# Also note that if build fails due to C++ internal error or similar,
# it is possible that the image build needs more RAM than available by
# default on non-Linux docker installs.
#
# Using Ubuntu 18.04 as base, as building with 20.04 will result in a
# cilium-envoy binary that fails to run on 18.04 due to the glibc
# being 2.27, while 2.28 and/or 2.29 is required. This will also
# affect Istio sidecar compatibility, so we should keep the builder at
# Ubuntu 18.04 for now.
FROM docker.io/library/ubuntu:18.04 as base
LABEL maintainer="maintainer@cilium.io"
RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y --no-install-recommends \
      # Envoy Build dependencies
      autoconf \
      automake \
      clang-10 \
      cmake \
      coreutils \
      curl \
      g++ \
      gcc \
      git \
      libc6-dev \
      libtool \
      lld-10 \
      llvm-10-dev \
      make \
      ninja-build \
      patch \
      python \
      python3 \
      unzip \
      virtualenv \
      wget \
      zip && \
    apt-get purge --auto-remove && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

WORKDIR /cilium/proxy
COPY .bazelversion ./
#
# Install Bazel
#
RUN export BAZEL_VERSION=$(cat .bazelversion) \
	&& ARCH=$(uname -m) && [ "$ARCH" != "aarch64" ] || ARCH="arm64" \
	&& curl -sfL https://github.com/bazelbuild/bazel/releases/download/${BAZEL_VERSION}/bazel-${BAZEL_VERSION}-linux-${ARCH} -o /usr/bin/bazel \
	&& chmod +x /usr/bin/bazel

FROM base as builder
LABEL maintainer="maintainer@cilium.io"
WORKDIR /cilium/proxy
COPY . ./
ARG V
ARG BAZEL_BUILD_OPTS

#
# Build Bazel cache
#
RUN BAZEL_BUILD_OPTS=${BAZEL_BUILD_OPTS:---jobs=8} PKG_BUILD=1 V=$V DESTDIR=/tmp/install make envoy-deps-release

#
# Absolutely nothing after making envoy deps!
#
