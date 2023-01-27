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
FROM docker.io/library/ubuntu:20.04 as base
LABEL maintainer="maintainer@cilium.io"
ARG TARGETARCH
# Setup TimeZone to prevent tzdata package asking for it interactively
ENV TZ=Etc/UTC
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone
RUN apt-get update && \
    apt-get upgrade -y --no-install-recommends && \
    apt-get install -y --no-install-recommends \
      # Multi-arch cross-compilation packages
      gcc-aarch64-linux-gnu g++-aarch64-linux-gnu libc6-dev-arm64-cross binutils-aarch64-linux-gnu \
      gcc-x86-64-linux-gnu g++-x86-64-linux-gnu libc6-dev-amd64-cross binutils-x86-64-linux-gnu \
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
      libicu-dev \
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
    ln /usr/bin/clang-10 /usr/bin/clang && ln /usr/bin/clang++-10 /usr/bin/clang++ && ln /usr/bin/lld-10 /usr/bin/lld && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

WORKDIR /cilium/proxy
COPY .bazelversion ./
#
# Install Bazel
#
RUN export BAZEL_VERSION=$(cat .bazelversion) \
	&& ARCH=$TARGETARCH && [ "$ARCH" != "amd64" ] || ARCH="x86_64" \
	&& curl -sfL https://github.com/bazelbuild/bazel/releases/download/${BAZEL_VERSION}/bazel-${BAZEL_VERSION}-linux-${ARCH} -o /usr/bin/bazel \
	&& chmod +x /usr/bin/bazel
