#
# Builder dependencies. This takes a long time to build from scratch!
# Also note that if build fails due to C++ internal error or similar,
# it is possible that the image build needs more RAM than available by
# default on non-Linux docker installs.
#
# Using cilium-builder as the base to ensure libc etc. are in sync.
#
# cilium-builder:2020-04-16 is the last one before it was changed from
# Ubuntu 18.04 to 20.04. Building with 20.04 will result in a
# cilium-envoy binary that fails to run on 18.04 due to the glibc
# being 2.27, while 2.28 and/or 2.29 is required. This will also
# affect Istio sidecar compatibility, so we should keep the builder at
# Ubuntu 18.04 for now.
FROM quay.io/cilium/cilium-builder:2020-04-16@sha256:2bb6316f5edeaf917eaccdd81438b83e8a6e671926e11d26c1f028cef7880bbe as builder
LABEL maintainer="maintainer@cilium.io"
WORKDIR /go/src/github.com/cilium/cilium/envoy
COPY . ./

#
# Additional Envoy Build dependencies
#
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get upgrade -y --no-install-recommends \
	&& DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
		automake \
		cmake \
		g++ \
		git \
		libtool \
		make \
		ninja-build \
		python \
		python3 \
		wget \
		zip \
		unzip \
	&& apt-get clean \
	&& rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

#
# Install Bazel
#
RUN export BAZEL_VERSION=`cat .bazelversion` \
	&& curl -sfL https://github.com/bazelbuild/bazel/releases/download/${BAZEL_VERSION}/bazel-${BAZEL_VERSION}-installer-linux-x86_64.sh -o bazel-${BAZEL_VERSION}-installer-linux-x86_64.sh \
	&& chmod +x bazel-${BAZEL_VERSION}-installer-linux-x86_64.sh \
	&& ./bazel-${BAZEL_VERSION}-installer-linux-x86_64.sh \
	&& mv /usr/local/bin/bazel /usr/bin \
	&& rm bazel-${BAZEL_VERSION}-installer-linux-x86_64.sh

#
# Build and keep the cache
#
RUN make BAZEL_BUILD_OPTS="--jobs=4 --sandbox_debug --verbose_failures" PKG_BUILD=1 ./bazel-bin/cilium-envoy && rm ./bazel-bin/cilium-envoy

#
# Absolutely nothing after making envoy deps!
#
