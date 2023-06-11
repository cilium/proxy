# 
# BUILDER_BASE is a multi-platform image with all the build tools
#
ARG BUILDER_BASE=quay.io/cilium/cilium-envoy-builder:6.0.0-latest

# Common Builder image used in cilium/cilium
# We need gcc for cgo cross-compilation at least, we can swap to something smaller later on
ARG PROXYLIB_BUILDER=quay.io/cilium/cilium-builder:832f86bb0f7c7129c1536d5620174deeec645117@sha256:6dbac9f9eba3e20f8edad4676689aa8c11b172035fe5e25b533552f42dea4e9a

#
# ARCHIVE_IMAGE defaults to the result of the first stage below,
# refreshing the build caches from Envoy dependencies before the final
# build stage. This can be overridden on docker build command line to
# use pre-built dependencies. Note that if cross-compiling, these
# pre-built dependencies will include BUILDPLATFORM build tools and
# TARGETPLATFORM build artifacts, and thus can only be reused when
# building on the same BUILDPLATFORM.
#
ARG ARCHIVE_IMAGE=builder-fresh

FROM --platform=$BUILDPLATFORM $PROXYLIB_BUILDER as proxylib
WORKDIR /go/src/github.com/cilium/proxy
ARG TARGETARCH
ENV TARGETARCH=$TARGETARCH
RUN --mount=type=bind,readwrite,target=/go/src/github.com/cilium/proxy --mount=target=/root/.cache,type=cache --mount=target=/go/pkg,type=cache \
    GOARCH=${TARGETARCH} make -C proxylib all && mv proxylib/libcilium.so /tmp/libcilium.so

FROM --platform=$BUILDPLATFORM $BUILDER_BASE as builder-fresh
LABEL maintainer="maintainer@cilium.io"
WORKDIR /cilium/proxy
COPY . ./
COPY --from=proxylib /tmp/libcilium.so /tmp/install/usr/lib/libcilium.so
ARG V
ARG BAZEL_BUILD_OPTS
ARG DEBUG
ARG BUILDARCH
ARG TARGETARCH
ARG NO_CACHE
ENV TARGETARCH=$TARGETARCH
#
# Clear cache?
#
RUN --mount=target=/root/.cache,type=cache,id=$TARGETARCH,sharing=private if [ "z$NO_CACHE" = "z2" ]; then echo NO_CACHE=2 defined, clearing /root/.cache; rm -rf /root/.cache/*; fi
#
# Build dependencies
#
RUN --mount=target=/root/.cache,type=cache,id=$TARGETARCH,sharing=private BAZEL_BUILD_OPTS="${BAZEL_BUILD_OPTS} --disk_cache=/tmp/bazel-cache" PKG_BUILD=1 V=$V DEBUG=$DEBUG DESTDIR=/tmp/install make bazel-bin/cilium-envoy

# By default this stage picks up the result of the build above, but ARCHIVE_IMAGE can be
# overridden to point to a saved image of an earlier run of that stage.
# Must pick the TARGETPLATFORM image here, so NO --platform=$BUILDPLATFORM, otherwise cross-compilation
# will pick up build-artifacts for the build platform when an external image is used.
FROM $ARCHIVE_IMAGE as builder-cache

#
# Release builder, uses 'builder-cache' from $ARCHIVE_IMAGE
#
# Persist Bazel disk cache by passing COPY_CACHE=1
#
FROM --platform=$BUILDPLATFORM $BUILDER_BASE as builder
LABEL maintainer="maintainer@cilium.io"
WORKDIR /cilium/proxy
COPY . ./
COPY --from=proxylib /tmp/libcilium.so /tmp/install/usr/lib/libcilium.so
ARG V
ARG COPY_CACHE_EXT
ARG BAZEL_BUILD_OPTS
ARG DEBUG
ARG BUILDARCH
ARG TARGETARCH
ENV TARGETARCH=$TARGETARCH
RUN ./bazel/get_workspace_status
RUN --mount=target=/root/.cache,type=cache,id=$TARGETARCH,sharing=private \
    --mount=target=/tmp/bazel-cache,source=/tmp/bazel-cache,from=builder-cache,rw \
    BAZEL_BUILD_OPTS="${BAZEL_BUILD_OPTS} --disk_cache=/tmp/bazel-cache" PKG_BUILD=1 V=$V DEBUG=$DEBUG DESTDIR=/tmp/install make install && \
    if [ -n "${COPY_CACHE_EXT}" ]; then cp -ra /tmp/bazel-cache /tmp/bazel-cache${COPY_CACHE_EXT}; fi

FROM scratch as empty-builder-archive
LABEL maintainer="maintainer@cilium.io"
WORKDIR /tmp/bazel-cache

# This stage retains only the build caches from the previous step. This is used as the target for persisting
# Bazel build caches for later re-use.
FROM empty-builder-archive as builder-archive
ARG COPY_CACHE_EXT
COPY --from=builder /tmp/bazel-cache${COPY_CACHE_EXT}/ /tmp/bazel-cache/

#
# Extract installed cilium-envoy binaries to an otherwise empty image
#
FROM docker.io/library/ubuntu:22.04@sha256:6120be6a2b7ce665d0cbddc3ce6eae60fe94637c6a66985312d1f02f63cc0bcd
LABEL maintainer="maintainer@cilium.io"
# install ca-certificates package
RUN apt-get update && apt-get upgrade -y \
    && apt-get install --no-install-recommends -y ca-certificates \
    && apt-get autoremove -y && apt-get clean \
    && rm -rf /tmp/* /var/tmp/* \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /tmp/install /
