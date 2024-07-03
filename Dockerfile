# 
# BUILDER_BASE is a multi-platform image with all the build tools
#
ARG BUILDER_BASE=quay.io/cilium/cilium-envoy-builder:6.1.0-latest

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

FROM --platform=$BUILDPLATFORM $BUILDER_BASE AS proxylib
WORKDIR /go/src/github.com/cilium/proxy
COPY --chown=1337:1337 . ./
ARG TARGETARCH
ENV TARGETARCH=$TARGETARCH
RUN --mount=mode=0777,gid=1337,uid=1337,target=/cilium/proxy/.cache,type=cache \
    --mount=mode=0777,gid=1337,uid=1337,target=/go/pkg,type=cache \
    PATH=$PATH:/usr/local/go/bin GOARCH=${TARGETARCH} make -C proxylib all && mv proxylib/libcilium.so /tmp/libcilium.so

FROM --platform=$BUILDPLATFORM $BUILDER_BASE AS builder-fresh
LABEL maintainer="maintainer@cilium.io"
WORKDIR /cilium/proxy
COPY . ./
ARG V
ARG BAZEL_BUILD_OPTS
ARG DEBUG
ARG BUILDARCH
ARG TARGETARCH
ENV TARGETARCH=$TARGETARCH
#
# Clear runner's cache when building deps
#
RUN --mount=mode=0777,uid=1337,gid=1337,target=/cilium/proxy/.cache,type=cache,id=$TARGETARCH,sharing=private rm -rf /cilium/proxy/.cache/*
#
# Build dependencies from scratch (no cache mounts, not archive mount)
#
RUN BAZEL_BUILD_OPTS="${BAZEL_BUILD_OPTS} --disk_cache=/tmp/bazel-cache" PKG_BUILD=1 V=$V DEBUG=$DEBUG DESTDIR=/tmp/install make bazel-bin/cilium-envoy-starter bazel-bin/cilium-envoy

# By default this stage picks up the result of the build above, but ARCHIVE_IMAGE can be
# overridden to point to a saved image of an earlier run of that stage.
# Must pick the TARGETPLATFORM image here, so NO --platform=$BUILDPLATFORM, otherwise cross-compilation
# will pick up build-artifacts for the build platform when an external image is used.
FROM $ARCHIVE_IMAGE AS builder-cache

#
# Release builder, uses 'builder-cache' from $ARCHIVE_IMAGE
#
# Persist Bazel disk cache by passing COPY_CACHE=1
#
FROM --platform=$BUILDPLATFORM $BUILDER_BASE AS builder
LABEL maintainer="maintainer@cilium.io"
WORKDIR /cilium/proxy
COPY . ./
ARG V
ARG COPY_CACHE_EXT
ARG BAZEL_BUILD_OPTS
ARG DEBUG
ARG BUILDARCH
ARG TARGETARCH
ENV TARGETARCH=$TARGETARCH
RUN ./bazel/get_workspace_status
RUN --mount=mode=0777,uid=1337,gid=1337,target=/cilium/proxy/.cache,type=cache,id=$TARGETARCH,sharing=private \
    --mount=target=/tmp/bazel-cache,source=/tmp/bazel-cache,from=builder-cache,rw \
    if [ -f /tmp/bazel-cache/ENVOY_VERSION ]; then CACHE_ENVOY_VERSION=`cat /tmp/bazel-cache/ENVOY_VERSION`; ENVOY_VERSION=`cat ENVOY_VERSION`; if [ "${CACHE_ENVOY_VERSION}" != "${ENVOY_VERSION}" ]; then echo "Building Envoy ${ENVOY_VERSION} with bazel archive from different Envoy version (${CACHE_ENVOY_VERSION})"; else echo "Building Envoy ${ENVOY_VERSION} with bazel cache of the same version"; fi; else echo "Bazel cache has no ENVOY_VERSION, it may be empty."; fi && \
    touch /tmp/bazel-cache/permissions-check && \
    if [ -n "${COPY_CACHE_EXT}" ]; then PKG_BUILD=1 make BUILD_DEP_HASHES; if [ -f /tmp/bazel-cache/BUILD_DEP_HASHES ] && ! diff BUILD_DEP_HASHES /tmp/bazel-cache/BUILD_DEP_HASHES; then echo "Build dependencies have changed, clearing bazel cache"; rm -rf /tmp/bazel-cache/*; rm -rf /cilium/proxy/.cache/*; fi ; cp BUILD_DEP_HASHES ENVOY_VERSION /tmp/bazel-cache; fi && \
    BAZEL_BUILD_OPTS="${BAZEL_BUILD_OPTS} --disk_cache=/tmp/bazel-cache" PKG_BUILD=1 V=$V DEBUG=$DEBUG DESTDIR=/tmp/install make install && \
    if [ -n "${COPY_CACHE_EXT}" ]; then cp -ra /tmp/bazel-cache /tmp/bazel-cache${COPY_CACHE_EXT}; ls -la /tmp/bazel-cache${COPY_CACHE_EXT}; fi
#
# Copy proxylib after build to allow install as non-root to succeed
#
COPY --from=proxylib /tmp/libcilium.so /tmp/install/usr/lib/libcilium.so

FROM scratch AS empty-builder-archive
LABEL maintainer="maintainer@cilium.io"
USER 1337:1337
WORKDIR /tmp/bazel-cache

# This stage retains only the build caches from the previous step. This is used as the target for persisting
# Bazel build caches for later re-use.
FROM empty-builder-archive AS builder-archive
ARG COPY_CACHE_EXT
COPY --from=builder /tmp/bazel-cache${COPY_CACHE_EXT}/ /tmp/bazel-cache/

# Format check
FROM --platform=$BUILDPLATFORM $BUILDER_BASE AS check-format
LABEL maintainer="maintainer@cilium.io"
WORKDIR /cilium/proxy
COPY --chown=1337:1337 . ./
ARG V
ARG BAZEL_BUILD_OPTS
ARG DEBUG
ENV TARGETARCH=$TARGETARCH
#
# Check format
#
RUN BAZEL_BUILD_OPTS="${BAZEL_BUILD_OPTS}" PKG_BUILD=1 V=$V DEBUG=$DEBUG make V=1 check > format-output.txt

FROM scratch AS format
COPY --from=check-format /cilium/proxy/format-output.txt /

#
# Extract installed cilium-envoy binaries to an otherwise empty image
#
FROM docker.io/library/ubuntu:22.04@sha256:340d9b015b194dc6e2a13938944e0d016e57b9679963fdeb9ce021daac430221
LABEL maintainer="maintainer@cilium.io"
# install ca-certificates package
RUN apt-get update && apt-get upgrade -y \
    && apt-get install --no-install-recommends -y ca-certificates \
    && apt-get autoremove -y && apt-get clean \
    && rm -rf /tmp/* /var/tmp/* \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /tmp/install /
