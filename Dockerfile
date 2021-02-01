# 
# BUILDER_BASE is a multi-platform image with all the build tools
#
ARG BUILDER_BASE=quay.io/cilium/cilium-envoy-builder:bazel-3.7.2@sha256:9c3c490b1741da420116d1cc6b3c13fce6f7b9f004955997d4ce853518839a04

#
# BUILDER_IMAGE defaults to the result of the first stage below,
# refreshing the build caches from Envoy dependencies before the final
# build stage. This can be overridden on docker build command line to
# use pre-built dependencies. Note that if cross-compiling, these
# pre-built dependencies will include BUILDPLATFORM build tools and
# TARGETPLATFORM build artifacts, and thus can only be reused when
# building on the same BUILDPLATFORM.
#
ARG BUILDER_IMAGE=builder-fresh
#
# Override this as "use-updated" to use pre-compiled bazel dependencies
#
ARG BUILDER=builder-fresh

FROM --platform=$BUILDPLATFORM $BUILDER_BASE as builder-fresh
LABEL maintainer="maintainer@cilium.io"
WORKDIR /cilium/proxy
COPY .bazelrc .bazelversion envoy.bazelrc Makefile.defs Makefile.quiet Makefile WORKSPACE BUILD SOURCE_VERSION ./
COPY bazel bazel
COPY patches patches
COPY tools tools
COPY envoy_build_config envoy_build_config
ARG V
ARG BAZEL_BUILD_OPTS
ARG BUILDARCH
ARG TARGETARCH

#
# Build dependencies
#
RUN [ "$BUILDARCH" = "$TARGETARCH" ] || CROSSARCH=$TARGETARCH && CROSSARCH=${CROSSARCH} BAZEL_BUILD_OPTS=${BAZEL_BUILD_OPTS} PKG_BUILD=1 V=$V DESTDIR=/tmp/install make envoy-deps-release

# By default this stage picks up the result of the build above, but BUILDER_IMAGE can be
# overridden to point to a saved image of an earlier run of that stage.
# Must pick the TARGETPLATFORM image here, so NO --platform=$BUILDPLATFORM, otherwise cross-compilation
# will pick up build-artifacts for the build platform when an external image is used.
FROM $BUILDER_IMAGE as builder-cache

# This stage retains only the build caches from the previous step. This is used as the target for persisting
# Bazel build caches for later re-use.
FROM scratch as builder-archive
LABEL maintainer="maintainer@cilium.io"
COPY --from=builder-cache /root/.cache/ /root/.cache/

# This stage copies over the pre-built target platform dependencies
# from builder-cache on top of a build platform builder base image.
# This is only used if $BUILDER is overridden as "use-updated"
# This avoids a large copy when not using pre-built deps.
#
FROM --platform=$BUILDPLATFORM $BUILDER_BASE as use-updated
LABEL maintainer="maintainer@cilium.io"
COPY --from=builder-cache /root/.cache/ /root/.cache/

FROM --platform=$BUILDPLATFORM $BUILDER as builder
LABEL maintainer="maintainer@cilium.io"
WORKDIR /cilium/proxy
COPY . ./
ARG V
ARG BAZEL_BUILD_OPTS
ARG BUILDARCH
ARG TARGETARCH

RUN ./tools/get_workspace_status
RUN [ "$BUILDARCH" = "$TARGETARCH" ] || CROSSARCH=$TARGETARCH && CROSSARCH=${CROSSARCH} BAZEL_BUILD_OPTS=${BAZEL_BUILD_OPTS} PKG_BUILD=1 V=$V DESTDIR=/tmp/install make install

#
# Extract installed cilium-envoy binaries to an otherwise empty image
#
FROM scratch
LABEL maintainer="maintainer@cilium.io"
COPY --from=builder /tmp/install /
