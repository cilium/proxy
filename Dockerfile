# 
# BUILDER_BASE is a multi-platform image with all the build tools
#
ARG BUILDER_BASE=quay.io/cilium/cilium-envoy-builder:bazel-5.1.1@sha256:9e94c4c6b5bca30e0fee62e652c9a7ef07b0feeb86d4eb12b068336d95887f31

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

FROM --platform=$BUILDPLATFORM $BUILDER_BASE as builder-fresh
LABEL maintainer="maintainer@cilium.io"
WORKDIR /cilium/proxy
COPY . ./
ARG V
ARG BAZEL_BUILD_OPTS
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
RUN --mount=target=/root/.cache,type=cache,id=$TARGETARCH,sharing=private BAZEL_BUILD_OPTS="${BAZEL_BUILD_OPTS} --disk_cache=/tmp/bazel-cache" PKG_BUILD=1 V=$V DESTDIR=/tmp/install make bazel-bin/cilium-envoy

# By default this stage picks up the result of the build above, but BUILDER_IMAGE can be
# overridden to point to a saved image of an earlier run of that stage.
# Must pick the TARGETPLATFORM image here, so NO --platform=$BUILDPLATFORM, otherwise cross-compilation
# will pick up build-artifacts for the build platform when an external image is used.
FROM $BUILDER_IMAGE as builder-cache

#
# Release builder, uses 'builder-cache' from $BUILDER_IMAGE
#
# Persist Bazel disk cache by passing COPY_CACHE=1
#
FROM --platform=$BUILDPLATFORM $BUILDER_BASE as builder
LABEL maintainer="maintainer@cilium.io"
WORKDIR /cilium/proxy
COPY . ./
ARG V
ARG COPY_CACHE_EXT
ARG BAZEL_BUILD_OPTS
ARG BUILDARCH
ARG TARGETARCH
ENV TARGETARCH=$TARGETARCH
RUN ./bazel/get_workspace_status
RUN --mount=target=/root/.cache,type=cache,id=$TARGETARCH,sharing=private \
    --mount=target=/tmp/bazel-cache,source=/tmp/bazel-cache,from=builder-cache,rw \
    BAZEL_BUILD_OPTS="${BAZEL_BUILD_OPTS} --disk_cache=/tmp/bazel-cache" PKG_BUILD=1 V=$V DESTDIR=/tmp/install make install && \
    if [ -n "${COPY_CACHE_EXT}" ]; then cp -ra /tmp/bazel-cache /tmp/bazel-cache${COPY_CACHE_EXT}; fi

# This stage retains only the build caches from the previous step. This is used as the target for persisting
# Bazel build caches for later re-use.
FROM scratch as builder-archive
LABEL maintainer="maintainer@cilium.io"
ARG COPY_CACHE_EXT
COPY --from=builder /tmp/bazel-cache${COPY_CACHE_EXT}/ /tmp/bazel-cache/

#
# Extract installed cilium-envoy binaries to an otherwise empty image
#
FROM scratch
LABEL maintainer="maintainer@cilium.io"
COPY --from=builder /tmp/install /
