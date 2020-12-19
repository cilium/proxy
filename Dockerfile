#
# Cilium incremental build. Should be fast given builder-deps is up-to-date!
#
# cilium-builder tag is the Git SHA of the compatible build image commit.
# Keeping the old images available will allow older versions to be built
# while allowing the new versions to make changes that are not backwards compatible.
#
FROM quay.io/cilium/cilium-envoy-builder:568e31eb9e77f8b3104ca601a64fd8c7d69bee8d@sha256:307ead606faed56590156117ae6526a369faafe5ab28644b0b5f067132fdd396 as builder
LABEL maintainer="maintainer@cilium.io"
WORKDIR /cilium/proxy
COPY . ./
ARG V
ARG BAZEL_BUILD_OPTS

#
# Please do not add any dependency updates before the 'make install' here,
# as that will mess with caching for incremental builds!
#
RUN ./tools/get_workspace_status
RUN BAZEL_BUILD_OPTS=${BAZEL_BUILD_OPTS:---jobs=2} PKG_BUILD=1 V=$V DESTDIR=/tmp/install make install

#
# Extract installed cilium-envoy binaries to an otherwise empty image
#
FROM scratch
LABEL maintainer="maintainer@cilium.io"
COPY --from=builder /tmp/install /
