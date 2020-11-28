#
# Cilium incremental build. Should be fast given builder-deps is up-to-date!
#
# cilium-builder tag is the Git SHA of the compatible build image commit.
# Keeping the old images available will allow older versions to be built
# while allowing the new versions to make changes that are not backwards compatible.
#
FROM quay.io/cilium/cilium-envoy-builder:76f3cbc0cc348be7c51ce023f536b5bf008e76bd@sha256:af0211a709e41df3d39bf72f929011dee7a4c676b4f6ee1eb871ac5cabd784bb as builder
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
RUN BAZEL_BUILD_OPTS=${BAZEL_BUILD_OPTS:---jobs=2} PKG_BUILD=1 V=$V DESTDIR=/tmp/install make cilium-envoy install

#
# Extract installed cilium-envoy binaries to an otherwise empty image
#
FROM scratch
LABEL maintainer="maintainer@cilium.io"
COPY --from=builder /tmp/install /
