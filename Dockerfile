# syntax = docker/dockerfile:experimental
#
# Cilium incremental build. Should be fast given builder-deps is up-to-date!
#
# cilium-builder tag is the Git SHA of the compatible build image commit.
# Keeping the old images available will allow older versions to be built
# while allowing the new versions to make changes that are not backwards compatible.
#
FROM quay.io/cilium/cilium-envoy-builder:a31e6f62f344735d9b23763f9855c06e0569916b@sha256:ab94eba1d5665c48163646c3696b3732a32d6192053c2b7260ce5171da90fedd as builder
LABEL maintainer="maintainer@cilium.io"
WORKDIR /go/src/github.com/cilium/cilium/envoy
COPY . ./
ARG V
ARG BAZEL_BUILD_OPTS

#
# Please do not add any dependency updates before the 'make install' here,
# as that will mess with caching for incremental builds!
#
RUN ./tools/get_workspace_status
RUN --mount=type=cache,target=/root/.cache/bazel BAZEL_BUILD_OPTS=${BAZEL_BUILD_OPTS:---jobs=4} PKG_BUILD=1 V=$V DESTDIR=/tmp/install make cilium-envoy install

#
# Extract installed cilium-envoy binaries to an otherwise empty image
#
FROM scratch
LABEL maintainer="maintainer@cilium.io"
COPY --from=builder /tmp/install /
