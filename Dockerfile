#
# Cilium incremental build. Should be fast given builder-deps is up-to-date!
#
# cilium-builder tag is the Git SHA of the compatible build image commit.
# Keeping the old images available will allow older versions to be built
# while allowing the new versions to make changes that are not backwards compatible.
#
FROM quay.io/cilium/cilium-envoy-builder:1dbffdfc472eeaac0dd7b9f056cf03ad8bafeae2@sha256:50ad862fae1e58d3f4ce17f5a78ebc24320701c35125819504449958901fde45 as builder-refresh
LABEL maintainer="maintainer@cilium.io"
WORKDIR /cilium/proxy
COPY .bazelrc .bazelversion envoy.bazelrc Makefile.defs Makefile.quiet Makefile WORKSPACE BUILD SOURCE_VERSION ./
COPY bazel bazel
COPY patches patches
COPY tools tools
COPY envoy_build_config envoy_build_config
ARG V
ARG BAZEL_BUILD_OPTS

#
# Refresh Bazel build cache
#
RUN BAZEL_BUILD_OPTS=${BAZEL_BUILD_OPTS:---jobs=3} PKG_BUILD=1 V=$V DESTDIR=/tmp/install make envoy-deps-release

FROM builder-refresh as builder
LABEL maintainer="maintainer@cilium.io"
WORKDIR /cilium/proxy
COPY . ./
ARG V
ARG BAZEL_BUILD_OPTS

RUN ./tools/get_workspace_status
RUN BAZEL_BUILD_OPTS=${BAZEL_BUILD_OPTS:---jobs=3} PKG_BUILD=1 V=$V DESTDIR=/tmp/install make install

#
# Extract installed cilium-envoy binaries to an otherwise empty image
#
FROM scratch
LABEL maintainer="maintainer@cilium.io"
COPY --from=builder /tmp/install /
