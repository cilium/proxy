#
# Cilium incremental build. Should be fast given builder-deps is up-to-date!
#
# cilium-builder tag is the Git SHA of the compatible build image commit.
# Keeping the old images available will allow older versions to be built
# while allowing the new versions to make changes that are not backwards compatible.
#
FROM quay.io/cilium/cilium-envoy-builder:b5722f7b65f7a85027ef27637fd7d05051517cde@sha256:847017d6549637213f5b8501fd8812f2bef95136d0a7ea117859391684ac033f as builder
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
RUN BAZEL_BUILD_OPTS=${BAZEL_BUILD_OPTS:---jobs=2 --local_resources 3072,1.5,1.0} PKG_BUILD=1 V=$V DESTDIR=/tmp/install make cilium-envoy install

#
# Extract installed cilium-envoy binaries to an otherwise empty image
#
FROM scratch
LABEL maintainer="maintainer@cilium.io"
COPY --from=builder /tmp/install /
