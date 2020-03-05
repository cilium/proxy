#
# Cilium incremental build. Should be fast given builder-deps is up-to-date!
#
# cilium-builder tag is the Git SHA of the compatible build image commit.
# Keeping the old images available will allow older versions to be built
# while allowing the new versions to make changes that are not backwards compatible.
#
FROM quay.io/cilium/cilium-envoy-builder:b9ecc40463e0370048b9b28e9d643e3a212c9094 as builder
LABEL maintainer="maintainer@cilium.io"
WORKDIR /go/src/github.com/cilium/cilium/envoy
COPY . ./
ARG V
#
# Please do not add any dependency updates before the 'make install' here,
# as that will mess with caching for incremental builds!
#
RUN ./tools/get_workspace_status
RUN make BAZEL_BUILD_OPTS=--jobs=2 PKG_BUILD=1 V=$V DESTDIR=/tmp/install cilium-envoy install

#
# Extract installed cilium-envoy binaries to an otherwise empty image
#
FROM scratch
LABEL maintainer="maintainer@cilium.io"
COPY --from=builder /tmp/install /
