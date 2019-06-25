#
# Cilium incremental build. Should be fast given builder-deps is up-to-date!
#
# cilium-builder tag is the Git SHA of the compatible build image commit.
# Keeping the old images available will allow older versions to be built
# while allowing the new versions to make changes that are not backwards compatible.
#
FROM quay.io/cilium/cilium-envoy-builder:b5f584caa50303115a3f7c059d5fdcf85e8eb8d5 as builder
LABEL maintainer="maintainer@cilium.io"
WORKDIR /go/src/github.com/cilium/cilium/envoy
COPY . ./
ARG V
#
# Please do not add any dependency updates before the 'make install' here,
# as that will mess with caching for incremental builds!
#
RUN make PKG_BUILD=1 V=$V DESTDIR=/tmp/install cilium-envoy install

#
# Extract installed cilium-envoy binaries to an otherwise empty image
#
FROM scratch
LABEL maintainer="maintainer@cilium.io"
COPY --from=builder /tmp/install /
