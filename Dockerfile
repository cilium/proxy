#
# Cilium incremental build. Should be fast given builder-deps is up-to-date!
#
# cilium-builder tag is the Git SHA of the compatible build image commit.
# Keeping the old images available will allow older versions to be built
# while allowing the new versions to make changes that are not backwards compatible.
#
FROM quay.io/cilium/cilium-envoy-builder:acaaae73279e88f8d643d8089295e1a145fe5800@sha256:b6398eba65bd6ab6b9f3868ebe6511fb93acfe0ff08edbff0cbd641502b2d2da as builder
LABEL maintainer="maintainer@cilium.io"
WORKDIR /cilium/proxy
COPY . ./
ARG V
ARG BAZEL_BUILD_OPTS

#
# Install Bazel
#
RUN export BAZEL_VERSION=$(cat .bazelversion) \
	&& ARCH=$(uname -m) && [ "$ARCH" != "aarch64" ] || ARCH="arm64" \
	&& curl -sfL https://github.com/bazelbuild/bazel/releases/download/${BAZEL_VERSION}/bazel-${BAZEL_VERSION}-linux-${ARCH} -o /usr/bin/bazel \
	&& chmod +x /usr/bin/bazel

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
