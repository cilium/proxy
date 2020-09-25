# syntax=docker/dockerfile:1.1-experimental

# Copyright 2020 Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

ARG COMPILERS_IMAGE=docker.io/cilium/image-compilers:c1ba0665b6f9f012d014a642d9882f7c38bdf365

FROM --platform=linux/amd64 ${COMPILERS_IMAGE} as builder

ARG BAZEL_BUILD_EXTRA_OPTS
ARG BAZEL_BUILD_OPTS="--jobs=auto --experimental_local_memory_estimate --verbose_failures --disk_cache=/tmp/bazel-cache/cas --repository_cache=/tmp/bazel-cache/repository ${BAZEL_BUILD_EXTRA_OPTS}"

WORKDIR /src

RUN --mount=type=bind,readwrite,target=/src --mount=type=secret,id=gcp-service-account-key,target=/src/gcp-service-account-key.json --mount=type=cache,id=bazel-cache,target=/tmp/bazel-cache \
  df -h ; du -h -d 1 /tmp/bazel-cache

RUN --mount=type=bind,readwrite,target=/src --mount=type=secret,id=gcp-service-account-key,target=/src/gcp-service-account-key.json --mount=type=cache,id=bazel-cache,target=/tmp/bazel-cache \
  make cilium-envoy install \
  BAZEL_BUILD_OPTS="${BAZEL_BUILD_OPTS}" \
  PKG_BUILD=1 \
  DESTDIR=/out/linux/amd64

# otionally cleanup cached objects from disk since the amd64 objects cannot be re-used for cross-compilation
ARG PRUNE_DISK_CACHE=false
RUN --mount=type=bind,readwrite,target=/src --mount=type=secret,id=gcp-service-account-key,target=/src/gcp-service-account-key.json --mount=type=cache,id=bazel-cache,target=/tmp/bazel-cache \
  test "${PRUNE_DISK_CACHE}" = "true" && ( df -h ; du -sh /tmp/bazel-cache/cas ; rm -rf /tmp/bazel-cache/cas )

# output objects cannot be re-used in any way
RUN --mount=type=bind,readwrite,target=/src --mount=type=secret,id=gcp-service-account-key,target=/src/gcp-service-account-key.json --mount=type=cache,id=bazel-cache,target=/tmp/bazel-cache \
  df -h ; ls -la /src ; du -h -d 1 /src /root/.cache ; bazel clean --expunge ; df -h ; du -h -d 1 /src /root/.cache ; true ;

RUN --mount=type=bind,readwrite,target=/src --mount=type=secret,id=gcp-service-account-key,target=/src/gcp-service-account-key.json --mount=type=cache,id=bazel-cache,target=/tmp/bazel-cache \
  make cilium-envoy install \
  BAZEL_BUILD_OPTS="${BAZEL_BUILD_OPTS} --incompatible_enable_cc_toolchain_resolution --platforms=//bazel/platforms:aarch64_cross --define=cross=aarch64 --linkopt=\"-Wl,--reduce-memory-overheads\"" \
  STRIP=aarch64-linux-gnu-strip \
  PKG_BUILD=1 \
  DESTDIR=/out/linux/arm64 || (df -h ; du -h /tmp/bazel-cache ; exit 1 )

FROM scratch
ARG TARGETPLATFORM
LABEL maintainer="maintainer@cilium.io"
COPY images/cilium-envoy/empty /tmp/empty
COPY --from=builder /out/${TARGETPLATFORM} /
