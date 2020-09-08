# syntax=docker/dockerfile:1.1-experimental

# Copyright 2020 Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

ARG COMPILERS_IMAGE=docker.io/cilium/image-compilers:32a185376865d6cb0f82d7339e311d998ab859c1

FROM --platform=linux/amd64 ${COMPILERS_IMAGE} as builder
ARG TARGETPLATFORM

ARG BAZEL_BUILD_OPTS="--jobs=3 --local_ram_resources 4096 --verbose_failures"
WORKDIR /src

RUN --mount=type=bind,readwrite,target=/src \
  make cilium-envoy install \
  BAZEL_BUILD_OPTS="${BAZEL_BUILD_OPTS}" \
  PKG_BUILD=1 \
  DESTDIR=/out/linux/amd64

RUN --mount=type=bind,readwrite,target=/src \
  make cilium-envoy install \
  BAZEL_BUILD_OPTS="${BAZEL_BUILD_OPTS} --incompatible_enable_cc_toolchain_resolution --platforms=//bazel/platforms:aarch64_cross --record_rule_instantiation_callstack --define cross=aarch64" \
  STRIP=aarch64-linux-gnu-strip \
  PKG_BUILD=1 \
  DESTDIR=/out/linux/arm64

FROM scratch
ARG TARGETPLATFORM
LABEL maintainer="maintainer@cilium.io"
COPY --from=builder /out/${TARGETPLATFORM} /
