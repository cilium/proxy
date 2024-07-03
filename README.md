# Cilium Proxy

[Envoy proxy](https://github.com/envoyproxy/envoy) for Cilium with
minimal Envoy extensions and Cilium policy enforcement filters. Cilium
uses this as its host proxy for enforcing HTTP and other L7 policies
as specified in [network
policies](https://docs.cilium.io/en/latest/concepts/kubernetes/policy/#k8s-policy)
for the cluster. Cilium proxy is distributed within the Cilium images.

## Version compatibility matrix

The following table shows the Cilium proxy version compatibility with supported upstream Cilium versions.
Other combinations may work but are not tested.

| Cilium Version | Envoy version |
|----------------|---------------|
| (main)         | v1.30.x       |
| v1.16.0        | v1.29.7       |
| v1.15.6        | v1.28.4       |
| v1.15.5        | v1.28.3       |
| v1.15.4        | v1.27.4       |
| v1.15.3        | v1.27.3       |
| v1.15.2        | v1.27.3       |
| v1.15.1        | v1.27.3       |
| v1.15.0        | v1.27.2       |
| v1.14.12       | v1.28.4       |
| v1.14.11       | v1.27.5       |
| v1.14.10       | v1.27.4       |
| v1.14.9        | v1.26.7       |
| v1.14.8        | v1.26.7       |
| v1.14.7        | v1.26.7       |
| v1.14.6        | v1.26.6       |
| v1.14.5        | v1.26.6       |
| v1.14.4        | v1.26.6       |
| v1.14.3        | v1.25.10      |
| v1.14.2        | v1.25.9       |
| v1.14.1        | v1.25.9       |
| v1.14.0        | v1.25.9       |
| v1.13.17       | v1.28.4       |
| v1.13.16       | v1.27.5       |
| v1.13.15       | v1.27.4       |
| v1.13.14       | v1.26.7       |
| v1.13.13       | v1.26.7       |
| v1.13.12       | v1.26.7       |
| v1.13.11       | v1.26.6       |
| v1.13.10       | v1.26.6       |
| v1.13.9        | v1.26.6       |
| v1.13.8        | v1.24.11      |
| v1.13.7        | v1.24.10      |
| v1.13.6        | v1.24.10      |
| v1.13.5        | v1.24.10      |
| v1.13.4        | v1.23.10      |
| v1.13.3        | v1.23.9       |
| v1.13.2        | v1.23.8       |
| v1.13.1        | v1.23.4       |
| v1.13.0        | v1.22.7       |


## Building

Cilium proxy is best built with the provided build containers. For a
local host build consult [the builder
Dockerfile](https://github.com/cilium/proxy/blob/main/Dockerfile.builder)
for the required dependencies.

Container builds require Docker Buildkit and optionally Buildx for
multi-arch builds. Builds are currently only supported for amd64 and
arm64 targets. For arm64 both native and cross compile on amd64 are
supported.  Container builds produce container images by
default. These images can not be run by themselves as they do not
contain the required runtime dependencies. To run the Cilium proxy the
binary `/usr/bin/cilium-envoy` needs to be copied from the image to a
compatible runtime environment, such as Ubuntu 20.04, or 22.04.

The provided container build tools work on both Linux and macOS.

To build the Cilium proxy in a docker container for the host
architecture only:

```
make docker-image-envoy
```

This will write the image to the local Docker registry.

Depending on hour host CPU and memory resources a fresh build can take
an hour or more. Docker caching will speed up subsequent builds.

> If your build fails due to a compiler failure the most likely reason
> is the compiler running out of memory. You can mitigate this by
> limiting the number of concurrent build jobs by passing environment
> variable `BAZEL_BUILD_OPTS=--jobs=2` to `make`. By default the
> number of jobs is the number of CPUs available for the build, and
> for some complex C++ sources this may be too much.  Note that
> changing the value of `BAZEL_BUILD_OPTS` invalidates Docker caches
> for the build stages.


### Multi-arch builds

Build target architecture can be specified by passing `ARCH`
environment variable to `make`. Supported values are `amd64` (only on
amd64 hosts), `arm64` (on arm64 or amd64 hosts), and `multi` (on amd64
hosts). `multi` builds for all the supported architectures, currrently
amd64 and arm64:

```
ARCH=multi make docker-image-envoy
```

This will try to push the images to the container registry. Appropriate
authentication is required. (Pushing to the local Docker registry isn't
supported for multi-arch builds. See [Docker documentation](https://docs.docker.com/reference/cli/docker/buildx/build/#docker))

Builds will be performed concurrently when building for multiple
architectures on a single machine. You most likely need to limit the
number of jobs allowed for each builder, see the note above for
details.

Docker builds are done using Docker Buildx by default when `ARCH` is
explicitly passed to `make`. You can also force Docker Buildx to be
used when building for the host platform only (by not defining `ARCH`)
by defining `DOCKER_BUILDX=1`. A new buildx builder instance will be
created for amd64 and arm64 cross builds if the current builder is set
to `default`.

> Buildx builds will push the build result to
> `quay.io/cilium/cilium-envoy:<GIT_SHA>` by default. You can change
> the first two parts of this by defining
> `DOCKER_DEV_ACCOUNT=docker.io/me` for your own docker hub account.
> You can also request the build results to be output to your local
> directory instead by defining `DOCKER_BUILD_OPTS=--output=out`,
> where `out` is a local directory name or use 
> `DOCKER_BUILD_OPTS="--output=type=docker"` to load it into the
> local Docker daemon.

#### Building for the Raspberry Pi kernel

By default Raspberry Pi OS and other OSes using the 
[Raspberry Pi kernel](https://github.com/raspberrypi/linux) will
not be able to use Envoy as their default `CONFIG_ARM64_VA_BITS_39`
configuration [is not compatible with tcmalloc](https://github.com/raspberrypi/linux/issues/4375).

A workaround is to compile the Envoy proxy with `gperftools`: 
```
ARCH=arm64 BAZEL_BUILD_OPTS="--define tcmalloc=gperftools" make docker-image-envoy
```

This image can then be used in the [Envoy DaemonSet mode](https://docs.cilium.io/en/stable/security/network/proxy/envoy/#enable-and-configure-envoy-daemonset).

### Using custom pre-compiled Envoy dependencies

Docker build uses cached Bazel artifacts from
`quay.io/cilium/cilium-envoy-builder:main-archive-latest` by
default. You can override this by defining `ARCHIVE_IMAGE=<ref>`:

```
ARCH=multi ARCHIVE_IMAGE=docker.io/me/cilium-envoy-archive make docker-image-envoy
```

> Bazel build artifacts contain toolchain specific data and binaries
> that are not compatible between native and cross-compiled
> builds. For now the image ref shown above is for builds on amd64
> only (native amd64, cross-compiled arm64).

Define `NO_CACHE=1` to clear the local build cache before the build, and `NO_ARCHIVE=1` to build
from scratch, but be warned that this can take a long time.

### Docker caching

By default the build also tries to pull Docker build caches from
`docker.io/cilium/cilium-dev:cilium-envoy-cache`. You can override
this with our own build cache, which you can also update with the
`CACHE_PUSH=1` definition:

```
ARCH=multi CACHE_REF=docker.io/me/cilium-proxy:cache CACHE_PUSH=1 make docker-image-envoy
```

`NO_CACHE=1` can be used to disable docker cache pulling.

In a CI environment it might be a good idea to push a new cache image
after each main branch commit.


### Updating the pre-compiled Envoy dependencies

Build and push a new version of the pre-compiled Envoy dependencies by:

```
ARCH=multi make docker-builder-archive
```

By default the pre-compiled dependencies image is tagged as
`quay.io/cilium/cilium-envoy-builder:main-archive-latest`. You
can override the first two parts of this by defining
`DOCKER_DEV_ACCOUNT=docker.io/me`,
`BUILDER_ARCHIVE_TAG=my-builder-archive`, or completely by defining
`ARCHIVE_IMAGE=<ref>`.

Pre-compiled Envoy dependencies need to be updated only when Envoy
version is updated or patched enough to increase compilation time
significantly. To do this you should update Envoy version in
`ENVOY_VERSION` and supply `NO_CACHE=1` and `NO_ARCHIVE=1` on the make line, e.g.:

```
ARCH=multi NO_CACHE=1 NO_ARCHIVE=1 BUILDER_ARCHIVE_TAG=main-archive-latest make docker-builder-archive
```


## Updating the builder image

The required Bazel version typically changes from one Envoy release to
another. To create a new builder image first update the required Bazel
version at `.bazelversion` and then run:

```
ARCH=multi NO_CACHE=1 NO_ARCHIVE=1 make docker-image-builder
```

The builder can not be cross-compiled as native build tools are needed
for native arm64 builds. This means that for non-native builds QEMU
CPU emulation is used instead of cross-compilation. If you have an
arm64 machine you can create a Docker buildx builder to use it for
native builds.

The builder image is tagged as
"quay.io/cilium/cilium-envoy-builder:bazel-<version>". Change the
BUILDER_BASE ARG in `Dockerfile` to use the new builder and commit the
result.

For testing purposes you can define `DOCKER_DEV_ACCOUNT` as explained
above to push the builder into a different registry or account.


## Running integration tests

To run Cilium Envoy integration tests in a docker container:

```
make docker-tests
```

This runs the integration tests after loading Bazel build cache for
Envoy dependencies from
`quay.io/cilium/cilium-envoy-builder:test-main-archive-latest`. Define
`NO_ARCHIVE=1` and `NO_CACHE=1` to compile tests from scratch.

This command fails if any of the integration tests fail, printing the
failing test logs on console.

> Note that cross-compiling is not supported for running tests, so
> specifying `ARCH` is only supported for the native platform.
> `ARCH=multi` will fail.


### Updating the pre-compiled Envoy test dependencies

Build and push a new version of the pre-compiled test dependencies by:

```
make docker-tests-archive
```

By default the pre-compiled test dependencies image is tagged as
`quay.io/cilium/cilium-envoy-builder:test-main-archive-latest`. You
can override the first two parts of this by defining
`DOCKER_DEV_ACCOUNT=docker.io/me`,
`TESTS_ARCHIVE_TAG=my-test-archive`, or completely by defining
`ARCHIVE_IMAGE=<ref>`.

Pre-compiled Envoy test dependencies need to be updated only when
Envoy version is updated or patched enough to increase compilation
time significantly. To do this you should update Envoy version
in `ENVOY_VERSION` and supply `NO_ARCHIVE=1` and `NO_CACHE=1` on
the make line, e.g.:

```
ARCH=amd64 NO_ARCHIVE=1 NO_CACHE=1 make docker-tests-archive
```


## Updating generated API

[Cilium project](https://github.com/cilium/cilium) vendors the Envoy
xDS API, including Cilium extensions, from this repository. To update
the generated API files, run:

```
rm -r go/envoy/*
make api
```

`rm` is needed to clean up API files that are no longer generated for
Envoy. **Do not** remove files at `go/cilium/` as some of them are not
automatically generated!

Commit the results and update
[Cilium](https://github.com/cilium/cilium) to vendor this new commit.
