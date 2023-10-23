# Envoy Upgrade

Occasionally, we need to bump Envoy minor release version to support new
upstream features, or for any security fixes with patch version.

The recent PR [#417](https://github.com/cilium/proxy/pull/417) can be used
as reference.

For the patch release, we normally just need to do [Update Envoy release commit hash](#update-envoy-release-commit-hash) most of the time.
If there is no security fix involved, we can just Renovate Bot to perform
the upgrade automatically.

### Sync up Bazel version

New Envoy minor version might require new Bazel version.

1. Update `.bazelversion` file.
2. Sync up `WORKSPACE` file with upstream.

```shell
# Building a new builder image locally with your own docker account
$ DOCKER_DEV_ACCOUNT=docker.io/sayboras ARCH=multi NO_CACHE=1 make docker-image-builder

# Export the builder image environment variable for later use
$ export BUILDER=docker.io/sayboras/cilium-envoy-builder:6.3.2-35ff82a25ab6321721eba727a1cc23fe7c240d5f@sha256:028da98e1c815d12250cc32327f3511016a859a027c0136d1ac7a4a178fbfe41
```

### Update Envoy release commit hash
1. Bump version in `ENVOY_VERSION` file.
2. Update git hash from Envoy official release in `WORKSPACE`.
3. Sync up `envoy_build_config/extensions_build_config.bzl` with upstream.

### Adjust Cilium custom patches

Currently, we are maintaining a couple of custom patches in `patches` directory.
These patches should be applied successfully on top of new Envoy baseline.

The easiest way to do this is to apply the patches on top of `envoyproxy/envoy` repository.

```shell
# Run `git am` command in `envoyproxy/envoy` repository with local patch files.
$ git am ../../cilium/proxy/patches/0001-network-Add-callback-for-upstream-authorization.patch
$ git am ../../cilium/proxy/patches/0002-upstream-Add-callback-for-upstream-authorization.patch
$ git am ../../cilium/proxy/patches/0003-tcp_proxy-Add-filter-state-proxy_read_before_connect.patch
$ git am ../../cilium/proxy/patches/0004-listener-add-socket-options.patch

# Export all the patch file, assume that we are upgrading to v1.28.
# Then you can copy these patch files to `cilium/proxy/patches` directory.
$ git format-patch upstream/release/v1.28
```

### Adjust Cilium custom filters

We are maintaining a couple of custom filters in `cilium` directory. The
easiest way is to just run the compilation and fix any issues coming up.

```shell
# Please refer to main README.md for the details of how to build.
$ DOCKER_DEV_ACCOUNT=docker.io/sayboras BUILDER_BASE=$BUILDER ARCH=multi NO_CACHE=1 make docker-image-envoy
```

### Update Envoy API

Double check if we need to update any dependency in `Makefile.api` godeps target, otherwise
just run `make api` and submit the changes.

The last step is to pray for CI to be green, and then merge it in :pray:.
