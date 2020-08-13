workspace(name = "cilium")

#
# We grep for the following line to generate SOURCE_VERSION file for non-git
# distribution builds. This line must start with the string ENVOY_SHA followed by
# an equals sign and a git SHA in double quotes.
#
# No other line in this file may have ENVOY_SHA followed by an equals sign!
#
ENVOY_ORG = "istio"
ENVOY_REPO = "envoy"

# Commit date: 2021-08-05
ENVOY_SHA = "2ef38514559c85721ccfc4cb43c446f261e478a2"
ENVOY_SHA256 = "fd985dffa9f0035de4e5396f069c90dffb40870a8fdbd02bc4a997b9e216815a"

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive", "http_file")

# Dependencies for Istio filters.
# Cf. https://github.com/istio/proxy.
# Version 1.10.4
# NOTE: Update version in file 'ENVOY_VERSION' to keep test and build docker images
# for different versions.
ISTIO_PROXY_SHA = "6a2597296110a21043af384282539739d996c0ad"
ISTIO_PROXY_SHA256 = "8890e7a04ce4cc18079bae2df633d16983ef2327c58a75c12a2a7c9946c62836"

http_archive(
    name = "istio_proxy",
    url = "https://github.com/istio/proxy/archive/" + ISTIO_PROXY_SHA + ".tar.gz",
    sha256 = ISTIO_PROXY_SHA256,
    strip_prefix = "proxy-" + ISTIO_PROXY_SHA,
    patches = [
    ],
    patch_args = ["-p1"],
)

load(
    "@istio_proxy//bazel:repositories.bzl",
    "docker_dependencies",
    "googletest_repositories",
    "istioapi_dependencies",
)

googletest_repositories()

istioapi_dependencies()

bind(
    name = "boringssl_crypto",
    actual = "//external:ssl",
)

local_repository(
    name = "envoy_build_config",
    path = "envoy_build_config",
)

http_archive(
    name = "envoy",
    patch_tool = "git",
    patch_args = ["apply"],
    patches = [
        "@//patches:0001-common-Fix-compile-for-Arm.patch",
        "@//patches:cross-aarch64.patch",
    ],
    sha256 = ENVOY_SHA256,
    strip_prefix = ENVOY_REPO + "-" + ENVOY_SHA,
    url = "https://github.com/" + ENVOY_ORG + "/" + ENVOY_REPO + "/archive/" + ENVOY_SHA + ".tar.gz",
)

#
# Bazel does not do transitive dependencies, so we must basically
# include all of Envoy's WORKSPACE file below, with the following
# changes:
# - Skip the 'workspace(name = "envoy")' line as we already defined
#   the workspace above.
# - loads of "//..." need to be renamed as "@envoy//..."
#

load("@envoy//bazel:api_binding.bzl", "envoy_api_binding")

envoy_api_binding()

load("@envoy//bazel:api_repositories.bzl", "envoy_api_dependencies")

envoy_api_dependencies()

load("@envoy//bazel:repositories.bzl", "envoy_dependencies")

envoy_dependencies()

load("@envoy//bazel:repositories_extra.bzl", "envoy_dependencies_extra")

envoy_dependencies_extra()

load("@envoy//bazel:dependency_imports.bzl", "envoy_dependency_imports")

envoy_dependency_imports()

register_toolchains(
    "//bazel/toolchains:gcc_aarch64_cross_toolchain",
)

# Bazel @rules_pkg

http_archive(
    name = "rules_pkg",
    sha256 = "aeca78988341a2ee1ba097641056d168320ecc51372ef7ff8e64b139516a4937",
    urls = [
        "https://github.com/bazelbuild/rules_pkg/releases/download/0.2.6-1/rules_pkg-0.2.6.tar.gz",
        "https://mirror.bazel.build/github.com/bazelbuild/rules_pkg/releases/download/0.2.6/rules_pkg-0.2.6.tar.gz",
    ],
)

load("@rules_pkg//:deps.bzl", "rules_pkg_dependencies")

rules_pkg_dependencies()

# Docker dependencies

docker_dependencies()

load(
    "@io_bazel_rules_docker//repositories:repositories.bzl",
    container_repositories = "repositories",
)

container_repositories()

load("@io_bazel_rules_docker//repositories:deps.bzl", container_deps = "deps")

container_deps()

load(
    "@io_bazel_rules_docker//container:container.bzl",
    "container_pull",
)

container_pull(
    name = "distroless_cc",
    # Latest as of 10/21/2019. To update, remove this line, re-build, and copy the suggested digest.
    digest = "sha256:86f16733f25964c40dcd34edf14339ddbb2287af2f7c9dfad88f0366723c00d7",
    registry = "gcr.io",
    repository = "distroless/cc",
)

container_pull(
    name = "bionic",
    # Latest as of 10/21/2019. To update, remove this line, re-build, and copy the suggested digest.
    digest = "sha256:3e83eca7870ee14a03b8026660e71ba761e6919b6982fb920d10254688a363d4",
    registry = "index.docker.io",
    repository = "library/ubuntu",
    tag = "bionic",
)

# End of docker dependencies

load("@istio_proxy//bazel:wasm.bzl", "wasm_dependencies")

wasm_dependencies()
