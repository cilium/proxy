workspace(name = "cilium")

#
# We grep for the following line to generate SOURCE_VERSION file for non-git
# distribution builds. This line must start with the string ENVOY_SHA followed by
# an equals sign and a git SHA in double quotes.
#
# No other line in this file may have ENVOY_SHA followed by an equals sign!
#
ENVOY_PROJECT = "istio"
ENVOY_REPO = "envoy"
ENVOY_SHA = "fccea1f2b320fa56f4deae6c35007479e4fc3404"
ENVOY_SHA256 = "1078c146d15d4edd25c848bc318b67702e89ee6e618f0eea639711a526cad242"

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

# Dependencies for Istio filters.
# Cf. https://github.com/istio/proxy.
# Version 1.5.2
ISTIO_PROXY_SHA = "54fd05bc1e3e59a155651e5c84e4138d849e8d58"
ISTIO_PROXY_SHA256 = "feb631ccc4fb33472c8b0651f323bddbe4c1a0930fe0d4b58786d8d71682d196"

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
    "@istio_proxy//:repositories.bzl",
    "docker_dependencies",
    "googletest_repositories",
    "mixerapi_dependencies",
)
googletest_repositories()
mixerapi_dependencies()

bind(
    name = "boringssl_crypto",
    actual = "//external:ssl",
)

http_archive(
    name = "envoy",
    sha256 = ENVOY_SHA256,
    strip_prefix = ENVOY_REPO + "-" + ENVOY_SHA,
    url = "https://github.com/" + ENVOY_PROJECT + "/" + ENVOY_REPO + "/archive/" + ENVOY_SHA + ".tar.gz",
    patches = [
        "@//patches:wasm-undefined-result.patch",
        "@//patches:original-dst-add-sni.patch",
        "@//patches:test-enable-half-close.patch",
        "@//patches:add-getTransportSocketFactoryContext.patch",
    ],
    patch_args = ["-p1"],
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

load("@envoy//bazel:dependency_imports.bzl", "envoy_dependency_imports")
envoy_dependency_imports()

load("@rules_antlr//antlr:deps.bzl", "antlr_dependencies")
antlr_dependencies(471)

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
