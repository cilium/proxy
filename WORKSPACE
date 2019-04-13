workspace(name = "cilium")

#
# We grep for the following line to generate SOURCE_VERSION file for non-git
# distribution builds. This line must start with the string ENVOY_SHA followed by
# an equals sign and a git SHA in double quotes.
#
# No other line in this file may have ENVOY_SHA followed by an equals sign!
#
ENVOY_SHA = "ac7aa5ac8a815e5277b4d4659c5c02145fa1d56f"
ENVOY_SHA256 = "3f13facc893ef0c5063c7391a1ffca8de0f52425c8a7a49ef45e69dbb5e7304b"

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

http_archive(
    name = "envoy",
    url = "https://github.com/envoyproxy/envoy/archive/" + ENVOY_SHA + ".tar.gz",
    sha256 = ENVOY_SHA256,
    strip_prefix = "envoy-" + ENVOY_SHA,
)

#
# Bazel does not do transitive dependencies, so we must basically
# include all of Envoy's WORKSPACE file below, with the following
# changes:
# - Skip the 'workspace(name = "envoy")' line as we already defined
#   the workspace above.
# - loads of "//..." need to be renamed as "@envoy//..."
#
load("@envoy//bazel:api_repositories.bzl", "envoy_api_dependencies")
envoy_api_dependencies()

load("@envoy//bazel:repositories.bzl", "GO_VERSION", "envoy_dependencies")
envoy_dependencies()

load("@rules_foreign_cc//:workspace_definitions.bzl", "rules_foreign_cc_dependencies")
rules_foreign_cc_dependencies()

load("@envoy//bazel:cc_configure.bzl", "cc_configure")
cc_configure()

load("@io_bazel_rules_go//go:deps.bzl", "go_register_toolchains", "go_rules_dependencies")
go_rules_dependencies()
go_register_toolchains(go_version = GO_VERSION)


# Dependencies for Istio filters.
# Cf. https://github.com/istio/proxy.

ISTIO_PROXY_SHA = "a169a0c0cd86b51538c240e2d037fa8f7f5860ae"
ISTIO_PROXY_SHA256 = "2fe34b4fe6aca9fdb3f0b5a9361b5a9e2ee27d5768780ccb312fed61c9684d47"

http_archive(
    name = "istio_proxy",
    url = "https://github.com/istio/proxy/archive/" + ISTIO_PROXY_SHA + ".tar.gz",
    sha256 = ISTIO_PROXY_SHA256,
    strip_prefix = "proxy-" + ISTIO_PROXY_SHA,
)

load("@istio_proxy//:repositories.bzl", "mixerapi_dependencies")
mixerapi_dependencies()

bind(
    name = "boringssl_crypto",
    actual = "//external:ssl",
)
