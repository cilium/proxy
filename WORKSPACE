workspace(name = "cilium")

#
# We grep for the following line to generate SOURCE_VERSION file for non-git
# distribution builds. This line must start with the string ENVOY_SHA followed by
# an equals sign and a git SHA in double quotes.
#
# No other line in this file may have ENVOY_SHA followed by an equals sign!
#
ENVOY_SHA = "7a12f379e47a9f7cf7211c727fe8fc70b6a0a9ab"
ENVOY_SHA256 = "7f261db13976b9f1bc1b433b57d7e5f585d827c352a7c56f8c2e3e7196a63f0d"

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

http_archive(
    name = "envoy",
    url = "https://github.com/envoyproxy/envoy/archive/" + ENVOY_SHA + ".tar.gz",
    sha256 = ENVOY_SHA256,
    strip_prefix = "envoy-" + ENVOY_SHA,
    patches = [
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
load("@envoy//bazel:api_repositories.bzl", "envoy_api_dependencies")
envoy_api_dependencies()

load("@envoy//bazel:repositories.bzl", "envoy_dependencies", "GO_VERSION")
load("@envoy//bazel:cc_configure.bzl", "cc_configure")
envoy_dependencies()

load("@rules_foreign_cc//:workspace_definitions.bzl", "rules_foreign_cc_dependencies")
rules_foreign_cc_dependencies()

cc_configure()

load("@io_bazel_rules_go//go:deps.bzl", "go_register_toolchains", "go_rules_dependencies")
go_rules_dependencies()
go_register_toolchains(go_version = GO_VERSION)


# Dependencies for Istio filters.
# Cf. https://github.com/istio/proxy.
# Version 1.2.2
# ISTIO_PROXY_SHA = "a975561b980463f08689d3debe33bb9eefc80c3d"
# ISTIO_PROXY_SHA256 = "c0123fe73be4c9f2fe5e673952743ceb836f5972a8377ea876d90b7ab63af6eb"

#http_archive(
#    name = "istio_proxy",
#    url = "https://github.com/istio/proxy/archive/" + ISTIO_PROXY_SHA + ".tar.gz",
#    sha256 = ISTIO_PROXY_SHA256,
#    strip_prefix = "proxy-" + ISTIO_PROXY_SHA,
#)

#load("@istio_proxy//:repositories.bzl", "mixerapi_dependencies")
#mixerapi_dependencies()

#bind(
#    name = "boringssl_crypto",
#    actual = "//external:ssl",
#)
