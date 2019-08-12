workspace(name = "cilium")

#
# We grep for the following line to generate SOURCE_VERSION file for non-git
# distribution builds. This line must start with the string ENVOY_SHA followed by
# an equals sign and a git SHA in double quotes.
#
# No other line in this file may have ENVOY_SHA followed by an equals sign!
#
ENVOY_SHA = "bf169f9d3c8f4c682650c5390c088a4898940913"
ENVOY_SHA256 = "f1ecdf7d636a8280db77d41b1a7e7669b6bb0cccb910bb039f7b76ce254b0e39"

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

http_archive(
    name = "envoy",
    url = "https://github.com/envoyproxy/envoy/archive/" + ENVOY_SHA + ".tar.gz",
    sha256 = ENVOY_SHA256,
    strip_prefix = "envoy-" + ENVOY_SHA,
    patches = [
        "@//patches:1.11.1-0001-http2-Limit-the-number-of-outbound-frames-9.patch",
        "@//patches:1.11.1-0002-http2-limit-the-number-of-inbound-frames.-20.patch",
        "@//patches:1.11.1-0003-http2-enable-strict-validation-of-HTTP-2-headers.-19.patch",
        "@//patches:1.11.1-0004-Always-disable-reads-when-connection-is-closed-with-.patch",
        "@//patches:1.11.1-0005-release-bump-to-1.11.1.patch",
        "@//patches:1.11.1-0006-Fix-flaky-http2-integration-tests-29.patch",
        "@//patches:1.11.1-0007-runtime-changing-snapshot-access-to-be-const-7677-26.patch",
        "@//patches:1.11.1-0008-runtime-making-runtime-accessible-from-non-worker-th.patch",
        "@//patches:1.11.1-0009-Disable-outbound-flood-mitigation-through-runtime-co.patch",
        "@//patches:1.11.1-0010-runtime-add-the-ability-to-log-downstream-HTTP-2-att.patch",
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
