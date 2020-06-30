workspace(name = "cilium")

#
# We grep for the following line to generate SOURCE_VERSION file for non-git
# distribution builds. This line must start with the string ENVOY_SHA followed by
# an equals sign and a git SHA in double quotes.
#
# No other line in this file may have ENVOY_SHA followed by an equals sign!
#
ENVOY_PROJECT = "envoyproxy"
ENVOY_REPO = "envoy"
ENVOY_SHA = "3921f8eb8c10cfc4d7cb8d20486aa889adedb2a1"
ENVOY_SHA256 = "e31a1d7cb7d79837dfbabc28ef844c2f6905ba5909982ca8164077020d6a5f2c"

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

http_archive(
    name = "envoy",
    sha256 = ENVOY_SHA256,
    strip_prefix = ENVOY_REPO + "-" + ENVOY_SHA,
    url = "https://github.com/" + ENVOY_PROJECT + "/" + ENVOY_REPO + "/archive/" + ENVOY_SHA + ".tar.gz",
    patches = [
        "@//patches:0001-Refactor-resource-manager-11182.patch",
        "@//patches:0002-listener-Add-configurable-accepted-connection-limits.patch",
        "@//patches:0003-overload-Runtime-configurable-global-connection-limi.patch",
        "@//patches:0004-http1-Include-request-URL-in-request-header-size-com.patch",
        "@//patches:0005-buffer-Add-on-drain-hook-to-buffer-API-and-use-it-to.patch",
        "@//patches:0006-http-2-add-stats-and-stream-flush-timeout-139.patch",
        "@//patches:0007-http2-fix-stream-flush-timeout-race-with-protocol-er.patch",
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
