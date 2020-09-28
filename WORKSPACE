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
ENVOY_SHA = "923c4111bb48405ac96ef050c4f59ebbad3d7761"
ENVOY_SHA256 = "cb31aa7b63e2fb2349e51880f75fae718873f9b1fd06b6b44bf5cadc70172ac1"

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

http_archive(
    name = "envoy",
    sha256 = ENVOY_SHA256,
    strip_prefix = ENVOY_REPO + "-" + ENVOY_SHA,
    url = "https://github.com/" + ENVOY_PROJECT + "/" + ENVOY_REPO + "/archive/" + ENVOY_SHA + ".tar.gz",
    patches = [
        "@//patches:0001-docs-kick-off-1.14.5-release.-12165.patch",
        "@//patches:0002-tls-update-BoringSSL-FIPS-to-20190808.-12169.patch",
        "@//patches:0003-http1-Preserve-LWS-from-the-middle-of-HTTP1-header-v.patch",
        "@//patches:0004-1.14-http-header-map-security-fixes-for-duplicate-he.patch",
        "@//patches:original-dst-add-sni.patch",
        "@//patches:test-enable-half-close.patch",
        "@//patches:cross-aarch64.patch",
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

register_toolchains(
    "//bazel/toolchains:gcc_aarch64_cross_toolchain",
)
