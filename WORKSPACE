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

# https://github.com/envoyproxy/envoy/tree/v1.21.2 (Tam: Update to v1.21.3 later)
# NOTE: Update version number to file 'ENVOY_VERSION' to keep test and build docker images
# for different versions.
# The below is latest commit from release/1.21 branch
ENVOY_SHA = "bcd22abe760928dd2b44c4e9f02f2ddc01ca7857"
ENVOY_SHA256 = "feecdb7a07e22aaadd9c6995f8065519bc0630c2e0321caedc7be8258719baae"

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

local_repository(
    name = "envoy_build_config",
    path = "envoy_build_config",
)

http_archive(
    name = "envoy",
    patch_tool = "git",
    patch_args = ["apply"],
    patches = [
        "@//patches:cross-aarch64.patch",
        "@//patches:clang-for-bpf.patch",
        "@//patches:unreferenced-parameters.patch",
        "@//patches:envoy-upstream-network-auth.patch",
        "@//patches:envoy-upstream-http-auth.patch",
        "@//patches:0001-decompressors-stop-decompressing-upon-excessive-comp.patch",
        "@//patches:0002-healthcheck-fix-grpc-inline-removal-crashes-749.patch",
        "@//patches:0003-oauth2-do-not-blindly-accept-requests-with-a-token-i.patch",
        "@//patches:0004-internal-redirect-fix-a-lifetime-bug-785.patch",
    ],
    sha256 = ENVOY_SHA256,
    strip_prefix = ENVOY_REPO + "-" + ENVOY_SHA,
    url = "https://github.com/" + ENVOY_PROJECT + "/" + ENVOY_REPO + "/archive/" + ENVOY_SHA + ".tar.gz",
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
