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

# https://github.com/envoyproxy/envoy/tree/v1.21.2
# NOTE: Update version number to file 'ENVOY_VERSION' to keep test and build docker images
# for different versions.
ENVOY_SHA = "8c8c75fe7a2d3d2844da1de4cf66b09abf8e8227"
ENVOY_SHA256 = "e7e3059a841162a0a78e0939e3ac602f750325eb9b554334f3547362c94c421c"

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
