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

ENVOY_SHA = "21fe4496ca0c7798d6a9a747fdbf1ec1071e7f4f"

ENVOY_SHA256 = "4239723c5fb1b350aee9560655d94769835a9ac8c67fa42c355bdd1a7bbee204"

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
        "@//patches:test-enable-half-close.patch",
        "@//patches:test-double-server-create-timeout.patch",
        "@//patches:cross-aarch64.patch",
        "@//patches:envoy-unused-variables.patch",
	"@//patches:0001-bazel-Assume-default-compiler-is-gcc.patch",
	"@//patches:0001-bazel-Update-toolchains-to-3.7.2.patch",
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

register_toolchains(
    "//bazel/toolchains:gcc_aarch64_cross_toolchain",
)
