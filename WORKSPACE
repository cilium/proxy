workspace(name = "cilium")

register_toolchains("//bazel/toolchains:all")

ENVOY_PROJECT = "envoyproxy"

ENVOY_REPO = "envoy"

#
# Envoy GIT commit SHA of release
#
# We grep for the following line to generate SOURCE_VERSION file for non-git
# distribution builds. This line must start with the string ENVOY_SHA followed by
# an equals sign and a git SHA in double quotes.
#
# No other line in this file may have ENVOY_SHA followed by an equals sign!
#
# renovate: datasource=github-releases depName=envoyproxy/envoy digestVersion=v1.23.8
ENVOY_SHA = "ae7ea959ac468ef21da6eb85e2892c8101a6eb54"

# // clang-format off: unexpected @bazel_tools reference, please indirect via a definition in //bazel
load("@bazel_tools//tools/build_defs/repo:git.bzl", "git_repository")
# // clang-format on

local_repository(
    name = "envoy_build_config",
    path = "envoy_build_config",
)

git_repository(
    name = "envoy",
    # // clang-format off: Envoy's format check: Only repository_locations.bzl may contains URL references
    remote = "https://github.com/envoyproxy/envoy.git",
    # // clang-format on
    commit = ENVOY_SHA,
    patch_args = ["apply"],
    patch_tool = "git",
    patches = [
        "@//patches:0001-network-Add-callback-for-upstream-authorization.patch",
        "@//patches:0002-upstream-Add-callback-for-upstream-authorization.patch",
        "@//patches:0003-connection-Make-isHalfCloseEnabled-const.patch",
        "@//patches:0004-tcp_proxy-Add-filter-state-proxy_read_before_connect.patch",
        "@//patches:0005-router-Do-not-set-SNI-or-SAN-due-to-auto_sni-or-auto.patch",
    ],
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

load("@envoy//bazel:python_dependencies.bzl", "envoy_python_dependencies")

envoy_python_dependencies()

load("@envoy//bazel:dependency_imports.bzl", "envoy_dependency_imports")

envoy_dependency_imports()
