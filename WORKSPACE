workspace(name = "cilium")

ENVOY_PROJECT = "envoyproxy"

ENVOY_REPO = "envoy"

# Envoy GIT commit SHA of release
#
# We grep for the following line to generate SOURCE_VERSION file for non-git
# distribution builds. This line must start with the string ENVOY_SHA followed by
# an equals sign and a git SHA in double quotes.
#
# No other line in this file may have ENVOY_SHA followed by an equals sign!
#
# renovate: datasource=github-releases depName=envoyproxy/envoy digestVersion=v1.37.1
ENVOY_SHA = "5ef4e4cea57f63e7e2970b9c1ad696278db927d6"

# // clang-format off: unexpected @bazel_tools reference, please indirect via a definition in //bazel
load("@bazel_tools//tools/build_defs/repo:git.bzl", "git_repository")
# // clang-format on

local_repository(
    name = "envoy_build_config",
    path = "envoy_build_config",
)

# This is a local repository for local development instead of git repository for faster feedback loop
#local_repository(
#    name = "envoy",
#    # Update the path to point to your local Envoy repository.
#    path = "/home/tammach/go/src/github.com/envoyproxy/envoy",
#)

git_repository(
    name = "envoy",
    commit = ENVOY_SHA,
    patch_args = ["apply"],
    patch_tool = "git",
    patches = [
        "@//patches:0001-network-Add-callback-for-upstream-authorization.patch",
        "@//patches:0002-listener-add-socket-options.patch",
        "@//patches:0003-original_dst_cluster-Avoid-multiple-hosts-for-the-sa.patch",
        "@//patches:0004-thread_local-reset-slot-in-worker-threads-first.patch",
        "@//patches:0005-http-header-expose-attribute.patch",
        "@//patches:0006-build-Fix-arm-build-for-liburing.patch",
        "@//patches:0007-Add-latomic-back-for-arm-build.patch",
        "@//patches:0008-repo-Make-yq-dependency-optional-for-CI-config-parsi.patch",
    ],
    # // clang-format off: Envoy's format check: Only repository_locations.bzl may contains URL references
    remote = "https://github.com/envoyproxy/envoy.git",
    # // clang-format on
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

load("@envoy//bazel:bazel_deps.bzl", "envoy_bazel_dependencies")

envoy_bazel_dependencies()

load("@envoy//bazel:repositories_extra.bzl", "envoy_dependencies_extra")

envoy_dependencies_extra()

load("@envoy//bazel:python_dependencies.bzl", "envoy_python_dependencies")

envoy_python_dependencies()

load("@envoy//bazel:dependency_imports.bzl", "envoy_dependency_imports")

# Pre-declare key Go repos before envoy_dependency_imports() so they are known
# to Gazelle's go_repository_config (which is created by gazelle_dependencies()
# inside envoy_dependency_imports). Without these, Gazelle's BUILD generation
# for go_repository targets can't resolve cross-repo dependencies.
load("@bazel_gazelle//:deps.bzl", "go_repository")

go_repository(
    name = "org_golang_x_text",
    importpath = "golang.org/x/text",
    sum = "h1:zyQAAkrwaneQ066sspRyJaG9VNi/YJ1NfzcGB3hZ/qo=",
    version = "v0.21.0",
    build_external = "external",
)

go_repository(
    name = "org_golang_x_tools",
    importpath = "golang.org/x/tools",
    sum = "h1:Iey4qkscZuv0VvIt8E0neZjtPVQFSc870HQ448QgEmQ=",
    version = "v0.13.0",
    build_external = "external",
)

go_repository(
    name = "org_golang_x_net",
    importpath = "golang.org/x/net",
    sum = "h1:Mb7Mrk043xzHgnRM88suvJFwzVrRfHEHJEl5/71CKw0=",
    version = "v0.34.0",
    build_external = "external",
)

go_repository(
    name = "org_golang_x_sys",
    importpath = "golang.org/x/sys",
    sum = "h1:TPYlXGxIudtjnhMUyEBNIuqx3IKcJBx+JGEIGy0Wms=",
    version = "v0.29.0",
    build_external = "external",
)

go_repository(
    name = "org_golang_x_mod",
    importpath = "golang.org/x/mod",
    sum = "h1:zY54UmvipHiNd+pm+m0x9KhZ9hl1/7QNMyxXbc6ICqA=",
    version = "v0.15.0",
    build_external = "external",
)

envoy_dependency_imports()

load("@envoy//bazel:repo.bzl", "envoy_repo")

envoy_repo()

load("@envoy//bazel:toolchains.bzl", "envoy_toolchains")

envoy_toolchains()

load("@envoy//bazel:dependency_imports_extra.bzl", "envoy_dependency_imports_extra")

envoy_dependency_imports_extra()
