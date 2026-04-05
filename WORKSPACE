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

load("@bazel_gazelle//:deps.bzl", "go_repository")
load("@envoy//bazel:dependency_imports.bzl", "envoy_dependency_imports")

go_repository(
    name = "org_golang_x_text",
    build_external = "external",
    importpath = "golang.org/x/text",
    sum = "h1:B3njUFyqtHDUI5jMn1YIr5B0IE2U0qck04r6d4KPAxE=",
    version = "v0.33.0",
)

go_repository(
    name = "org_golang_x_tools",
    build_external = "external",
    importpath = "golang.org/x/tools",
    sum = "h1:a9b8iMweWG+S0OBnlU36rzLp20z1Rp10w+IY2czHTQc=",
    version = "v0.41.0",
)

go_repository(
    name = "org_golang_x_net",
    build_external = "external",
    importpath = "golang.org/x/net",
    sum = "h1:eeHFmOGUTtaaPSGNmjBKpbng9MulQsJURQUAfUwY++o=",
    version = "v0.49.0",
)

go_repository(
    name = "org_golang_x_sys",
    build_external = "external",
    importpath = "golang.org/x/sys",
    sum = "h1:omrd2nAlyT5ESRdCLYdm3+fMfNFE/+Rf4bDIQImRJeo=",
    version = "v0.42.0",
)

go_repository(
    name = "org_golang_x_mod",
    build_external = "external",
    importpath = "golang.org/x/mod",
    sum = "h1:9F4d3PHLljb6x//jOyokMv3eX+YDeepZSEo3mFJy93c=",
    version = "v0.32.0",
)

envoy_dependency_imports()

load("@envoy//bazel:repo.bzl", "envoy_repo")

envoy_repo()

load("@envoy//bazel:toolchains.bzl", "envoy_toolchains")

envoy_toolchains()

# When BAZEL_LLVM_PATH is set, envoy_toolchains() skips creating the
# llvm_toolchain_llvm repo, but envoy's clang-format target still depends on it.
# Provide it only if it wasn't already created.
load("//bazel:local_llvm.bzl", "local_llvm_repo")

local_llvm_repo(name = "llvm_toolchain_llvm")

load("@envoy//bazel:dependency_imports_extra.bzl", "envoy_dependency_imports_extra")

envoy_dependency_imports_extra()
