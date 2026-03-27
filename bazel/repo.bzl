# `@cilium_proxy_repo` repository rule for managing the repo and querying its metadata.

def _cilium_proxy_repo_impl(repository_ctx):
    """This provides information about the Envoy repository

    You can access the current project and api versions and the path to the repository in
    .bzl/BUILD files as follows:

    ```starlark
    load("@cilium_proxy_repo//:version.bzl", "VERSION", "API_VERSION")
    ```

    `*VERSION` can be used to derive version-specific rules and can be passed
    to the rules.

    The `VERSION`s and also the local `PATH` to the repo can be accessed in
    python libraries/binaries. By adding `@cilium_proxy_repo` to `deps` they become
    importable through the `cilium_proxy_repo` namespace.

    As the `PATH` is local to the machine, it is generally only useful for
    jobs that will run locally.

    This can be useful, for example, for bazel run jobs to run bazel queries that cannot be run
    within the constraints of a `genquery`, or that otherwise need access to the repository
    files.

    Project and repo data can be accessed in JSON format using `@cilium_proxy_repo//:project`, eg:

    ```starlark
    load("@aspect_bazel_lib//lib:jq.bzl", "jq")

    jq(
        name = "project_version",
        srcs = ["@cilium_proxy_repo//:data"],
        out = "version.txt",
        args = ["-r"],
        filter = ".version",
    )

    ```

    """
    repo_version_path = repository_ctx.path(repository_ctx.attr.envoy_version)
    api_version_path = repository_ctx.path(repository_ctx.attr.envoy_api_version)
    version = repository_ctx.read(repo_version_path).strip()
    api_version = repository_ctx.read(api_version_path).strip()
    repository_ctx.file("version.bzl", "VERSION = '%s'\nAPI_VERSION = '%s'" % (version, api_version))
    repository_ctx.file("path.bzl", "PATH = '%s'" % repo_version_path.dirname)
    repository_ctx.file("__init__.py", "PATH = '%s'\nVERSION = '%s'\nAPI_VERSION = '%s'" % (repo_version_path.dirname, version, api_version))
    repository_ctx.file("WORKSPACE", "")
    repository_ctx.file("BUILD", '''
load("@rules_python//python:defs.bzl", "py_library")
load("@rules_python//python/entry_points:py_console_script_binary.bzl", "py_console_script_binary")
load("//:path.bzl", "PATH")

py_library(
    name = "cilium_proxy_repo",
    srcs = ["__init__.py"],
    visibility = ["//visibility:public"],
)

''')

_cilium_proxy_repo = repository_rule(
    implementation = _cilium_proxy_repo_impl,
    attrs = {
        #todo(nezdolik) add cilium version
        "envoy_version": attr.label(default = "@envoy//:VERSION.txt"),
        "envoy_api_version": attr.label(default = "@envoy//:API_VERSION.txt"),
    },
)

def cilium_proxy_repo():
    if "cilium_proxy_repo" not in native.existing_rules().keys():
        _cilium_proxy_repo(name = "cilium_proxy_repo")
