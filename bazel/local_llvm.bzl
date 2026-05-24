"""Provide @llvm_toolchain_llvm when building with a local LLVM (BAZEL_LLVM_PATH).

In local LLVM mode envoy_toolchains() creates @llvm_toolchain_llvm without the
//:clang-format target that @envoy//tools/clang-format depends on. Pre-creating
the repo here (before envoy_toolchains(), which skips existing repos) adds that
target. No-op when BAZEL_LLVM_PATH is unset: the hermetic toolchain already
provides //:clang-format.
"""

load("@envoy_repo//:compiler.bzl", "LLVM_PATH")

# This repo replaces the one envoy_toolchains() would create, so it must define every
# target Envoy's _LLVM_LOCAL_BUILD (bazel/toolchains.bzl) does, plus clang-format. The
# globs below are deliberately a superset of Envoy's exact file lists so that upstream
# adding a file to _LLVM_LOCAL_BUILD does not silently break the local LLVM build.
_LLVM_LOCAL_BUILD = """\
package(default_visibility = ["//visibility:public"])

exports_files(glob(
    [
        "bin/*",
        "lib/**",
        "lib64/**",
        "include/**",
    ],
    allow_empty = True,
))

filegroup(
    name = "include",
    srcs = glob([
        "include/**/c++/**",
        "lib/clang/*/include/**",
    ]),
)

filegroup(
    name = "all_includes",
    srcs = glob(
        ["include/**"],
        allow_empty = True,
    ),
)

filegroup(
    name = "symbolizer",
    srcs = glob(["bin/llvm-symbolizer*"]),
)

filegroup(
    name = "clang-format",
    srcs = ["bin/clang-format"],
)
"""

def local_llvm_repo(name):
    if LLVM_PATH:
        native.new_local_repository(
            name = name,
            path = LLVM_PATH,
            build_file_content = _LLVM_LOCAL_BUILD,
        )
