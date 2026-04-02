"""Repository rule to provide llvm_toolchain_llvm when using a local LLVM toolchain.

When BAZEL_LLVM_PATH is set (local toolchain mode), the toolchains_llvm
llvm_toolchain() macro skips creating the llvm_toolchain_llvm repository.
Envoy's tools/clang-format target still depends on @llvm_toolchain_llvm//:clang-format,
so we need to provide it.
"""

def _local_llvm_repo_impl(repository_ctx):
    llvm_path = repository_ctx.os.environ.get("BAZEL_LLVM_PATH", "")
    clang_format = None

    if llvm_path:
        candidate = repository_ctx.path(llvm_path + "/bin/clang-format")
        if candidate.exists:
            clang_format = candidate

    if not clang_format:
        clang_format = repository_ctx.which("clang-format")

    if not clang_format:
        fail("Could not find clang-format. Set BAZEL_LLVM_PATH or ensure clang-format is on PATH.")

    repository_ctx.symlink(clang_format, "bin/clang-format")
    repository_ctx.file("BUILD.bazel", """\
package(default_visibility = ["//visibility:public"])

filegroup(
    name = "clang-format",
    srcs = ["bin/clang-format"],
)
""")

local_llvm_repo = repository_rule(
    implementation = _local_llvm_repo_impl,
    environ = ["BAZEL_LLVM_PATH", "PATH"],
    local = True,
)
