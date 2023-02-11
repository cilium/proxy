load("@rules_cc//cc:defs.bzl", "cc_toolchain", "cc_toolchain_suite")
load(":cc_toolchain_config.bzl", "cc_toolchain_config")

# Using platform-provided files
filegroup(name = "empty")

toolchain(
    name = "aarch64_linux_cc_toolchain",
    toolchain = ":clang_aarch64_linux_cc_toolchain",
    toolchain_type = "@bazel_tools//tools/cpp:toolchain_type",
    target_compatible_with = [
        "@platforms//cpu:aarch64",
	"@platforms//os:linux",
    ],
    exec_compatible_with = ["@platforms//os:linux"],
)

cc_toolchain(
    name = "clang_aarch64_linux_cc_toolchain",
    all_files = ":empty",
    compiler_files = ":empty",
    dwp_files = ":empty",
    linker_files = ":empty",
    objcopy_files = ":empty",
    strip_files = ":empty",
    toolchain_config = ":clang_aarch64_linux_toolchain_config",
)

cc_toolchain_config(
    name = "clang_aarch64_linux_toolchain_config",
    abi_libc_version = "aarch64",
    abi_version = "aarch64",
    compile_flags = [
        "--target=aarch64-unknown-linux-gnu",
        "-fuse-ld=lld",                      # cmake compiler test needs this
        "-U_FORTIFY_SOURCE",
        "-fstack-protector",
        "-Wall",
        "-Wunused-but-set-parameter",
        "-Wno-free-nonheap-object",
        "-fno-omit-frame-pointer",
	# Needed by Envoy dependencies to build:
	"-Wno-unused-command-line-argument", # tcmalloc needs this since -fuse-ld was added above
	"-Wno-deprecated-builtins",
    ],
    compiler = "clang",
    coverage_compile_flags = ["--coverage"],
    coverage_link_flags = ["--coverage"],
    cpu = "aarch64",
    cxx_builtin_include_directories = [
        "/usr/lib/llvm-15",
	"/usr/aarch64-linux-gnu/include",
        "/usr/include",
    ],
    cxx_flags = ["-std=c++0x"],
    dbg_compile_flags = ["-g"],
    host_system_name = "local",
    link_flags = [
        "--target=aarch64-unknown-linux-gnu",
        "-fuse-ld=lld",
        "-Wl,-no-as-needed",
        "-Wl,-z,relro,-z,now",
        "-lm",
    ],
    link_libs = ["-l:libstdc++.a"],
    opt_compile_flags = [
        "-g0",
        "-O2",
        "-D_FORTIFY_SOURCE=1",
        "-DNDEBUG",
        "-ffunction-sections",
        "-fdata-sections",
    ],
    opt_link_flags = ["-Wl,--gc-sections"],
    supports_start_end_lib = True,
    target_libc = "glibc",
    target_system_name = "aarch64-linux-gnu",
    tool_paths = {
        "ar": "/usr/bin/llvm-ar-15",
        "compat-ld": "/usr/bin/lld-15",
        "ld": "/usr/bin/lld-15",
        "gold": "/usr/bin/lld-15",
        "cpp": "/usr/bin/clang-cpp-15",
        "gcc": "/usr/bin/clang-15",
        "dwp": "/usr/bin/llvm-dwp-15",
        "gcov": "/usr/bin/llvmcov-15",
        "nm": "/usr/bin/llvm-nm-15",
        "objcopy": "/usr/bin/llvm-objcopy-15",
        "objdump": "/usr/bin/llvm-objdump-15",
        "strip": "/usr/bin/llvm-strip-15",
    },
    toolchain_identifier = "linux_aarch64",
    unfiltered_compile_flags = [
        "-Wno-builtin-macro-redefined",
        "-D__DATE__=\"redacted\"",
        "-D__TIMESTAMP__=\"redacted\"",
        "-D__TIME__=\"redacted\"",
    ],
    #
    # cxx_builtin_include_directories entries need "" prefix if sysroot is set
    #
    # builtin_sysroot = "/sysroot",
)

toolchain(
    name = "x86_64_linux_cc_toolchain",
    toolchain = ":clang_x86_64_linux_cc_toolchain",
    toolchain_type = "@bazel_tools//tools/cpp:toolchain_type",
    target_compatible_with = [
        "@platforms//cpu:x86_64",
	"@platforms//os:linux",
    ],
    exec_compatible_with = ["@platforms//os:linux"],
)  

cc_toolchain(
    name = "clang_x86_64_linux_cc_toolchain",
    all_files = ":empty",
    compiler_files = ":empty",
    dwp_files = ":empty",
    linker_files = ":empty",
    objcopy_files = ":empty",
    strip_files = ":empty",
    toolchain_config = ":clang_x86_64_linux_toolchain_config",
)

cc_toolchain_config(
    name = "clang_x86_64_linux_toolchain_config",
    abi_libc_version = "unknown",
    abi_version = "unknown",
    compile_flags = [
        "--target=x86_64-unknown-linux-gnu",
        "-fuse-ld=lld",                      # cmake compiler test needs this
        "-U_FORTIFY_SOURCE",
        "-fstack-protector",
        "-Wall",
        "-Wunused-but-set-parameter",
        "-Wno-free-nonheap-object",
        "-fno-omit-frame-pointer",
	# Needed by Envoy dependencies to build:
	"-Wno-unused-command-line-argument", # tcmalloc needs this since -fuse-ld was added above
	"-Wno-deprecated-builtins",
    ],
    compiler = "clang",
    coverage_compile_flags = ["--coverage"],
    coverage_link_flags = ["--coverage"],
    cpu = "k8",
    cxx_builtin_include_directories = [
        "/usr/lib/llvm-15",
	"/usr/x86_64-linux-gnu/include",
        "/usr/include",
    ],
    cxx_flags = ["-std=c++0x"],
    dbg_compile_flags = ["-g"],
    host_system_name = "local",
    link_flags = [
        "--target=x86_64-unknown-linux-gnu",
        "-fuse-ld=lld",
        "-Wl,-no-as-needed",
        "-Wl,-z,relro,-z,now",
        "-lm",
    ],
    link_libs = ["-l:libstdc++.a"],
    opt_compile_flags = [
        "-g0",
        "-O2",
        "-D_FORTIFY_SOURCE=1",
        "-DNDEBUG",
        "-ffunction-sections",
        "-fdata-sections",
    ],
    opt_link_flags = ["-Wl,--gc-sections"],
    supports_start_end_lib = True,
    target_libc = "unknown",
    target_system_name = "unknown",
    tool_paths = {
        "ar": "/usr/bin/llvm-ar-15",
        "compat-ld": "/usr/bin/lld-15",
        "ld": "/usr/bin/lld-15",
        "gold": "/usr/bin/lld-15",
        "cpp": "/usr/bin/clang-cpp-15",
        "gcc": "/usr/bin/clang-15",
        "dwp": "/usr/bin/llvm-dwp-15",
        "gcov": "/usr/bin/llvmcov-15",
        "nm": "/usr/bin/llvm-nm-15",
        "objcopy": "/usr/bin/llvm-objcopy-15",
        "objdump": "/usr/bin/llvm-objdump-15",
        "strip": "/usr/bin/llvm-strip-15",
    },
    toolchain_identifier = "linux_x86_64",
    unfiltered_compile_flags = [
        "-Wno-builtin-macro-redefined",
        "-D__DATE__=\"redacted\"",
        "-D__TIMESTAMP__=\"redacted\"",
        "-D__TIME__=\"redacted\"",
    ],
    #
    # cxx_builtin_include_directories entries need "%sysroot%" prefix if sysroot is set
    #
    # builtin_sysroot = "/sysroot",
)

# still needed to avoid use of local_config_cc toolchain
cc_toolchain_suite(
    name = "toolchain",
    toolchains = {
        "k8": ":clang_x86_64_linux_cc_toolchain",
        "aarch64": ":clang_aarch64_linux_cc_toolchain",
    },
)
