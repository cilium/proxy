load("@rules_cc//cc:defs.bzl", "cc_toolchain", "cc_toolchain_suite")
load(":cc_toolchain_config.bzl", "cc_toolchain_config")

platform(
    name = "gcc_aarch64_cross",
    constraint_values = [
        "@platforms//cpu:aarch64",
    ],
)

filegroup(
    name = "gcc_aarch64_cross_toolchain_files",
    srcs = glob([
        "aarch64-none-linux-gnu/**",
        "libexec/**",
        "lib/gcc/aarch64-none-linux-gnu/**",
        "include/**",
    ]),
    visibility = ["//visibility:private"],
)

cc_toolchain_suite(
    name = "toolchain",
    toolchains = {
        # Bazel requires to provide the k8 toolchain, but this toolchain should
        # be never used to producs k8 binaries!
        "k8": ":gcc_aarch64_cross_cc_toolchain",
        "aarch64-cross": ":gcc_aarch64_cross_cc_toolchain",
    },
)

cc_toolchain(
    name = "gcc_aarch64_cross_cc_toolchain",
    all_files = ":gcc_aarch64_cross_toolchain_files",
    compiler_files = ":gcc_aarch64_cross_toolchain_files",
    dwp_files = ":empty",
    linker_files = ":gcc_aarch64_cross_toolchain_files",
    objcopy_files = ":gcc_aarch64_cross_toolchain_files",
    strip_files = ":gcc_aarch64_cross_toolchain_files",
    supports_param_files = 1,
    toolchain_config = ":gcc_aarch64_cross_toolchain_config",
    toolchain_identifier = "aarch64-linux-gnu",
)

toolchain(
    name = "gcc_aarch64_cross_toolchain",
    exec_compatible_with = [
        "@platforms//cpu:x86_64",
    ],
    target_compatible_with = [
        "@platforms//cpu:aarch64",
    ],
    toolchain = ":gcc_aarch64_cross_cc_toolchain",
    toolchain_type = "@bazel_tools//tools/cpp:toolchain_type",
)

cc_toolchain_config(
    name = "gcc_aarch64_cross_toolchain_config",
    cpu = "aarch64",
    compiler = "gcc",
    toolchain_identifier = "cross_aarch64",
    host_system_name = "local",
    target_system_name = "aarch64-linux-gnu",
    target_libc = "aarch64",
    abi_version = "aarch64",
    abi_libc_version = "aarch64",
    cxx_builtin_include_directories = [
        "/usr/lib/gcc-cross/aarch64-linux-gnu/9/include",
        "/usr/aarch64-linux-gnu/include",
        "/usr/include",
        "/usr/aarch64-linux-gnu/include/c++/9",
        "/usr/aarch64-linux-gnu/include/c++/9/aarch64-linux-gnu",
        "/usr/aarch64-linux-gnu/include/c++/9/backward",
    ],
    tool_paths = {
        "ar": "/usr/bin/aarch64-linux-gnu-ar",
        "compat-ld": "/usr/bin/aarch64-linux-gnu-ld",
        "ld": "/usr/bin/aarch64-linux-gnu-ld",
        "cpp": "/usr/bin/aarch64-linux-gnu-cpp",
        "gcc": "/usr/bin/aarch64-linux-gnu-gcc",
        "dwp": "/usr/bin/aarch64-linux-gnu-dwp",
        "gcov": "/usr/bin/aarch64-linux-gnu-gcov",
        "nm": "/usr/bin/aarch64-linux-gnu-nm",
        "objcopy": "/usr/bin/aarch64-linux-gnu-objcopy",
        "objdump": "/usr/bin/aarch64-linux-gnu-objdump",
        "strip": "/usr/bin/aarch64-linux-gnu-strip",
    },
    compile_flags = [
        "-U_FORTIFY_SOURCE",
        "-fstack-protector",
        "-Wall",
        "-Wunused-but-set-parameter",
        "-Wno-free-nonheap-object",
        "-fno-omit-frame-pointer",
        # GCC uses unsigned char by default for all non-x86
        # architectures which breaks opentracing-cpp and
        # lightstep-tracer-cpp builds, as they are using
        # signed characters. Using signed char by default
        # fixes that.
        "-fsigned-char",
        # Disable assembly code in BoringSSL.
        # TODO(mrostecki): Fix BoringSSL assembly code for
        # aarch64.
        "-DOPENSSL_NO_ASM",
    ],
    opt_compile_flags = [
        "-g0",
        "-O2",
        "-D_FORTIFY_SOURCE=1",
        "-DNDEBUG",
        "-ffunction-sections",
        "-fdata-sections",
    ],
    dbg_compile_flags = ["-g"],
    cxx_flags = ["-std=c++0x"],
    link_flags = [
        "-Wl,-no-as-needed",
        "-Wl,-z,relro,-z,now",
        "-pass-exit-codes",
        "-lm",
    ],
    link_libs = ["-l:libstdc++.a"],
    opt_link_flags = ["-Wl,--gc-sections"],
    unfiltered_compile_flags = [
        "-fno-canonical-system-headers",
        "-Wno-builtin-macro-redefined",
        "-D__DATE__=\"redacted\"",
        "-D__TIMESTAMP__=\"redacted\"",
        "-D__TIME__=\"redacted\"",
    ],
    coverage_compile_flags = ["--coverage"],
    coverage_link_flags = ["--coverage"],
    supports_start_end_lib = False,
)

