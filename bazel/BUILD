constraint_setting(
    name = "cilium_target_platform",
    visibility = ["//visibility:public"],
)

constraint_value(
    name = "cilium_target_platform_enabled",
    constraint_setting = ":cilium_target_platform",
    visibility = ["//visibility:public"],
)

platform(
    name = "linux_aarch64",
    constraint_values = [
        ":cilium_target_platform_enabled",
        "@platforms//cpu:aarch64",
        "@platforms//os:linux",
    ],
)

platform(
    name = "linux_x86_64",
    constraint_values = [
        ":cilium_target_platform_enabled",
        "@platforms//cpu:x86_64",
        "@platforms//os:linux",
    ],
)

exports_files(["envoy_dynamic_modules_rust_sdk.Cargo.Bazel.lock"])
