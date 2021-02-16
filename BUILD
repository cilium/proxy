load(
    "@envoy//bazel:envoy_build_system.bzl",
    "envoy_cc_binary",
    "envoy_cc_library",
    "envoy_cc_test",
)

licenses(["notice"])  # Apache 2

exports_files([
    "linux/bpf.h",
    "linux/bpf_common.h",
    "linux/type_mapper.h",
])

envoy_cc_library(
    name = "envoy_deps_lib",
    repository = "@envoy",
    visibility = ["//visibility:public"],
    deps = [
        "@envoy//include/envoy/buffer:buffer_interface",
        "@envoy//include/envoy/config:subscription_interface",
        "@envoy//include/envoy/network:connection_interface",
        "@envoy//include/envoy/network:filter_interface",
        "@envoy//include/envoy/network:listen_socket_interface",
        "@envoy//include/envoy/network:transport_socket_interface",
        "@envoy//include/envoy/registry",
        "@envoy//include/envoy/server:filter_config_interface",
        "@envoy//include/envoy/server:transport_socket_config_interface",
        "@envoy//include/envoy/singleton:manager_interface",
        "@envoy//source/common/buffer:buffer_lib",
        "@envoy//source/common/common:assert_lib",
        "@envoy//source/common/common:logger_lib",
        "@envoy//source/common/config:grpc_subscription_lib",
        "@envoy//source/common/local_info:local_info_lib",
        "@envoy//source/common/network:address_lib",
        "@envoy//source/common/router:config_utility_lib",
        "@envoy//source/exe:envoy_common_lib",
        "@envoy//source/extensions/transport_sockets/tls:ssl_socket_lib",
        "@envoy//source/server:transport_socket_config_lib",
    ],
)

envoy_cc_binary(
    name = "cilium-envoy-deps",
    repository = "@envoy",
    visibility = ["//visibility:public"],
    deps = [
        "@envoy//source/exe:envoy_main_entry_lib",
        ":envoy_deps_lib",
    ],
)

envoy_cc_binary(
    name = "cilium-envoy",
    repository = "@envoy",
    visibility = ["//visibility:public"],
    deps = [
        # Cilium filters.
        "//cilium:bpf_metadata_lib",
        "//cilium:network_filter_lib",
        "//cilium:l7policy_lib",
        "//cilium:tls_wrapper_lib",
        "@envoy//source/exe:envoy_main_entry_lib",
    ],
)

sh_test(
    name = "envoy_binary_test",
    srcs = ["envoy_binary_test.sh"],
    data = [":cilium-envoy"],
)

sh_binary(
    name = "check_format.py",
    srcs = ["@envoy//tools:code_format/check_format.py"],
    deps = [
        ":envoy_build_fixer.py",
        ":header_order.py",
    ],
)

sh_library(
    name = "header_order.py",
    srcs = ["@envoy//tools:code_format/header_order.py"],
)

sh_library(
    name = "envoy_build_fixer.py",
    srcs = ["@envoy//tools:code_format/envoy_build_fixer.py"],
)

envoy_cc_test(
    name = "cilium-envoy-test-deps",
    repository = "@envoy",
    deps = [
        "@envoy//source/common/common:logger_lib",
        "@envoy//source/common/common:thread_lib",
        "@envoy//test/integration:http_integration_lib",
        "@envoy//test/integration:integration_lib",
        "@envoy//test/mocks/network:connection_mocks",
        "@envoy//test/mocks/stream_info:stream_info_mocks",
        "@envoy//test/test_common:environment_lib",
        "@envoy//test/test_common:thread_factory_for_test_lib",
        "@envoy//test/test_common:utility_lib",
        ":envoy_deps_lib",
    ],
)
