load(
    "@envoy//bazel:envoy_build_system.bzl",
    "envoy_cc_library",
    "envoy_package",
)

licenses(["notice"])  # Apache 2

envoy_package()

envoy_cc_library(
    name = "tls_wrapper_lib",
    srcs = ["tls_wrapper.cc"],
    hdrs = ["tls_wrapper.h"],
    repository = "@envoy",
    visibility = ["//visibility:public"],
    deps = [
        "//cilium:network_policy_lib",
        "//cilium:socket_option_lib",
        "@envoy//include/envoy/network:transport_socket_interface",
        "@envoy//include/envoy/registry",
        "@envoy//include/envoy/server:transport_socket_config_interface",
        "@envoy//source/extensions/transport_sockets/tls:ssl_socket_lib",
        "@envoy//source/server:transport_socket_config_lib",
    ],
)

envoy_cc_library(
    name = "network_policy_lib",
    srcs = [
        "network_policy.cc",
    ],
    hdrs = [
        "network_policy.h",
    ],
    repository = "@envoy",
    deps = [
        "//cilium:accesslog_lib",
        "//cilium:conntrack_lib",
        "//cilium:grpc_subscription_lib",
        "//cilium/api:npds_cc_proto",
        "@envoy//include/envoy/config:subscription_interface",
        "@envoy//include/envoy/singleton:manager_interface",
        "@envoy//source/common/common:logger_lib",
        "@envoy//source/common/local_info:local_info_lib",
        "@envoy//source/common/network:address_lib",
        "@envoy//source/common/router:config_utility_lib",
        "@envoy//source/exe:envoy_common_lib",
    ],
)

envoy_cc_library(
    name = "socket_option_lib",
    hdrs = [
        "socket_option.h",
    ],
    repository = "@envoy",
    deps = [
        "//cilium:conntrack_lib",
        "@envoy//include/envoy/network:listen_socket_interface",
        "@envoy//source/common/common:logger_lib",
    ],
)

envoy_cc_library(
    name = "grpc_subscription_lib",
    srcs = [
        "grpc_subscription.cc",
    ],
    hdrs = [
        "grpc_subscription.h",
    ],
    repository = "@envoy",
    visibility = ["//visibility:public"],
    deps = [
        "@envoy//source/common/config:grpc_subscription_lib",
        "@envoy//source/exe:envoy_common_lib",
    ],
)

envoy_cc_library(
    name = "l7policy_lib",
    srcs = [
        "l7policy.cc",
    ],
    hdrs = [
        "l7policy.h",
    ],
    repository = "@envoy",
    visibility = ["//visibility:public"],
    deps = [
        "//cilium:accesslog_lib",
        "//cilium:network_policy_lib",
        "//cilium:socket_option_lib",
        "//cilium/api:l7policy_cc_proto",
        "@envoy//include/envoy/config:subscription_interface",
    ],
)

envoy_cc_library(
    name = "accesslog_lib",
    srcs = [
        "accesslog.cc",
    ],
    hdrs = [
        "accesslog.h",
    ],
    repository = "@envoy",
    visibility = ["//visibility:public"],
    deps = [
        "//cilium:socket_option_lib",
        "//cilium/api:accesslog_proto_cc_proto",
        "@envoy//source/exe:envoy_common_lib",
    ],
)

envoy_cc_library(
    name = "bpf_lib",
    srcs = [
        "bpf.cc",
    ],
    hdrs = [
        "bpf.h",
        "//:linux/bpf.h",
        "//:linux/bpf_common.h",
        "//:linux/type_mapper.h",
    ],
    repository = "@envoy",
    deps = [
        "@envoy//source/common/common:logger_lib",
        "@envoy//source/common/common:utility_lib",
    ],
)

envoy_cc_library(
    name = "ipcache_lib",
    srcs = [
        "ipcache.cc",
    ],
    hdrs = [
        "ipcache.h",
    ],
    repository = "@envoy",
    deps = [
        "//cilium:bpf_lib",
        "@envoy//include/envoy/singleton:manager_interface",
        "@envoy//source/common/common:assert_lib",
        "@envoy//source/common/common:logger_lib",
        "@envoy//source/common/network:address_lib",
    ],
)

envoy_cc_library(
    name = "conntrack_lib",
    srcs = [
        "conntrack.cc",
    ],
    hdrs = [
        "conntrack.h",
    ],
    repository = "@envoy",
    deps = [
        "//cilium:bpf_lib",
        "@envoy//include/envoy/network:connection_interface",
        "@envoy//include/envoy/network:listen_socket_interface",
        "@envoy//include/envoy/singleton:manager_interface",
        "@envoy//source/common/common:assert_lib",
        "@envoy//source/common/common:logger_lib",
        "@envoy//source/common/network:address_lib",
    ],
)

envoy_cc_library(
    name = "proxylib_lib",
    srcs = [
        "proxylib.cc",
    ],
    hdrs = [
        "proxylib.h",
        "//proxylib:libcilium.h",
        "//proxylib:types.h",
    ],
    repository = "@envoy",
    deps = [
        "@envoy//include/envoy/network:connection_interface",
        "@envoy//include/envoy/singleton:manager_interface",
        "@envoy//source/common/buffer:buffer_lib",
        "@envoy//source/common/common:assert_lib",
        "@envoy//source/common/common:logger_lib",
    ],
)

envoy_cc_library(
    name = "network_filter_lib",
    srcs = [
        "network_filter.cc",
    ],
    hdrs = [
        "network_filter.h",
    ],
    repository = "@envoy",
    visibility = ["//visibility:public"],
    deps = [
        "//cilium:conntrack_lib",
        "//cilium:network_policy_lib",
        "//cilium:proxylib_lib",
        "//cilium:socket_option_lib",
        "//cilium/api:network_filter_cc_proto",
        "@envoy//include/envoy/buffer:buffer_interface",
        "@envoy//include/envoy/network:connection_interface",
        "@envoy//include/envoy/network:filter_interface",
        "@envoy//include/envoy/registry",
        "@envoy//include/envoy/server:filter_config_interface",
        "@envoy//source/common/common:assert_lib",
        "@envoy//source/common/common:logger_lib",
        "@envoy//source/common/network:address_lib",
    ],
)

envoy_cc_library(
    name = "bpf_metadata_lib",
    srcs = [
        "bpf_metadata.cc",
        "host_map.cc",
    ],
    hdrs = [
        "bpf_metadata.h",
        "host_map.h",
    ],
    repository = "@envoy",
    visibility = ["//visibility:public"],
    deps = [
        "//cilium:conntrack_lib",
        "//cilium:grpc_subscription_lib",
        "//cilium:ipcache_lib",
        "//cilium:network_policy_lib",
        "//cilium:socket_option_lib",
        "//cilium/api:bpf_metadata_cc_proto",
        "//cilium/api:nphds_cc_proto",
        "@envoy//include/envoy/buffer:buffer_interface",
        "@envoy//include/envoy/config:subscription_interface",
        "@envoy//include/envoy/network:connection_interface",
        "@envoy//include/envoy/network:filter_interface",
        "@envoy//include/envoy/registry",
        "@envoy//include/envoy/server:filter_config_interface",
        "@envoy//include/envoy/singleton:manager_interface",
        "@envoy//source/common/common:assert_lib",
        "@envoy//source/common/common:logger_lib",
        "@envoy//source/common/network:address_lib",
        "@envoy//source/common/router:config_utility_lib",
    ],
)
