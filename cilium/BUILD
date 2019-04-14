licenses(["notice"])  # Apache 2

load(
    "@envoy//bazel:envoy_build_system.bzl",
    "envoy_cc_library",
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
        "@envoy//source/exe:envoy_common_lib",
        "@envoy//source/common/common:logger_lib",
        "@envoy//source/common/network:address_lib",
        "@envoy//source/common/local_info:local_info_lib",
        "@envoy//include/envoy/config:subscription_interface",
        "@envoy//include/envoy/singleton:manager_interface",
        "@envoy//source/common/router:config_utility_lib",
	"//cilium:grpc_subscription_lib",
        "//cilium/api:npds_cc",
    ],
)

envoy_cc_library(
    name = "socket_option_lib",
    hdrs = [
        "socket_option.h",
    ],
    repository = "@envoy",
    deps = [
        "@envoy//include/envoy/network:listen_socket_interface",
        "@envoy//source/common/common:logger_lib",
	"//cilium:proxymap_lib",
        "//cilium:network_policy_lib",
    ],
)

envoy_cc_library(
    name = "grpc_subscription_lib",
    visibility = ["//visibility:public"],
    srcs = [
        "grpc_subscription.cc",
    ],
    hdrs = [
        "grpc_subscription.h",
    ],
    repository = "@envoy",
    deps = [
        "@envoy//source/exe:envoy_common_lib",
        "@envoy//source/common/config:subscription_factory_lib",
        "@envoy_api//envoy/api/v2/core:config_source_cc",
    ],
)

envoy_cc_library(
    name = "l7policy_lib",
    visibility = ["//visibility:public"],
    srcs = [
        "accesslog.cc",
        "l7policy.cc",
    ],
    hdrs = [
        "accesslog.h",
        "l7policy.h",
    ],
    repository = "@envoy",
    deps = [
        "@envoy//include/envoy/config:subscription_interface",
        "//cilium/api:accesslog_proto_cc",
        "//cilium/api:l7policy_cc",
        "//cilium:socket_option_lib",
        "//cilium:network_policy_lib",
    ],
)

envoy_cc_library(
    name = "proxymap_lib",
    srcs = [
        "bpf.cc",
        "proxymap.cc",
    ],
    hdrs = [
        "bpf.h",
        "//:linux/bpf.h",
        "//:linux/bpf_common.h",
        "//:linux/type_mapper.h",
        "proxymap.h",
    ],
    repository = "@envoy",
    deps = [
        "@envoy//include/envoy/network:listen_socket_interface",
        "@envoy//include/envoy/network:connection_interface",
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
	"//:proxylib/libcilium.h",
	"//:proxylib/types.h"
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
    visibility = ["//visibility:public"],
    srcs = [
        "network_filter.cc",
    ],
    hdrs = [
        "network_filter.h",
    ],
    repository = "@envoy",
    deps = [
        "@envoy//include/envoy/buffer:buffer_interface",
        "@envoy//include/envoy/network:connection_interface",
        "@envoy//include/envoy/network:filter_interface",
        "@envoy//include/envoy/registry:registry",
        "@envoy//include/envoy/server:filter_config_interface",
        "@envoy//source/common/common:assert_lib",
        "@envoy//source/common/common:logger_lib",
        "@envoy//source/common/network:address_lib",
        "//cilium/api:network_filter_cc",
        "//cilium:proxylib_lib",
        "//cilium:proxymap_lib",
        "//cilium:socket_option_lib",
    ],
)

envoy_cc_library(
    name = "bpf_metadata_lib",
    visibility = ["//visibility:public"],
    srcs = [
        "bpf_metadata.cc",
        "host_map.cc",
    ],
    hdrs = [
        "bpf_metadata.h",
        "host_map.h",
    ],
    repository = "@envoy",
    deps = [
        "@envoy//include/envoy/buffer:buffer_interface",
        "@envoy//include/envoy/config:subscription_interface",
        "@envoy//include/envoy/network:connection_interface",
        "@envoy//include/envoy/network:filter_interface",
        "@envoy//include/envoy/singleton:manager_interface",
        "@envoy//include/envoy/registry:registry",
        "@envoy//include/envoy/server:filter_config_interface",
        "@envoy//source/common/common:assert_lib",
        "@envoy//source/common/common:logger_lib",
        "@envoy//source/common/network:address_lib",
        "@envoy//source/common/router:config_utility_lib",
        "//cilium/api:bpf_metadata_cc",
        "//cilium/api:nphds_cc",
        "//cilium:grpc_subscription_lib",
        "//cilium:proxymap_lib",
        "//cilium:socket_option_lib",
        "//cilium:network_policy_lib",
    ],
)
