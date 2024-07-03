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
    deps = [
        "//cilium:network_policy_lib",
        "//cilium:socket_option_lib",
        "//cilium/api:tls_wrapper_cc_proto",
        "@envoy//envoy/network:transport_socket_interface",
        "@envoy//envoy/registry",
        "@envoy//envoy/server:transport_socket_config_interface",
        "@envoy//source/common/tls:ssl_socket_lib",
        "@envoy//source/server:transport_socket_config_lib",
        "@envoy_api//envoy/extensions/transport_sockets/tls/v3:pkg_cc_proto",
    ],
)

envoy_cc_library(
    name = "network_policy_lib",
    srcs = [
        "network_policy.cc",
        "secret_watcher.cc",
        "secret_watcher.h",
    ],
    hdrs = [
        "network_policy.h",
    ],
    repository = "@envoy",
    deps = [
        "//cilium:accesslog_lib",
        "//cilium:conntrack_lib",
        "//cilium:grpc_subscription_lib",
        "//cilium:ipcache_lib",
        "//cilium/api:npds_cc_proto",
        "@envoy//envoy/config:subscription_interface",
        "@envoy//envoy/singleton:manager_interface",
        "@envoy//source/common/common:logger_lib",
        "@envoy//source/common/config:opaque_resource_decoder_lib",
        "@envoy//source/common/init:manager_lib",
        "@envoy//source/common/init:target_lib",
        "@envoy//source/common/init:watcher_lib",
        "@envoy//source/common/local_info:local_info_lib",
        "@envoy//source/common/network:address_lib",
        "@envoy//source/common/router:config_utility_lib",
        "@envoy//source/common/tls:context_config_lib",
        "@envoy//source/server:transport_socket_config_lib",
        "@envoy_api//envoy/type/matcher/v3:pkg_cc_proto",
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
        "@envoy//envoy/network:listen_socket_interface",
        "@envoy//source/common/common:logger_lib",
        "@envoy_api//envoy/config/core/v3:pkg_cc_proto",
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
    deps = [
        "@envoy//envoy/network:connection_interface",
        "@envoy//source/common/config:type_to_endpoint_lib",
        "@envoy//source/extensions/config_subscription/grpc:grpc_subscription_lib",
        "@envoy_api//envoy/annotations:pkg_cc_proto",
        "@envoy_api//envoy/config/core/v3:pkg_cc_proto",
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
    deps = [
        "//cilium:accesslog_lib",
        "//cilium:network_policy_lib",
        "//cilium:socket_option_lib",
        "//cilium/api:l7policy_cc_proto",
        "@envoy//envoy/config:subscription_interface",
        "@envoy//source/common/http:utility_lib",
        "@envoy//source/common/network:upstream_server_name_lib",
        "@envoy//source/common/network:upstream_subject_alt_names_lib",
        "@envoy//source/extensions/filters/http/common:factory_base_lib",
    ],
)

envoy_cc_library(
    name = "websocket_lib",
    srcs = [
        "websocket.cc",
        "websocket_codec.cc",
        "websocket_config.cc",
    ],
    hdrs = [
        "websocket.h",
        "websocket_codec.h",
        "websocket_config.h",
        "websocket_protocol.h",
    ],
    external_deps = ["http_parser"],
    repository = "@envoy",
    deps = [
        "//cilium:accesslog_lib",
        "//cilium:socket_option_lib",
        "//cilium/api:websocket_cc_proto",
        "@envoy//envoy/common/crypto:crypto_interface",
        "@envoy//source/common/common:base64_lib",
        "@envoy//source/common/common:hex_lib",
        "@envoy//source/common/crypto:utility_lib",
        "@envoy//source/common/http:codes_lib",
        "@envoy//source/common/http:header_utility_lib",
        "@envoy//source/common/http:request_id_extension_lib",
        "@envoy//source/common/http:utility_lib",
        "@envoy//source/common/network:filter_manager_lib",
        "@envoy//source/common/stream_info:bool_accessor_lib",
        "@envoy//source/common/tcp_proxy",
        "@envoy_api//envoy/extensions/request_id/uuid/v3:pkg_cc_proto",
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
    deps = [
        "//cilium:uds_client_lib",
        "//cilium/api:accesslog_proto_cc_proto",
        "@envoy//envoy/http:header_map_interface",
        "@envoy//envoy/network:connection_interface",
        "@envoy//envoy/router:router_interface",
    ],
)

envoy_cc_library(
    name = "uds_client_lib",
    srcs = [
        "uds_client.cc",
    ],
    hdrs = [
        "uds_client.h",
    ],
    repository = "@envoy",
    deps = [
        "@envoy//source/common/common:minimal_logger_lib",
        "@envoy//source/common/common:thread_lib",
        "@envoy//source/common/common:utility_lib",
        "@envoy//source/common/network:address_lib",
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
        "privileged_service_client_lib",
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
        "@envoy//envoy/singleton:manager_interface",
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
        "@envoy//envoy/network:connection_interface",
        "@envoy//envoy/network:listen_socket_interface",
        "@envoy//envoy/singleton:manager_interface",
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
        "@envoy//envoy/network:connection_interface",
        "@envoy//envoy/singleton:manager_interface",
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
    deps = [
        "//cilium:conntrack_lib",
        "//cilium:network_policy_lib",
        "//cilium:proxylib_lib",
        "//cilium:socket_option_lib",
        "//cilium/api:network_filter_cc_proto",
        "@envoy//envoy/buffer:buffer_interface",
        "@envoy//envoy/network:connection_interface",
        "@envoy//envoy/network:filter_interface",
        "@envoy//envoy/registry",
        "@envoy//envoy/server:filter_config_interface",
        "@envoy//source/common/common:assert_lib",
        "@envoy//source/common/common:logger_lib",
        "@envoy//source/common/network:address_lib",
        "@envoy//source/common/network:upstream_server_name_lib",
        "@envoy//source/common/network:upstream_subject_alt_names_lib",
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
    deps = [
        "//cilium:conntrack_lib",
        "//cilium:grpc_subscription_lib",
        "//cilium:ipcache_lib",
        "//cilium:network_policy_lib",
        "//cilium:socket_option_lib",
        "//cilium/api:bpf_metadata_cc_proto",
        "//cilium/api:nphds_cc_proto",
        "@envoy//envoy/buffer:buffer_interface",
        "@envoy//envoy/config:subscription_interface",
        "@envoy//envoy/network:connection_interface",
        "@envoy//envoy/network:filter_interface",
        "@envoy//envoy/registry",
        "@envoy//envoy/server:filter_config_interface",
        "@envoy//envoy/singleton:manager_interface",
        "@envoy//source/common/common:assert_lib",
        "@envoy//source/common/common:logger_lib",
        "@envoy//source/common/network:address_lib",
        "@envoy//source/common/router:config_utility_lib",
    ],
)

envoy_cc_library(
    name = "privileged_service_client_lib",
    srcs = ["privileged_service_client.cc"],
    hdrs = ["privileged_service_client.h"],
    repository = "@envoy",
    deps = [
        "//starter:privileged_service_protocol",
        "@envoy//envoy/api:os_sys_calls_interface",
        "@envoy//source/common/singleton:threadsafe_singleton",
    ],
)

envoy_cc_library(
    name = "health_check_sink_lib",
    srcs = ["health_check_sink.cc"],
    hdrs = ["health_check_sink.h"],
    repository = "@envoy",
    deps = [
        "//cilium:uds_client_lib",
        "//cilium/api:health_check_sink_cc_proto",
        "@envoy//envoy/registry",
        "@envoy//envoy/upstream:health_check_event_sink_interface",
    ],
)
