load(
    "@envoy//bazel:envoy_build_system.bzl",
    "envoy_cc_test",
    "envoy_cc_test_library",
)

licenses(["notice"])  # Apache 2

envoy_cc_test_library(
    name = "accesslog_server_lib",
    srcs = ["accesslog_server.cc"],
    hdrs = ["accesslog_server.h"],
    repository = "@envoy",
    deps = [
        "//cilium/api:accesslog_proto_cc_proto",
        "@envoy//source/common/common:logger_lib",
        "@envoy//source/common/common:thread_lib",
        "@envoy//test/test_common:thread_factory_for_test_lib",
    ],
)

envoy_cc_test_library(
    name = "bpf_metadata_lib",
    srcs = ["bpf_metadata.cc"],
    hdrs = ["bpf_metadata.h"],
    repository = "@envoy",
    deps = [
        "//cilium:bpf_metadata_lib",
        "//cilium:network_policy_lib",
        "//cilium:socket_option_lib",
        "@envoy//test/test_common:environment_lib",
    ],
)

envoy_cc_test_library(
    name = "l7policy_lib",
    srcs = ["l7policy.cc"],
    hdrs = ["l7policy.h"],
    repository = "@envoy",
    deps = [
        "//cilium:l7policy_lib",
    ],
)

envoy_cc_test_library(
    name = "cilium_http_integration_lib",
    srcs = ["cilium_http_integration.cc"],
    hdrs = ["cilium_http_integration.h"],
    repository = "@envoy",
    deps = [
        ":accesslog_server_lib",
        ":bpf_metadata_lib",
        "@envoy//test/integration:http_integration_lib",
    ],
)

envoy_cc_test_library(
    name = "cilium_tls_integration_lib",
    srcs = ["cilium_tls_integration.cc"],
    hdrs = ["cilium_tls_integration.h"],
    data = [
        "@envoy//test/config/integration/certs",
    ],
    repository = "@envoy",
    deps = [
        "@envoy//test/integration:integration_lib",
    ],
)

envoy_cc_test_library(
    name = "cilium_tcp_integration_lib",
    srcs = ["cilium_tcp_integration.cc"],
    hdrs = ["cilium_tcp_integration.h"],
    repository = "@envoy",
    deps = [
        ":accesslog_server_lib",
        ":bpf_metadata_lib",
        "@envoy//test/integration:integration_lib",
    ],
)

envoy_cc_test(
    name = "accesslog_test",
    srcs = ["accesslog_test.cc"],
    repository = "@envoy",
    deps = [
        "//cilium:accesslog_lib",
        "@envoy//test/mocks/network:connection_mocks",
        "@envoy//test/mocks/stream_info:stream_info_mocks",
        "@envoy//test/test_common:utility_lib",
    ],
)

envoy_cc_test(
    name = "cilium_tcp_integration_test",
    srcs = ["cilium_tcp_integration_test.cc"],
    data = [
        "//proxylib:libcilium.so",
    ],
    repository = "@envoy",
    deps = [
        ":cilium_tcp_integration_lib",
        "//cilium:bpf_metadata_lib",
        "//cilium:network_filter_lib",
    ],
)

envoy_cc_test(
    name = "cilium_tls_http_integration_test",
    srcs = ["cilium_tls_http_integration_test.cc"],
    data = [
        "@envoy//test/config/integration/certs",
    ],
    repository = "@envoy",
    deps = [
        ":cilium_http_integration_lib",
        ":cilium_tls_integration_lib",
        "//cilium:bpf_metadata_lib",
        "//cilium:l7policy_lib",
        "//cilium:network_filter_lib",
        "//cilium:tls_wrapper_lib",
    ],
)

envoy_cc_test(
    name = "cilium_tls_tcp_integration_test",
    srcs = ["cilium_tls_tcp_integration_test.cc"],
    data = [
        "//proxylib:libcilium.so",
        "@envoy//test/config/integration/certs",
    ],
    repository = "@envoy",
    deps = [
        ":cilium_tcp_integration_lib",
        ":cilium_tls_integration_lib",
        "//cilium:bpf_metadata_lib",
        "//cilium:l7policy_lib",
        "//cilium:network_filter_lib",
        "//cilium:tls_wrapper_lib",
    ],
)

envoy_cc_test(
    name = "cilium_http_integration_test",
    srcs = ["cilium_http_integration_test.cc"],
    data = [
        "//proxylib:libcilium.so",
    ],
    repository = "@envoy",
    deps = [
        ":cilium_http_integration_lib",
        ":l7policy_lib",
        "//cilium:bpf_metadata_lib",
        "//cilium:l7policy_lib",
        "//cilium:network_filter_lib",
    ],
)

envoy_cc_test(
    name = "cilium_websocket_decap_integration_test",
    srcs = ["cilium_websocket_decap_integration_test.cc"],
    data = [
        "//proxylib:libcilium.so",
    ],
    repository = "@envoy",
    deps = [
        ":cilium_http_integration_lib",
        "//cilium:bpf_metadata_lib",
        "//cilium:network_filter_lib",
        "//cilium:websocket_lib",
    ],
)

envoy_cc_test(
    name = "cilium_websocket_codec_integration_test",
    srcs = ["cilium_websocket_codec_integration_test.cc"],
    data = [
        "//proxylib:libcilium.so",
    ],
    repository = "@envoy",
    deps = [
        ":cilium_tcp_integration_lib",
        "//cilium:bpf_metadata_lib",
        "//cilium:network_filter_lib",
        "//cilium:websocket_lib",
    ],
)

envoy_cc_test(
    name = "cilium_websocket_encap_integration_test",
    srcs = ["cilium_websocket_encap_integration_test.cc"],
    data = [
        "//proxylib:libcilium.so",
    ],
    repository = "@envoy",
    deps = [
        ":cilium_tcp_integration_lib",
        "//cilium:bpf_metadata_lib",
        "//cilium:network_filter_lib",
        "//cilium:websocket_lib",
    ],
)
