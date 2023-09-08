load(
    "@envoy//bazel:envoy_build_system.bzl",
    "envoy_package",
    "envoy_proto_library",
)
load(
    "@envoy_api//bazel:api_build_system.bzl",
    "api_cc_py_proto_library",
)

licenses(["notice"])  # Apache 2

envoy_package()

api_cc_py_proto_library(
    name = "health_check_sink",
    srcs = ["health_check_sink.proto"],
)

api_cc_py_proto_library(
    name = "bpf_metadata",
    srcs = ["bpf_metadata.proto"],
)

api_cc_py_proto_library(
    name = "network_filter",
    srcs = ["network_filter.proto"],
)

api_cc_py_proto_library(
    name = "l7policy",
    srcs = ["l7policy.proto"],
)

api_cc_py_proto_library(
    name = "websocket",
    srcs = ["websocket.proto"],
)

api_cc_py_proto_library(
    name = "tls_wrapper",
    srcs = ["tls_wrapper.proto"],
)

envoy_proto_library(
    name = "accesslog_proto",
    srcs = ["accesslog.proto"],
)

api_cc_py_proto_library(
    name = "npds",
    srcs = ["npds.proto"],
    deps = [
        "@envoy_api//envoy/annotations:pkg",
        "@envoy_api//envoy/config/core/v3:pkg",
        "@envoy_api//envoy/config/route/v3:pkg",
        "@envoy_api//envoy/service/discovery/v3:pkg",
        "@envoy_api//envoy/type/matcher/v3:pkg",
    ],
)

api_cc_py_proto_library(
    name = "nphds",
    srcs = ["nphds.proto"],
    deps = [
        "@envoy_api//envoy/annotations:pkg",
        "@envoy_api//envoy/service/discovery/v3:pkg",
    ],
)
