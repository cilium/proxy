licenses(["notice"])  # Apache 2

load(
    "@envoy//bazel:envoy_build_system.bzl",
    "envoy_proto_library",
)

load(
    "@envoy_api//bazel:api_build_system.bzl",
    "api_cc_py_proto_library",
)

api_cc_py_proto_library(
    name = "bpf_metadata",
    srcs = ["bpf_metadata.proto"],
    visibility = ["//visibility:public"],
)

api_cc_py_proto_library(
    name = "network_filter",
    srcs = ["network_filter.proto"],
    visibility = ["//visibility:public"],
)

api_cc_py_proto_library(
    name = "l7policy",
    srcs = ["l7policy.proto"],
    visibility = ["//visibility:public"],
)

envoy_proto_library(
    name = "accesslog_proto",
    srcs = ["accesslog.proto"],
)

api_cc_py_proto_library(
    name = "npds",
    srcs = ["npds.proto"],
    visibility = ["//visibility:public"],
    deps = [
        "@envoy_api//envoy/annotations:pkg",
        "@envoy_api//envoy/service/discovery/v3:pkg",
        "@envoy_api//envoy/api/v2/core:pkg",
        "@envoy_api//envoy/api/v2/route:pkg",
    ],
)

api_cc_py_proto_library(
    name = "nphds",
    srcs = ["nphds.proto"],
    visibility = ["//visibility:public"],
    deps = [
        "@envoy_api//envoy/annotations:pkg",
        "@envoy_api//envoy/service/discovery/v3:pkg",
    ],
)
