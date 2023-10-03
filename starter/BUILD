licenses(["notice"])  # Apache 2

cc_library(
    name = "main_entry_lib",
    srcs = ["main.cc"],
    visibility = ["//visibility:public"],
    deps = [
        "privileged_service_server_lib",
    ],
)

cc_library(
    name = "privileged_service_protocol",
    srcs = ["privileged_service_protocol.cc"],
    hdrs = ["privileged_service_protocol.h"],
    visibility = ["//visibility:public"],
)

cc_library(
    name = "privileged_service_server_lib",
    srcs = ["privileged_service_server.cc"],
    hdrs = ["privileged_service_server.h"],
    deps = [
        "privileged_service_protocol",
    ],
)
