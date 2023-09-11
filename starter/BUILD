licenses(["notice"])  # Apache 2

cc_library(
    name = "main_entry_lib",
    srcs = ["main.cc"],
    deps = [
        "privileged_service_server_lib",
    ],
    visibility = ["//visibility:public"],
)

cc_library(
    name = "privileged_service_protocol",
    srcs = ["privileged_service_protocol.cc"],
    hdrs = ["privileged_service_protocol.h"],
    visibility = ["//visibility:public"],
)

cc_library(
    name = "privileged_service_server_lib",
    hdrs = ["privileged_service_server.h"],
    srcs = ["privileged_service_server.cc"],
    deps = [
        "privileged_service_protocol",
    ],
)
