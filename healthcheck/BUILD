load("@io_bazel_rules_go//go:def.bzl", "go_binary")

licenses(["notice"])  # Apache 2

go_binary(
    name = "cilium-envoy-healthcheck",
    srcs = ["main.go"],
    out = "cilium-envoy-healthcheck",
    pure = "on",
    visibility = ["//visibility:public"],
)
