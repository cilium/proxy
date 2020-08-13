load(
    "@envoy//bazel:envoy_build_system.bzl",
    "envoy_cc_binary",
    "envoy_cc_library",
)

licenses(["notice"])  # Apache 2

exports_files([
    "linux/bpf.h",
    "linux/bpf_common.h",
    "linux/type_mapper.h",
])

envoy_cc_library(
    name = "istio_deps_lib",
    repository = "@envoy",
    visibility = ["//visibility:public"],
    deps = [
        # Cf. https://github.com/istio/proxy/blob/1.7.6/src/envoy/BUILD#L28-L41
        "@istio_proxy//extensions/access_log_policy:access_log_policy_lib",
        "@istio_proxy//extensions/attributegen:attributegen_plugin",
        "@istio_proxy//extensions/metadata_exchange:metadata_exchange_lib",
        "@istio_proxy//extensions/stackdriver:stackdriver_plugin",
        "@istio_proxy//extensions/stats:stats_plugin",
        "@istio_proxy//src/envoy/extensions/wasm:wasm_lib",
        "@istio_proxy//src/envoy/http/alpn:config_lib",
        "@istio_proxy//src/envoy/http/authn:filter_lib",
        "@istio_proxy//src/envoy/http/mixer:filter_lib",
        "@istio_proxy//src/envoy/tcp/forward_downstream_sni:config_lib",
        "@istio_proxy//src/envoy/tcp/metadata_exchange:config_lib",
        "@istio_proxy//src/envoy/tcp/mixer:filter_lib",
        "@istio_proxy//src/envoy/tcp/sni_verifier:config_lib",
        "@istio_proxy//src/envoy/tcp/tcp_cluster_rewrite:config_lib",
    ],
)

envoy_cc_binary(
    name = "cilium-envoy-deps",
    repository = "@envoy",
    visibility = ["//visibility:public"],
    deps = [
        "//cilium:envoy_deps_lib",
        ":istio_deps_lib",
        "@envoy//source/exe:envoy_main_entry_lib",
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

        ":istio_deps_lib",
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
