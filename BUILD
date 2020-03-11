licenses(["notice"])  # Apache 2

load(
    "@envoy//bazel:envoy_build_system.bzl",
    "envoy_cc_binary",
    "envoy_cc_test",
)

exports_files(["linux/bpf_common.h", "linux/bpf.h", "linux/type_mapper.h",
               "proxylib/libcilium.h", "proxylib/types.h"])

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

        # Cf. https://github.com/istio/proxy/blob/1.5.0/src/envoy/BUILD#L28-L40
        "@istio_proxy//extensions/access_log_policy:access_log_policy_lib",
        "@istio_proxy//extensions/metadata_exchange:metadata_exchange_lib",
        "@istio_proxy//extensions/stackdriver:stackdriver_plugin",
        "@istio_proxy//extensions/stats:stats_plugin",
        "@istio_proxy//src/envoy/http/alpn:config_lib",
        "@istio_proxy//src/envoy/http/authn:filter_lib",
        "@istio_proxy//src/envoy/http/jwt_auth:http_filter_factory",
        "@istio_proxy//src/envoy/http/mixer:filter_lib",
        "@istio_proxy//src/envoy/tcp/forward_downstream_sni:config_lib",
        "@istio_proxy//src/envoy/tcp/metadata_exchange:config_lib",
        "@istio_proxy//src/envoy/tcp/mixer:filter_lib",
        "@istio_proxy//src/envoy/tcp/sni_verifier:config_lib",
        "@istio_proxy//src/envoy/tcp/tcp_cluster_rewrite:config_lib",

        "@envoy//source/exe:envoy_main_entry_lib",
    ],
)

envoy_cc_test(
    name = "cilium_integration_test",
    srcs = ["cilium_integration_test.cc"],
    data = [
        "cilium_proxy_test.json",
        "proxylib/libcilium.so",
        "@envoy//test/config/integration/certs",
    ],
    repository = "@envoy",
    deps = [
        "//cilium:bpf_metadata_lib",
        "//cilium:network_filter_lib",
        "//cilium:l7policy_lib",
        "//cilium:tls_wrapper_lib",
        "@envoy//test/integration:http_integration_lib",
        #"@envoy//source/extensions/transport_sockets/tls:context_config_lib",
    ],
)

sh_test(
    name = "envoy_binary_test",
    srcs = ["envoy_binary_test.sh"],
    data = [":cilium-envoy"],
)

sh_binary(
    name = "check_format.py",
    srcs = ["@envoy//tools:check_format.py"],
    deps = [
        ":envoy_build_fixer.py",
        ":header_order.py",
    ],
)

sh_library(
    name = "header_order.py",
    srcs = ["@envoy//tools:header_order.py"],
)

sh_library(
    name = "envoy_build_fixer.py",
    srcs = ["@envoy//tools:envoy_build_fixer.py"],
)
