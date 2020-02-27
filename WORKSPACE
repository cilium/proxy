workspace(name = "cilium")

#
# We grep for the following line to generate SOURCE_VERSION file for non-git
# distribution builds. This line must start with the string ENVOY_SHA followed by
# an equals sign and a git SHA in double quotes.
#
# No other line in this file may have ENVOY_SHA followed by an equals sign!
#
ENVOY_SHA = "fc40c08a807111943c4b3cbe11df494f3e0df4d4"
ENVOY_SHA256 = "f6bb1bfbd5a6681ef4898f396e671ff4adcd372f6dca8d0cfa980f8b91914ff1"

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

http_archive(
    name = "envoy",
    url = "https://github.com/jrajahalme/envoy/archive/" + ENVOY_SHA + ".tar.gz",
    sha256 = ENVOY_SHA256,
    strip_prefix = "envoy-" + ENVOY_SHA,
    patches = [
        "@//patches:1.12-0001-sds-fix-combined-validation-context-validation-bypas.patch",
        "@//patches:1.12-0002-buffer-draining-any-zero-byte-fragments-9837-109-123.patch",
        "@//patches:1.12-0003-network-draining-the-buffer-on-close-9870-110-124.patch",
        "@//patches:1.12-0004-tls_inspector-enable-TLSv1.3.-119.patch",
        "@//patches:1.12-0005-http-adding-response-flood-protection-113-125.patch",
        "@//patches:1.12-0006-buffer-release-empty-slices-after-commit-116-128.patch",
        "@//patches:1.12-0007-buffer-Force-copy-when-appending-small-slices-to-Own.patch",
        "@//patches:sni_support_fix.patch",
    ],
    patch_args = ["-p1"],
)

#
# Bazel does not do transitive dependencies, so we must basically
# include all of Envoy's WORKSPACE file below, with the following
# changes:
# - Skip the 'workspace(name = "envoy")' line as we already defined
#   the workspace above.
# - loads of "//..." need to be renamed as "@envoy//..."
#

load("@envoy//bazel:api_binding.bzl", "envoy_api_binding")
envoy_api_binding()

load("@envoy//bazel:api_repositories.bzl", "envoy_api_dependencies")
envoy_api_dependencies()

load("@envoy//bazel:repositories.bzl", "envoy_dependencies")
envoy_dependencies()

load("@envoy//bazel:dependency_imports.bzl", "envoy_dependency_imports")
envoy_dependency_imports()

# Dependencies for Istio filters.
# Cf. https://github.com/istio/proxy.
# Version 1.2.2
# ISTIO_PROXY_SHA = "a975561b980463f08689d3debe33bb9eefc80c3d"
# ISTIO_PROXY_SHA256 = "c0123fe73be4c9f2fe5e673952743ceb836f5972a8377ea876d90b7ab63af6eb"

#http_archive(
#    name = "istio_proxy",
#    url = "https://github.com/istio/proxy/archive/" + ISTIO_PROXY_SHA + ".tar.gz",
#    sha256 = ISTIO_PROXY_SHA256,
#    strip_prefix = "proxy-" + ISTIO_PROXY_SHA,
#)

#load("@istio_proxy//:repositories.bzl", "mixerapi_dependencies")
#mixerapi_dependencies()

#bind(
#    name = "boringssl_crypto",
#    actual = "//external:ssl",
#)
