# Cilium Proxy

This project provides the Envoy binary with additional Cilium filters.

## Building

To build the Cilium Proxy, Bazel 0.19.0 or later is required.

To build the binary:

```
make
```

To build Docker images with Envoy and Istio:

```
make docker-image-envoy
make docker-istio-proxy
```

## How it works

[Envoy](https://github.com/envoyproxy/envoy) and
[Istio Proxy](https://github.com/istio/proxy) are provided as Bazel
repositories and build dependencies. This repository provides a new
Envoy binary target which links together Cilium filters, Istio filters
and Envoy's main library (`@envoy//source/exe:envoy_main_lib`). Cilium
filters use Envoy API and Envoy libraries as dependencies.
