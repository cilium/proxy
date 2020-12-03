# Envoy binary for Istio sidecar proxy

The integration of Cilium and Istio requires building artifacts from
several repositories in order to build Docker images.  Some of those
artifacts require changes that have not yet been merged upstream.

This document provides the instructions to build the Cilium-specific
Istio images.

## Build the Istio pilot docker image & cilium-istioctl

Build the Istio pilot docker image modified to configure Cilium
filters in every HTTP filter chain.  This work is being developed in
cilium/istio `inject-cilium-filters-1.6.14` branch, which is based on
Istio's release 1.6.14 branch. Make sure that when you build the Istio
binaries that you are using a Linux box meeting the requirements of
Istio.

    mkdir -p ${GOPATH}/src/istio.io
    cd ${GOPATH}/src/istio.io
    git clone https://github.com/cilium/istio.git
    cd istio
    git checkout inject-cilium-filters-1.6.14
    docker build -t cilium/istio_pilot:1.6.14 .
    make -f cilium-istioctl.Makefile

## Build Cilium's sidecar proxy Docker images

    mkdir -p ${GOPATH}/src/github.com/cilium
    cd ${GOPATH}/src/github.com/cilium
    git clone https://github.com/cilium/proxy.git
    cd proxy
    git checkout istio-1.6.14
    make docker-istio-proxy

## Push the Docker images to Docker Hub

    docker login -u ...
    docker image push cilium/istio_pilot:1.6.14
    docker image push cilium/istio_proxy:1.6.14
