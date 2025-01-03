#!/usr/bin/env bash

if ! command -v sudo >/dev/null; then
    SUDO=
else
    SUDO=sudo
fi

# renovate: datasource=datasource depName=bazelbuild/bazelisk
BAZELISK_VERSION=v1.20.0

installed_bazelisk_version=""

if [[ $(command -v bazel) ]]; then
    installed_bazelisk_version=$(bazel version | grep 'Bazelisk' | cut -d ' ' -f 3)
fi

echo "Checking if Bazelisk ${BAZELISK_VERSION} needs to be installed..."
if [[ "${installed_bazelisk_version}" = "${BAZELISK_VERSION}" || "${installed_bazelisk_version}" = "development" ]]; then
    echo "Bazelisk ${BAZELISK_VERSION} (or development) already installed, skipping."
else
    BAZEL=$(command -v bazel)
    if [ -n "${BAZEL}" ] ; then
        echo "Removing old Bazel version at ${BAZEL}"
        ${SUDO} rm "${BAZEL}"
    else
        BAZEL=/usr/local/bin/bazel
    fi
    OS=$(uname -s | tr '[:upper:]' '[:lower:]')
    ARCH=$(uname -m)
    if [ "$ARCH" = "x86_64" ]; then
        ARCH="amd64"
    elif [ "$ARCH" = "aarch64" ]; then
        ARCH="arm64"
    fi
    echo "Downloading bazel-${BAZEL_VERSION}-${OS}-${ARCH} to ${BAZEL}"
    ${SUDO} curl -sfL "https://github.com/bazelbuild/bazelisk/releases/download/${BAZELISK_VERSION}/bazelisk-${OS}-${ARCH}" -o "${BAZEL}"
    ${SUDO} chmod +x "${BAZEL}"
fi
