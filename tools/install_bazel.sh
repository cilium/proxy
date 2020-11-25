#!/usr/bin/env bash

BAZEL_VERSION=$1

echo "Checking if Bazel ${BAZEL_VERSION} needs to be installed..."
if [[ $(command -v bazel) && "$(bazel version | grep 'label' | cut -d ' ' -f 3)" =~ ${BAZEL_VERSION} ]]; then
    echo "Bazel ${BAZEL_VERSION} already installed, skipping fetch."
else
    BAZEL=$(command -v bazel)
    if [ -n "${BAZEL}" ] ; then
	echo "Removing old Bazel version at ${BAZEL}"
	sudo rm ${BAZEL}
    else
	BAZEL=/usr/local/bin/bazel
    fi
    OS=$(uname -s | tr '[:upper:]' '[:lower:]')
    ARCH=$(uname -m) && [ "$ARCH" != "aarch64" ] || ARCH="arm64"
    echo "Downloading bazel-${BAZEL_VERSION}-${OS}-${ARCH} to ${BAZEL}"
    sudo curl -sfL https://github.com/bazelbuild/bazel/releases/download/${BAZEL_VERSION}/bazel-${BAZEL_VERSION}-${OS}-${ARCH} -o ${BAZEL}
    sudo chmod +x ${BAZEL}
fi
