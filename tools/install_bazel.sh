#!/usr/bin/env bash

BAZEL_VERSION=$1

echo "Checking if Bazel ${BAZEL_VERSION} needs to be installed..."
if [[ $(command -v bazel) && "$(bazel version | grep 'label' | cut -d ' ' -f 3)" =~ ${BAZEL_VERSION} ]]; then
  echo "Bazel ${BAZEL_VERSION} already installed, skipping fetch."
else
  wget -nv https://github.com/bazelbuild/bazel/releases/download/${BAZEL_VERSION}/bazel-${BAZEL_VERSION}-installer-linux-x86_64.sh
  chmod +x bazel-${BAZEL_VERSION}-installer-linux-x86_64.sh
  sudo -E ./bazel-${BAZEL_VERSION}-installer-linux-x86_64.sh
  sudo -E mv /usr/local/bin/bazel /usr/bin
  rm bazel-${BAZEL_VERSION}-installer-linux-x86_64.sh
fi
