#!/usr/bin/env bash

BAZEL_VERSION=$1

echo "Checking if Bazel ${BAZEL_VERSION} needs to be installed..."
if [[ $(command -v bazel) && "$(bazel version | grep 'label' | cut -d ' ' -f 3)" =~ ${BAZEL_VERSION} ]]; then
  echo "Bazel ${BAZEL_VERSION} already installed, skipping fetch."
else
  if [ "$(uname -m)" = "aarch64" ]; then
     echo "Install Bazel on arm64: ......"
     sudo apt-get update && DEBIAN_FRONTEND=noninteractive sudo -E apt-get install -y curl unzip zip build-essential openjdk-11-jdk
     sudo sh -c 'echo "deb https://download.opensuse.org/repositories/home:/mrostecki:/bazel/xUbuntu_20.04/ /" > /etc/apt/sources.list.d/bazel.list'
     curl -L https://download.opensuse.org/repositories/home:/mrostecki:/bazel/xUbuntu_20.04/Release.key | sudo apt-key add -
     sudo apt-get update && DEBIAN_FRONTEND=noninteractive sudo -E apt-get install -y bazel
  else
     echo "Install Bazel ..."
     wget -nv https://github.com/bazelbuild/bazel/releases/download/${BAZEL_VERSION}/bazel-${BAZEL_VERSION}-installer-linux-x86_64.sh
     chmod +x bazel-${BAZEL_VERSION}-installer-linux-x86_64.sh
     sudo -E ./bazel-${BAZEL_VERSION}-installer-linux-x86_64.sh
     sudo -E mv /usr/local/bin/bazel /usr/bin
     rm bazel-${BAZEL_VERSION}-installer-linux-x86_64.sh
  fi
fi
