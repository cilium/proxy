#!/bin/bash

BAZELRC_FILE="${BAZELRC_FILE:-$(bazel info workspace)/clang.bazelrc}"

LLVM_PREFIX=$1

# On RHEL/UBI, llvm-config may live directly in /usr/bin rather than
# under a versioned prefix like /usr/lib/llvm-18/bin. Try the given
# prefix first, then fall back to searching PATH.
if [[ -e "${LLVM_PREFIX}/bin/llvm-config" ]]; then
  LLVM_CONFIG="${LLVM_PREFIX}/bin/llvm-config"
elif command -v llvm-config &>/dev/null; then
  LLVM_CONFIG="$(command -v llvm-config)"
  # Derive LLVM_PREFIX from the discovered llvm-config
  LLVM_PREFIX="$("${LLVM_CONFIG}" --prefix)"
else
  echo "Error: cannot find llvm-config in ${LLVM_PREFIX} or PATH."
  exit 1
fi

BINDIR="$("${LLVM_CONFIG}" --bindir)"
PATH="${BINDIR}:${PATH}"
export PATH

LLVM_VERSION="$("${LLVM_CONFIG}" --version)"
LLVM_LIBDIR="$("${LLVM_CONFIG}" --libdir)"
LLVM_TARGET="$("${LLVM_CONFIG}" --host-target)"

RT_LIBRARY_PATH="${LLVM_LIBDIR}/clang/${LLVM_VERSION}/lib/${LLVM_TARGET}"

echo "# Generated file, do not edit. If you want to disable clang, just delete this file.
build:clang --action_env='PATH=${PATH}' --host_action_env='PATH=${PATH}'
build:clang --action_env='LLVM_CONFIG=${LLVM_CONFIG}' --host_action_env='LLVM_CONFIG=${LLVM_CONFIG}'
build:clang --repo_env='LLVM_CONFIG=${LLVM_CONFIG}'
build:clang --linkopt='-L${LLVM_LIBDIR}'
build:clang --linkopt='-Wl,-rpath,${LLVM_LIBDIR}'

build:clang-asan --linkopt='-L${RT_LIBRARY_PATH}'
" >"${BAZELRC_FILE}"
