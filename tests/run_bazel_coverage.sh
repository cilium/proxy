#!/usr/bin/env bash

set -e -o pipefail

LLVM_VERSION=${LLVM_VERSION:-"18.1.3"}
CLANG_VERSION=$(clang --version | grep version | sed -e 's/\ *clang version \([0-9.]*\).*/\1/')
LLVM_COV_VERSION=$(llvm-cov --version | grep version | sed -e 's/\ *LLVM version \([0-9.]*\).*/\1/')
LLVM_PROFDATA_VERSION=$(llvm-profdata show --version | grep version | sed -e 's/\ *LLVM version \(.*\)/\1/')

if [[ "${CLANG_VERSION}" != "${LLVM_VERSION}" ]]; then
    echo "ERROR: clang version ${CLANG_VERSION} does not match expected ${LLVM_VERSION}" >&2
    exit 1
fi

if [[ "${LLVM_COV_VERSION}" != "${LLVM_VERSION}" ]]; then
    echo "ERROR: llvm-cov version ${LLVM_COV_VERSION} does not match expected ${LLVM_VERSION}" >&2
    exit 1
fi

if [[ "${LLVM_PROFDATA_VERSION}" != "${LLVM_VERSION}" ]]; then
    echo "ERROR: llvm-profdata version ${LLVM_PROFDATA_VERSION} does not match expected ${LLVM_VERSION}" >&2
    exit 1
fi

[[ -z "${SRCDIR}" ]] && SRCDIR="${PWD}"
[[ -z "${VALIDATE_COVERAGE}" ]] && VALIDATE_COVERAGE=true
COVERAGE_TARGET="${COVERAGE_TARGET:-}"
#TBD propogate any important global build options
read -ra BAZEL_BUILD_OPTIONS <<< "${BAZEL_BUILD_OPTION_LIST:-}"
read -ra BAZEL_GLOBAL_OPTIONS <<< "${BAZEL_GLOBAL_OPTION_LIST:-}"

# This is the target that will be run to generate coverage data. It can be overridden by consumer
# projects that want to run coverage on a different/combined target.
# Command-line arguments take precedence over ${COVERAGE_TARGET}.
if [[ $# -gt 0 ]]; then
  COVERAGE_TARGETS=("$@")
elif [[ -n "${COVERAGE_TARGET}" ]]; then
  COVERAGE_TARGETS=("${COVERAGE_TARGET}")
else
  COVERAGE_TARGETS=(//tests/...)
fi

BAZEL_COVERAGE_OPTIONS=(--heap_dump_on_oom)
BAZEL_VALIDATE_OPTIONS=()
BAZEL_COVERAGE_OPTIONS+=("--config=coverage")
BAZEL_COVERAGE_OPTIONS+=("--config=clang")

# Output unusually long logs due to trace logging.
BAZEL_COVERAGE_OPTIONS+=("--experimental_ui_max_stdouterr_bytes=80000000")

COVERAGE_DIR="${SRCDIR}/generated/coverage"

run_coverage() {
    echo "Running bazel coverage with:"
    echo "  Options: ${BAZEL_BUILD_OPTIONS[*]} ${BAZEL_COVERAGE_OPTIONS[*]}"
    echo "  Targets: ${COVERAGE_TARGETS[*]}"

    bazel coverage "${BAZEL_BUILD_OPTIONS[@]}" "${BAZEL_COVERAGE_OPTIONS[@]}" "${COVERAGE_TARGETS[@]}"

    if [[ ! -e bazel-out/_coverage/_coverage_report.dat ]]; then
        echo "ERROR: No coverage report found (bazel-out/_coverage/_coverage_report.dat)" >&2
        exit 1
    elif [[ ! -s bazel-out/_coverage/_coverage_report.dat ]]; then
        echo "ERROR: Coverage report is empty (bazel-out/_coverage/_coverage_report.dat)" >&2
        exit 1
    fi
}


run_coverage
#TBD
#render_coverage

