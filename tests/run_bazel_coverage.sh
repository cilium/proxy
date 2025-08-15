#!/usr/bin/env bash

set -e -o pipefail
set +x
set -u

LLVM_VERSION=${LLVM_VERSION:-"18.1.8"}
CLANG_VERSION=$(clang-18 --version | grep version | sed -e 's/\ *Ubuntu clang version \([0-9.]*\).*/\1/')
LLVM_COV_VERSION=$(llvm-cov --version | grep version | sed -e 's/\ *Ubuntu LLVM version \([0-9.]*\).*/\1/')
LLVM_PROFDATA_VERSION=$(llvm-profdata show --version | grep version | sed -e 's/\ *Ubuntu LLVM version \(.*\)/\1/')
SRCDIR=${SRCDIR:-"${PWD}"}

#ERROR: clang version Ubuntu18.1.3 does not match expected 18.1.3
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

BAZEL_COVERAGE_OPTIONS=()
BAZEL_COVERAGE_OPTIONS+=(--heap_dump_on_oom)
BAZEL_COVERAGE_OPTIONS+=(--action_env=BAZEL_USE_LLVM_NATIVE_COVERAGE=1)
BAZEL_COVERAGE_OPTIONS+=(--combined_report=lcov)
BAZEL_COVERAGE_OPTIONS+=(--coverage_report_generator=//tools/coverage:cilium_report_generator)
BAZEL_COVERAGE_OPTIONS+=(--experimental_use_llvm_covmap)
BAZEL_COVERAGE_OPTIONS+=(--experimental_generate_llvm_lcov)
BAZEL_COVERAGE_OPTIONS+=(--experimental_split_coverage_postprocessing)
BAZEL_COVERAGE_OPTIONS+=(--experimental_fetch_all_coverage_outputs)
BAZEL_COVERAGE_OPTIONS+=(--collect_code_coverage)
BAZEL_COVERAGE_OPTIONS+=(--remote_download_minimal)
BAZEL_COVERAGE_OPTIONS+=(--copt=-DNDEBUG)
BAZEL_COVERAGE_OPTIONS+=(--build_tests_only)
#from envoy
BAZEL_COVERAGE_OPTIONS+=(--experimental_repository_cache_hardlinks)
BAZEL_COVERAGE_OPTIONS+=(--verbose_failures)
BAZEL_COVERAGE_OPTIONS+=(--experimental_generate_json_trace_profile)
BAZEL_COVERAGE_OPTIONS+=(--action_env=GCOV=llvm-profdata)
BAZEL_VALIDATE_OPTIONS=()


# Output unusually long logs due to trace logging.
BAZEL_COVERAGE_OPTIONS+=("--experimental_ui_max_stdouterr_bytes=80000000")
BAZEL_BUILD_OPTIONS+=("--remote_cache=https://storage.googleapis.com/cilium-proxy-bazel-remote-cache")
BAZEL_BUILD_OPTIONS+=("--google_default_credentials")

COVERAGE_DIR="${SRCDIR}/generated/coverage"

COVERAGE_DATA="${COVERAGE_DIR}/coverage.dat"


run_coverage() {
    echo "Running bazel coverage with:"
    echo "  Options: ${BAZEL_BUILD_OPTIONS[*]} ${BAZEL_COVERAGE_OPTIONS[*]}"
    echo "  Targets: ${COVERAGE_TARGETS[*]}"
    bazel coverage "${COVERAGE_TARGETS[@]}" "${BAZEL_BUILD_OPTIONS[@]}" "${BAZEL_COVERAGE_OPTIONS[@]}" --compiler=clang-18 --verbose_failures --sandbox_writable_path=$(bazel info output_path) --test_timeout=300 --local_test_jobs=1 --flaky_test_attempts=3 --instrument_test_targets --instrumentation_filter='^//'

    if [[ ! -e bazel-out/_coverage/_coverage_report.dat ]]; then
        echo "ERROR: No coverage report found (bazel-out/_coverage/_coverage_report.dat)" >&2
        exit 1
    elif [[ ! -s bazel-out/_coverage/_coverage_report.dat ]]; then
        echo "ERROR: Coverage report is empty (bazel-out/_coverage/_coverage_report.dat)" >&2
        exit 1
    fi
}

unpack_coverage_results() {
    rm -rf "${COVERAGE_DIR}"
    mkdir -p "${COVERAGE_DIR}"
    rm -f bazel-out/_coverage/_coverage_report.tar.zst
    mv bazel-out/_coverage/_coverage_report.dat bazel-out/_coverage/_coverage_report.tar.zst
    bazel run "${BAZEL_BUILD_OPTIONS[@]}" --nobuild_tests_only @envoy//tools/zstd -- -d -c "${PWD}/bazel-out/_coverage/_coverage_report.tar.zst" \
        | tar -xf - -C "${COVERAGE_DIR}"
    COVERAGE_JSON="${COVERAGE_DIR}/coverage.json"
}

validate_coverage() {
    bazel run \
          "${BAZEL_BUILD_OPTIONS[@]}" \
          "${BAZEL_VALIDATE_OPTIONS[@]}" \
          --nobuild_tests_only \
          //tools/coverage:validate \
          "$COVERAGE_JSON"
}

run_coverage
unpack_coverage_results
validate_coverage
