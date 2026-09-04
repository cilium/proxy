#!/bin/bash
#
# Minimal stand-in for LLVM's run-clang-tidy driver, which the hermetic LLVM
# toolchain does not ship. Runs clang-tidy on the given files in parallel and,
# with -fix, applies the collected fixes with clang-apply-replacements.
#
# Usage: run_clang_tidy.sh [-fix] [-format] [-style=<style>] [-j <jobs>]
#                          [clang-tidy options...] <file>...
#
# Options starting with '-' other than the ones above are passed to clang-tidy
# as is. Files without a compile command in ./compile_commands.json are skipped.
# The exit status is non-zero if any clang-tidy invocation failed, as with
# run-clang-tidy.
set -euo pipefail

CLANG_TIDY="${CLANG_TIDY:-clang-tidy}"
CLANG_APPLY_REPLACEMENTS="${CLANG_APPLY_REPLACEMENTS:-clang-apply-replacements}"

fix=0
format_opts=()
jobs="$(nproc)"
opts=()
files=()
while [ $# -gt 0 ]; do
  case "$1" in
    -fix) fix=1 ;;
    -format) format_opts+=("-format") ;;
    -style=*) format_opts+=("$1") ;;
    -j) jobs="$2"; shift ;;
    -j*) jobs="${1#-j}" ;;
    -*) opts+=("$1") ;;
    *) files+=("$1") ;;
  esac
  shift
done

if [ "${#files[@]}" -eq 0 ]; then
  echo "run_clang_tidy.sh: no files given" >&2
  exit 1
fi

# Like run-clang-tidy, only process files that have a compile command; the
# others (e.g. headers not included by any target) could not be parsed anyway.
mapfile -t files < <(python3 - "${files[@]}" <<'EOF'
import json
import os
import sys

with open("compile_commands.json") as f:
    known = {os.path.normpath(entry["file"]) for entry in json.load(f)}
for path in sys.argv[1:]:
    if os.path.normpath(path) in known or os.path.abspath(path) in known:
        print(path)
EOF
)
if [ "${#files[@]}" -eq 0 ]; then
  echo "run_clang_tidy.sh: none of the given files has a compile command" >&2
  exit 1
fi

fixes_dir="$(mktemp -d)"
trap 'rm -rf "${fixes_dir}"' EXIT

status=0
running=0
i=0
for file in "${files[@]}"; do
  "${CLANG_TIDY}" -p . "${opts[@]}" "-export-fixes=${fixes_dir}/${i}.yaml" "${file}" &
  i=$((i + 1))
  running=$((running + 1))
  if [ "${running}" -ge "${jobs}" ]; then
    wait -n || status=1
    running=$((running - 1))
  fi
done
while [ "${running}" -gt 0 ]; do
  wait -n || status=1
  running=$((running - 1))
done

if [ "${fix}" -eq 1 ] && [ -n "$(ls -A "${fixes_dir}")" ]; then
  "${CLANG_APPLY_REPLACEMENTS}" "${format_opts[@]}" "${fixes_dir}"
fi

exit "${status}"
